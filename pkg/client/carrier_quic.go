package client

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"github.com/quic-go/quic-go"
	"golang.zx2c4.com/wireguard/conn"
)

type adaptiveQUICClient struct {
	bind   *wstransport.QUICBind
	remote netip.AddrPort
	origin string
}

func (a *adaptiveCarrierClient) qualifyQUIC(ctx context.Context, from string) error {
	info, bearer, expires := a.credentials()
	endpoint := a.base + "/v1/transport/lanes/" + info.LaneID
	var candidates protocol.CarrierCandidates
	if err := a.controlRequest(ctx, http.MethodGet, endpoint+"/candidates", bearer, nil, &candidates); err != nil {
		return err
	}
	primary, epoch, _ := a.bind.LaneState(a.lane)
	if primary != from || (candidates.Selected != from && candidates.Selected != protocol.CarrierWSS) || candidates.ParentID != info.ParentID ||
		candidates.LaneID != info.LaneID || candidates.AuthGeneration != info.AuthGeneration || candidates.QUIC != info.QUIC ||
		!slices.Contains(candidates.IDs, protocol.CarrierQUIC) {
		return errors.New("missing authorized QUIC candidate")
	}
	// Candidate discovery has the HTTPS client's own request timeout. Start
	// the transport qualification budget once an authorized path is known.
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var requestID [16]byte
	if _, err := rand.Read(requestID[:]); err != nil {
		return err
	}
	body, err := json.Marshal(protocol.CarrierAttachRequest{
		RequestID: base64.RawURLEncoding.EncodeToString(requestID[:]), Generation: info.AuthGeneration,
		Candidate: protocol.CarrierQUIC, ExpectedEpoch: candidates.PathEpoch,
	})
	if err != nil {
		return err
	}
	var attach protocol.CarrierAttachResponse
	if err := a.controlRequest(ctx, http.MethodPost, endpoint+"/attach", bearer, body, &attach); err != nil {
		return err
	}
	ticket, validTicket := protocol.ParseCarrierTicket(attach.Ticket)
	lane, validLane := protocol.ParseCarrierID(info.LaneID)
	size := wstransport.MaxWireGuardDatagram(info.TunnelMTU)
	if !validTicket || !validLane || attach.ExpiresInMS <= 0 || attach.DatagramMax != size {
		return errors.New("invalid QUIC carrier attach response")
	}
	transport, ok := a.control.Transport.(*secureControlTransport)
	if !ok || transport.TLSClientConfig == nil {
		return errors.New("QUIC carrier requires the HTTPS trust configuration")
	}
	tlsConfig := transport.TLSClientConfig.Clone()
	tlsConfig.ServerName = a.quic.origin
	tlsConfig.NextProtos = []string{protocol.CarrierQUICALPN}
	// A certificate pin uses InsecureSkipVerify together with VerifyConnection.
	if tlsConfig.InsecureSkipVerify && tlsConfig.VerifyConnection == nil {
		return errors.New("QUIC carrier requires verified TLS")
	}
	c, err := quic.DialAddr(ctx, a.quic.remote.String(), tlsConfig, wstransport.QUICConfig(false))
	if err != nil {
		return fmt.Errorf("dial QUIC carrier: %w", err)
	}
	accepted := false
	defer func() {
		if !accepted {
			_ = c.CloseWithError(0, "carrier unavailable")
		}
	}()
	hello := protocol.CarrierQUICHello{Lane: lane, Ticket: ticket}
	if _, err := rand.Read(hello.Nonce[:]); err != nil {
		return err
	}
	result, err := exchangeQUICProof(ctx, c, hello, size)
	if err != nil {
		return err
	}
	if (result == protocol.CarrierQUICQualified) != (info.PathSelect && candidates.Selected != "") {
		return errors.New("unexpected QUIC qualification result")
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if ctx.Err() != nil || a.info.AuthGeneration != info.AuthGeneration || !time.Now().Before(expires) {
		return errors.New("QUIC carrier authorization changed")
	}
	published := make(chan struct{})
	defer close(published)
	physical, err := a.quic.bind.Adopt(info.LaneID, c, size, func(ep conn.Endpoint) {
		<-published
		a.bind.FailPath(a.lane, protocol.CarrierQUIC, ep, protocol.CarrierWSS)
	})
	if err != nil {
		return err
	}
	if err := a.bind.InstallQualifiedPath(a.lane, epoch, wstransport.QualifiedPath{
		ID: protocol.CarrierQUIC, Carrier: protocol.CarrierQUIC, Endpoint: physical,
		SendMax: size, ReceiveMax: size, ValidUntil: expires,
	}); err != nil {
		return err
	}
	if result == protocol.CarrierQUICCommitted {
		if _, err := a.bind.CommitPath(a.lane, protocol.CarrierQUIC, epoch); err != nil {
			a.bind.FailPath(a.lane, protocol.CarrierQUIC, physical, protocol.CarrierWSS)
			return err
		}
	}
	accepted = true
	return nil
}

func exchangeQUICProof(ctx context.Context, c *quic.Conn, hello protocol.CarrierQUICHello, size int) (byte, error) {
	state := c.ConnectionState()
	if state.Used0RTT || !state.SupportsDatagrams.Local || !state.SupportsDatagrams.Remote {
		return 0, errors.New("QUIC DATAGRAM support was not negotiated")
	}
	stream, err := c.OpenStreamSync(ctx)
	if err != nil {
		return 0, err
	}
	deadline, _ := ctx.Deadline()
	_ = stream.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = stream.SetDeadline(time.Now()) })
	defer stop()
	defer stream.CancelRead(0)
	writesClosed := false
	defer func() {
		if !writesClosed {
			stream.CancelWrite(0)
		}
	}()
	if _, err := stream.Write(hello.MarshalBinary()); err != nil {
		return 0, fmt.Errorf("send QUIC attach: %w", err)
	}
	var ready [35]byte
	if _, err := io.ReadFull(stream, ready[:]); err != nil {
		return 0, fmt.Errorf("receive QUIC attach response: %w", err)
	}
	if ready[0] != protocol.CarrierQUICReady || int(binary.BigEndian.Uint16(ready[1:3])) != size {
		return 0, errors.New("invalid QUIC datagram size negotiation")
	}
	nonce := [32]byte(ready[3:])
	if err := wstransport.SendQUICProof(ctx, c, protocol.CarrierQUICProbe(size, hello.Nonce)); err != nil {
		return 0, fmt.Errorf("send QUIC size proof: %w", err)
	}
	data, err := c.ReceiveDatagram(ctx)
	if err != nil {
		return 0, fmt.Errorf("receive QUIC size proof: %w", err)
	}
	if !protocol.ValidCarrierQUICProbe(data, size, nonce) {
		return 0, errors.New("QUIC datagram probe did not match")
	}
	if _, err := stream.Write(nonce[:]); err != nil {
		return 0, err
	}
	if err := stream.Close(); err != nil {
		return 0, err
	}
	writesClosed = true
	var result [1]byte
	if _, err := io.ReadFull(stream, result[:]); err != nil {
		return 0, fmt.Errorf("receive QUIC qualification result: %w", err)
	}
	if result[0] != protocol.CarrierQUICCommitted && result[0] != protocol.CarrierQUICQualified {
		return 0, errors.New("server did not qualify QUIC carrier")
	}
	return result[0], nil
}

func newAdaptiveQUIC(info *protocol.AdaptiveSession, base string, origin *url.URL, options Options) *adaptiveQUICClient {
	remote, ok := adaptiveUDPAddress(info.QUIC)
	if !ok || !adaptiveUDPAllowed(base, options) || !matchesIPVersion(remote.String(), options.IPVersion) {
		return nil
	}
	return &adaptiveQUICClient{remote: remote, origin: origin.Hostname()}
}

func (c *Connection) maintainAdaptiveQUIC(n *connectionNetwork, stop <-chan struct{}) {
	a := n.adaptive
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-stop:
		case <-c.stop:
		case <-ctx.Done():
		}
		cancel()
	}()
	probe := func() error {
		if err := a.qualifyQUIC(ctx, protocol.CarrierWSS); err != nil {
			c.log.Debug("adaptive QUIC qualification kept WebSocket", "error", err)
			return err
		}
		c.log.Debug("adaptive QUIC carrier qualified")
		if _, err := a.ws.CarrierEndpoint("remote"); err != nil {
			// The disconnect may have preceded installation of the standby.
			a.signalWSSLoss()
		}
		return nil
	}
	info, _, _ := a.credentials()
	var initialErr error
	if primary, _, _ := a.bind.LaneState(a.lane); primary == protocol.CarrierWSS {
		// An explicit diagnostic run measures QUIC from startup. Its
		// bootstrap is not part of ordinary standby exploration.
		if c.options.AdaptiveQUICDiagnostic {
			initialErr = probe()
		} else {
			initialErr = a.qualifyStandby(time.Now(), probe)
		}
		if initialErr == nil && info.PathSelect && c.options.AdaptiveQUICDiagnostic {
			if err := a.selectPrimary(ctx, protocol.CarrierQUIC); err != nil {
				c.log.Debug("adaptive QUIC primary selection did not complete", "error", err)
			}
		}
	}
	if !info.PathSelect || c.options.AdaptiveQUICDiagnostic || carrierControlDenied(initialErr) {
		return
	}
	interval := 15 * time.Second
	if c.options.quicRetryInterval > 0 {
		interval = c.options.quicRetryInterval
	}
	backoff := interval
	jitter := max(int64(interval/4), 1)
	next := time.Now().Add(backoff + time.Duration(mathrand.Int64N(jitter)))
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	prior, _ := c.adaptiveTrafficSnapshot(n)
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			current, ok := c.adaptiveTrafficSnapshot(n)
			if !ok {
				return
			}
			var demand uint64
			if current.offered >= prior.offered && current.received >= prior.received {
				demand = current.offered - prior.offered + current.received - prior.received
			}
			prior = current
			if demand < 16<<10 || now.Before(next) || a.bind.HasQualifiedPath(a.lane, protocol.CarrierQUIC) {
				continue
			}
			if primary, _, _ := a.bind.LaneState(a.lane); primary != protocol.CarrierWSS {
				continue
			}
			err := a.qualifyStandby(now, probe)
			if errors.Is(err, errAdaptiveExplorationDeferred) {
				continue
			}
			if err != nil {
				if carrierControlDenied(err) {
					return
				}
				backoff = min(2*backoff, time.Minute)
			} else {
				backoff = interval
			}
			next = time.Now().Add(backoff + time.Duration(mathrand.Int64N(jitter)))
		}
	}
}
