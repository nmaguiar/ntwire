package client

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	mathrand "math/rand/v2"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nmaguiar/ntwire/pkg/ipfamily"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"golang.zx2c4.com/wireguard/conn"
)

const (
	adaptiveUDPObservation = 2 * time.Second
	adaptiveUDPRetry       = 15 * time.Second
)

type adaptiveUDPClient struct {
	socket *wstransport.FilterBind
	remote netip.AddrPort
	peer   conn.Endpoint
	closed atomic.Bool

	mu             sync.Mutex
	probe          *activeUDPProof // at most one, owned by the connection's worker
	qualifiedUntil time.Time
	rtt            time.Duration
}

type activeUDPProof struct {
	scope  protocol.CarrierProofScope
	key    [32]byte
	path   protocol.CarrierUDPPath
	up     *protocol.CarrierChallenge
	size   uint16
	ack    chan time.Duration
	down   chan protocol.CarrierProof
	upDone bool
}

func adaptiveUDPAddress(endpoint string) (netip.AddrPort, bool) {
	ap, err := netip.ParseAddrPort(endpoint)
	if err != nil || ap.Port() == 0 || ap.Addr().Zone() != "" || !(ap.Addr().IsGlobalUnicast() || ap.Addr().IsLoopback()) {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

func adaptiveUDPAllowed(base string, options Options) bool {
	if options.NoDirectUpgrade || options.HTTPSProxy != "" {
		return false
	}
	if options.NoSystemProxy {
		return true
	}
	req, err := http.NewRequest(http.MethodGet, base, nil)
	if err != nil {
		return false
	}
	proxy, err := http.ProxyFromEnvironment(req)
	return proxy == nil && err == nil
}

func newAdaptiveUDP(remote netip.AddrPort, ipVersion string) (*adaptiveUDPClient, error) {
	u := &adaptiveUDPClient{remote: remote,
		socket: wstransport.NewFilterBind(ipfamily.New(wstransport.NewProbeUDPBind(), ipVersion))}
	peer, err := u.socket.ParseEndpoint(remote.String())
	if err != nil {
		return nil, err
	}
	u.peer = peer
	u.socket.SetRawControlHandler(u.receive)
	return u, nil
}

func (u *adaptiveUDPClient) receive(frame []byte, ep conn.Endpoint) bool {
	if !protocol.IsCarrierProof(frame) {
		return false
	}
	if ep.DstToString() != u.remote.String() {
		return true
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	probe := u.probe
	if probe == nil {
		return true
	}
	if !probe.upDone {
		if rtt, ok := probe.up.AcceptACK(probe.path, frame, time.Now()); ok {
			probe.upDone = true
			probe.ack <- rtt
		}
		return true
	}
	if proof, ok := protocol.DecodeCarrierProof(probe.scope, probe.key, frame); ok &&
		proof.Kind == protocol.CarrierProbe && proof.Direction == protocol.CarrierDownload && proof.Size == probe.size {
		select {
		case probe.down <- proof:
		default:
		}
	}
	return true
}

func (u *adaptiveUDPClient) state() (bool, time.Duration) {
	if u.closed.Load() {
		return false, 0
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return time.Now().Before(u.qualifiedUntil), u.rtt
}

func (u *adaptiveUDPClient) invalidate() {
	u.mu.Lock()
	u.qualifiedUntil, u.rtt, u.probe = time.Time{}, 0, nil
	u.mu.Unlock()
}

func (a *adaptiveCarrierClient) nativeUDP(candidate string) *adaptiveUDPClient {
	switch candidate {
	case protocol.CarrierDirectUDP:
		return a.udp
	case protocol.CarrierAlternateUDP:
		return a.altUDP
	default:
		return nil
	}
}

func (a *adaptiveCarrierClient) nativeUDPUsable(candidate string) bool {
	u := a.nativeUDP(candidate)
	return u != nil && !u.closed.Load()
}

// Caller owns a.mu so a renewal cannot republish a retired path.
func (a *adaptiveCarrierClient) extendUDPPath(candidate string, until time.Time) {
	u := a.nativeUDP(candidate)
	u.mu.Lock()
	u.qualifiedUntil = until
	u.mu.Unlock()
	a.bind.ExtendPath(a.lane, candidate, until)
}

func (a *adaptiveCarrierClient) qualifyUDP(ctx context.Context, candidate string) error {
	u := a.nativeUDP(candidate)
	if u == nil || u.closed.Load() {
		return errors.New("adaptive UDP is not available")
	}
	ctx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	info, bearer, expires := a.credentials()
	_, localEpoch, _ := a.bind.LaneState(a.lane)
	base := a.base + "/v1/transport/lanes/" + info.LaneID
	var candidates protocol.CarrierCandidates
	if err := a.controlRequest(ctx, http.MethodGet, base+"/candidates", bearer, nil, &candidates); err != nil {
		return err
	}
	if candidates.ParentID != info.ParentID || candidates.LaneID != info.LaneID || candidates.AuthGeneration != info.AuthGeneration ||
		candidates.NativeUDPAddress(candidate) != info.NativeUDPAddress(candidate) || candidates.TunnelMTU != info.TunnelMTU ||
		!protocol.HasCapability(candidates.IDs, candidate) {
		return errors.New("adaptive UDP candidate is no longer authorized")
	}
	var id protocol.CarrierID
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	request := protocol.CarrierAttachRequest{
		RequestID: base64.RawURLEncoding.EncodeToString(id[:]), Generation: info.AuthGeneration,
		ExpectedEpoch: candidates.PathEpoch, Candidate: candidate,
	}
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	var offer protocol.CarrierUDPOffer
	if err := a.controlRequest(ctx, http.MethodPost, base+"/udp/prepare", bearer, body, &offer); err != nil {
		return err
	}
	offerID, ok := protocol.ParseCarrierID(offer.ID)
	if len(offer.ProofKey) != 43 {
		return errors.New("invalid adaptive UDP proof key")
	}
	var key [32]byte
	n, err := base64.RawURLEncoding.Strict().Decode(key[:], []byte(offer.ProofKey))
	if !ok || err != nil || n != len(key) || key == ([32]byte{}) || offer.DatagramMax != wstransport.MaxWireGuardDatagram(info.TunnelMTU) ||
		offer.ExpiresInMS <= 0 || offer.ExpiresInMS > 15000 {
		return errors.New("invalid adaptive UDP offer")
	}
	parent, _ := protocol.ParseCarrierID(info.ParentID)
	lane, _ := protocol.ParseCarrierID(info.LaneID)
	scope := protocol.CarrierProofScope{Parent: parent, Lane: lane, Candidate: offerID, AuthGeneration: info.AuthGeneration, PathEpoch: candidates.PathEpoch}
	port, open := a.bind.CarrierPort(candidate)
	if !open || port == 0 {
		return errors.New("adaptive UDP socket is not open")
	}
	rtt, err := u.exchange(ctx, scope, key, port, uint16(offer.DatagramMax))
	if err != nil {
		return err
	}
	status, until, err := a.completeUDP(ctx, base+"/udp/qualify", bearer, body)
	if err != nil {
		return err
	}
	if status.Candidate != candidate || status.DatagramMax != offer.DatagramMax || status.ExpiresInMS <= 0 || status.ExpiresInMS > 30000 {
		return errors.New("invalid adaptive UDP qualification")
	}
	if expires.Before(until) {
		until = expires
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token != bearer || a.info.AuthGeneration != info.AuthGeneration {
		return errors.New("adaptive session changed during UDP proof")
	}
	if err := a.bind.InstallQualifiedPath(a.lane, localEpoch, wstransport.QualifiedPath{
		ID: candidate, Carrier: candidate, Endpoint: u.peer,
		SendMax: status.DatagramMax, ReceiveMax: status.DatagramMax, ValidUntil: until,
	}); err != nil {
		return err
	}
	u.mu.Lock()
	u.qualifiedUntil, u.rtt = until, rtt
	u.mu.Unlock()
	return nil
}

func (u *adaptiveUDPClient) exchange(ctx context.Context, scope protocol.CarrierProofScope, key [32]byte, port uint16, size uint16) (time.Duration, error) {
	path := protocol.CarrierUDPPath{LocalPort: port, Remote: u.remote}
	up, frame, err := protocol.BeginCarrierChallenge(scope, key, path, protocol.CarrierUpload, size, time.Now())
	if err != nil {
		return 0, err
	}
	probe := &activeUDPProof{scope: scope, key: key, path: path, up: up, size: size,
		ack: make(chan time.Duration, 1), down: make(chan protocol.CarrierProof, 1)}
	u.mu.Lock()
	if u.probe != nil {
		u.mu.Unlock()
		return 0, errors.New("adaptive UDP proof already pending")
	}
	u.probe = probe
	u.mu.Unlock()
	defer func() {
		u.mu.Lock()
		if u.probe == probe {
			u.probe = nil
		}
		u.mu.Unlock()
	}()
	if err := u.socket.Send([][]byte{frame}, u.peer); err != nil {
		return 0, err
	}
	var rtt time.Duration
	select {
	case rtt = <-probe.ack:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	// A second full-size request buys a separate same-size server challenge.
	_, request, err := protocol.BeginCarrierChallenge(scope, key, path, protocol.CarrierUpload, size, time.Now())
	if err != nil {
		return 0, err
	}
	if err := u.socket.Send([][]byte{request}, u.peer); err != nil {
		return 0, err
	}
	select {
	case proof := <-probe.down:
		proof.Kind = protocol.CarrierACK
		err := u.socket.Send([][]byte{protocol.EncodeCarrierProof(scope, key, proof)}, u.peer)
		return rtt, err
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (a *adaptiveCarrierClient) completeUDP(ctx context.Context, endpoint, bearer string, body []byte) (protocol.CarrierUDPStatus, time.Time, error) {
	var status protocol.CarrierUDPStatus
	for range 4 {
		started := time.Now()
		err := a.controlRequest(ctx, http.MethodPost, endpoint, bearer, body, &status)
		if err == nil {
			return status, started.Add(time.Duration(status.ExpiresInMS) * time.Millisecond), nil
		}
		var httpErr *carrierHTTPError
		if !errors.As(err, &httpErr) || httpErr.status != http.StatusConflict {
			return status, time.Time{}, err
		}
		select {
		case <-ctx.Done():
			return status, time.Time{}, ctx.Err()
		case <-time.After(40 * time.Millisecond):
		}
	}
	return status, time.Time{}, errors.New("adaptive UDP qualification did not reach the server")
}

func (c *Connection) observeAdaptiveUDP(network *connectionNetwork, stop <-chan struct{}) {
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
	tick := time.NewTicker(adaptiveUDPObservation)
	defer tick.Stop()
	var next [2]time.Time
	candidates := [...]string{protocol.CarrierDirectUDP, protocol.CarrierAlternateUDP}
	var prior uint64
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			traffic, ok := c.adaptiveTrafficSnapshot(network)
			if !ok {
				return
			}
			total := traffic.offered + traffic.received
			busy := total > prior
			prior = total
			if !busy {
				continue
			}
			a := network.adaptive
			for i, candidate := range candidates {
				u := a.nativeUDP(candidate)
				if u == nil || u.closed.Load() || now.Before(next[i]) {
					continue
				}
				if qualified, _ := u.state(); qualified {
					continue
				}
				err := a.qualifyStandby(now, func() error { return a.qualifyUDP(ctx, candidate) })
				if errors.Is(err, errAdaptiveExplorationDeferred) {
					break
				}
				if err == nil {
					c.log.Debug("adaptive UDP standby qualified", "carrier", candidate)
				}
				if carrierControlDenied(err) {
					return
				}
				next[i] = time.Now().Add(adaptiveUDPRetry + time.Duration(mathrand.Int64N(int64(time.Second))))
				break
			}
		}
	}
}
