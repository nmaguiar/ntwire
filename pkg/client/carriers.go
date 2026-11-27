package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"golang.zx2c4.com/wireguard/conn"
)

type adaptiveCarrierClient struct {
	control       *http.Client
	base          string
	bind          *wstransport.AdaptiveBind
	lane          *wstransport.LaneEndpoint
	ws            *wstransport.Bind
	udp           *adaptiveUDPClient
	altUDP        *adaptiveUDPClient
	quic          *adaptiveQUICClient
	http2         *wstransport.QUICBind
	http3         *adaptiveQUICClient
	httpBootstrap string
	relay         *adaptiveRelayClient

	traffic      adaptiveTraffic
	localTraffic adaptiveTraffic // fixed listeners, counted separately from prepared grants
	measurements adaptivePerformanceHistory
	exploration  atomic.Bool
	tunnelProbe  atomic.Bool
	selectionMu  sync.Mutex
	wssLost      chan time.Time
	udpLost      chan nativeUDPLoss

	mu                 sync.Mutex
	info               protocol.AdaptiveSession
	token              string
	expires            time.Time
	attempted          atomic.Bool
	upgradeUnavailable atomic.Bool
	wssAttach          protocol.CarrierAttachRequest
}

func (a *adaptiveCarrierClient) credentials() (protocol.AdaptiveSession, string, time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.info, a.token, a.expires
}

func (a *adaptiveCarrierClient) renew(response protocol.AuthResponse, previousGrants []protocol.Tunnel) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	info := response.Adaptive
	if info == nil || info.ParentID != a.info.ParentID || info.LaneID != a.info.LaneID || info.AuthGeneration != a.info.AuthGeneration+1 || info.DirectUDP != a.info.DirectUDP || info.AlternateUDP != a.info.AlternateUDP || info.UDPSelect != a.info.UDPSelect || info.QUIC != a.info.QUIC || info.TunnelMTU != a.info.TunnelMTU || info.Performance != a.info.Performance || info.PathSelect != a.info.PathSelect || info.RelayCatalog != a.info.RelayCatalog || info.RelayUDP != a.info.RelayUDP || info.RelaySelect != a.info.RelaySelect || info.Child != a.info.Child || info.MaxLanes != a.info.MaxLanes || info.LaneCarriers != a.info.LaneCarriers ||
		info.RelayPerformance != a.info.RelayPerformance || info.HTTP2 != a.info.HTTP2 || info.HTTP3 != a.info.HTTP3 ||
		response.Token == "" || response.TTLSeconds <= 0 || response.Multipath || response.UDP != "" || response.UDPAlt != "" || response.WebSocket != "" ||
		protocol.ValidateRequiredCapabilities(response.TransportCapabilities, a.info.Capabilities()) != nil {
		return errors.New("renewal did not preserve the adaptive lane")
	}
	a.info = *info
	a.measurements.renew(info.AuthGeneration, !info.RelayPerformance && slices.Equal(previousGrants, response.Tunnels))
	a.wssAttach = protocol.CarrierAttachRequest{}
	a.token = response.Token
	a.expires = time.Now().Add(time.Duration(response.TTLSeconds) * time.Second)
	a.renewActivePathsLocked()
	return nil
}

func (a *adaptiveCarrierClient) renewActivePathsLocked() {
	primary, _, _ := a.bind.LaneState(a.lane)
	for _, candidate := range [...]string{protocol.CarrierDirectUDP, protocol.CarrierAlternateUDP} {
		u := a.nativeUDP(candidate)
		if u == nil {
			continue
		}
		if primary == candidate {
			a.extendUDPPath(candidate, a.expires)
		} else {
			u.invalidate()
			a.bind.RemovePath(a.lane, candidate)
		}
	}
	a.bind.ExtendPath(a.lane, protocol.CarrierWSS, a.expires)
	a.bind.ExtendPath(a.lane, protocol.CarrierQUIC, a.expires)
	a.bind.ExtendPath(a.lane, protocol.CarrierHTTP2, a.expires)
	a.bind.ExtendPath(a.lane, protocol.CarrierHTTP3, a.expires)
	a.renewRelayPath()
}

func (a *adaptiveCarrierClient) webSocketAttach(generation, epoch uint64) (protocol.CarrierAttachRequest, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if generation != a.info.AuthGeneration {
		return protocol.CarrierAttachRequest{}, errors.New("WebSocket carrier authorization changed")
	}
	if a.wssAttach.RequestID == "" || a.wssAttach.ExpectedEpoch != epoch {
		var requestID [16]byte
		if _, err := rand.Read(requestID[:]); err != nil {
			return protocol.CarrierAttachRequest{}, err
		}
		a.wssAttach = protocol.CarrierAttachRequest{
			RequestID: base64.RawURLEncoding.EncodeToString(requestID[:]), Generation: generation,
			Candidate: protocol.CarrierWSS, ExpectedEpoch: epoch,
		}
	}
	return a.wssAttach, nil
}

func (a *adaptiveCarrierClient) forgetWebSocketAttach(request protocol.CarrierAttachRequest) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.wssAttach == request {
		a.wssAttach = protocol.CarrierAttachRequest{}
	}
}

type carrierUpgradeTransport struct {
	owner   *adaptiveCarrierClient
	upgrade string
	setup   context.Context
}

// The trusted control origin owns the upgrade URL. Only this exact request
// can receive a bearer or ticket, and neither the control nor upgrade client
// follows redirects.
func (t carrierUpgradeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet || req.URL.String() != t.upgrade {
		return nil, errors.New("unexpected adaptive carrier upgrade origin")
	}
	a := t.owner
	ctx, cancel := context.WithTimeout(req.Context(), 10*time.Second)
	defer cancel()
	first := !a.attempted.Swap(true)
	if first && t.setup != nil {
		stop := context.AfterFunc(t.setup, cancel)
		defer stop()
	}
	info, bearer, expires := a.credentials()
	if !time.Now().Before(expires) {
		return nil, errors.New("adaptive carrier authorization expired")
	}
	endpoint := a.base + "/v1/transport/lanes/" + info.LaneID
	epoch := info.PathEpoch
	if !first {
		// The first attempt already has the authenticated anchor epoch. On
		// redial, reconcile with the server before asking it for a ticket.
		var candidates protocol.CarrierCandidates
		if err := a.controlRequest(ctx, http.MethodGet, endpoint+"/candidates", bearer, nil, &candidates); err != nil {
			return nil, err
		}
		if candidates.ParentID != info.ParentID || candidates.LaneID != info.LaneID || candidates.AuthGeneration != info.AuthGeneration ||
			!slices.Contains(candidates.IDs, protocol.CarrierWSS) {
			return nil, errors.New("server did not offer the authorized WebSocket carrier")
		}
		epoch = candidates.PathEpoch
	}
	// A gateway may reject the upgrade before the server can consume its
	// ticket. Reuse the operation while that ticket remains in scope.
	attachRequest, err := a.webSocketAttach(info.AuthGeneration, epoch)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(attachRequest)
	if err != nil {
		return nil, err
	}
	var attach protocol.CarrierAttachResponse
	if err := a.controlRequest(ctx, http.MethodPost, endpoint+"/attach", bearer, body, &attach); err != nil {
		var rejected *carrierHTTPError
		if errors.As(err, &rejected) && rejected.status == http.StatusConflict {
			a.forgetWebSocketAttach(attachRequest)
		}
		return nil, err
	}
	if attach.ExpiresInMS <= 0 || attach.DatagramMax != protocol.CarrierWSSDatagramMax || len(attach.Ticket) != 43 {
		return nil, errors.New("server supplied an invalid carrier ticket")
	}
	upgrade := req.Clone(req.Context())
	upgrade.Header.Set("Authorization", "Bearer "+bearer)
	upgrade.Header.Set(protocol.CarrierTicketHeader, attach.Ticket)
	transport := a.control.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	response, err := transport.RoundTrip(upgrade)
	if response != nil && response.StatusCode == http.StatusSwitchingProtocols {
		a.forgetWebSocketAttach(attachRequest)
	}
	if first {
		status := 0
		if response != nil {
			status = response.StatusCode
		}
		a.upgradeUnavailable.Store(unavailableWebSocketUpgrade(status, err))
	}
	return response, err
}

type carrierHTTPError struct {
	status int
}

func (e *carrierHTTPError) Error() string {
	return fmt.Sprintf("carrier control failed with HTTP %d", e.status)
}

func (a *adaptiveCarrierClient) controlRequest(ctx context.Context, method, endpoint, bearer string, body []byte, output any) error {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := a.control.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent && output == nil {
		return nil
	}
	if response.StatusCode != http.StatusOK {
		return &carrierHTTPError{status: response.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	if err != nil {
		return err
	}
	if len(data) > 8192 {
		return errors.New("carrier control response is too large")
	}
	return json.Unmarshal(data, output)
}

// Permit a different WireGuard carrier after an unavailable upgrade. Auth
// failures and unexpected control-plane responses are terminal.
func unavailableWebSocketUpgrade(status int, err error) bool {
	switch status {
	case http.StatusOK, http.StatusBadRequest, http.StatusNotFound, http.StatusMethodNotAllowed,
		http.StatusUpgradeRequired, http.StatusNotImplemented, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	case 0:
		var networkError net.Error
		return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
			errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) ||
			(errors.As(err, &networkError) && networkError.Timeout())
	default:
		return false
	}
}

func newAdaptiveConnection(ctx context.Context, response protocol.AuthResponse, base string, config wgnet.Config, h *http.Client, options Options, clientIP, serverIP netip.Addr) (_ *connectionNetwork, err error) {
	origin, err := url.Parse(base)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" {
		return nil, errors.New("adaptive carrier requires a trusted HTTPS control origin")
	}
	base = strings.TrimRight(base, "/")
	upgradeURL := base + protocol.CarrierWSSPath
	if response.Adaptive.Child {
		upgradeURL = base + "/v1/transport/lanes/" + response.Adaptive.LaneID + "/wg"
	}
	control := *h
	control.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	defer func() {
		if err != nil && !response.Adaptive.Child {
			postSessionDisconnect(&control, base, response.Token)
		}
	}()
	a := &adaptiveCarrierClient{
		control: &control, base: base, info: *response.Adaptive, token: response.Token,
		expires: time.Now().Add(time.Duration(response.TTLSeconds) * time.Second),
	}
	upgrade := control
	upgrade.Transport = carrierUpgradeTransport{owner: a, upgrade: upgradeURL, setup: ctx}
	a.ws = wstransport.NewClient("wss:"+strings.TrimPrefix(upgradeURL, "https:"), &upgrade, nil)
	ws := a.ws
	if err := ws.SetDatagramReadLimit(protocol.CarrierWSSDatagramMax); err != nil {
		return nil, err
	}
	if options.SampleWSS {
		ws.EnableQueuePerformance()
	}
	carriers := []wstransport.Carrier{{Name: protocol.CarrierWSS, Bind: ws, DatagramMax: protocol.CarrierWSSDatagramMax}}
	if a.info.HTTP2 && !a.info.Child {
		a.http2, _ = wstransport.NewQUICBind(nil)
		carriers = append(carriers, wstransport.Carrier{Name: protocol.CarrierHTTP2, Bind: a.http2, DatagramMax: protocol.CarrierWSSDatagramMax})
		ws.AllowDeferredInitialDial(unavailableWebSocketUpgrade)
	}
	if remote, ok := adaptiveUDPAddress(a.info.HTTP3); ok && !a.info.Child &&
		adaptiveUDPAllowed(base, options) && matchesIPVersion(remote.String(), options.IPVersion) {
		h3Bind, _ := wstransport.NewQUICBind(nil)
		a.http3 = &adaptiveQUICClient{bind: h3Bind, remote: remote, origin: origin.Hostname()}
		carriers = append(carriers, wstransport.Carrier{Name: protocol.CarrierHTTP3, Bind: h3Bind, DatagramMax: protocol.CarrierWSSDatagramMax})
		ws.AllowDeferredInitialDial(unavailableWebSocketUpgrade)
	}
	if remote, ok := adaptiveUDPAddress(response.Adaptive.DirectUDP); ok && adaptiveUDPAllowed(base, options) && matchesIPVersion(remote.String(), options.IPVersion) {
		a.udp, err = newAdaptiveUDP(remote, options.IPVersion)
		if err != nil {
			return nil, err
		}
		carriers = append(carriers, wstransport.Carrier{Name: protocol.CarrierDirectUDP, Bind: a.udp.socket, Optional: true,
			DatagramMax: protocol.CarrierProofMax, SendFailed: a.nativeUDPSendFailed(protocol.CarrierDirectUDP)})
	}
	if remote, ok := adaptiveUDPAddress(response.Adaptive.AlternateUDP); ok && adaptiveUDPAllowed(base, options) && matchesIPVersion(remote.String(), options.IPVersion) {
		a.altUDP, err = newAdaptiveUDP(remote, options.IPVersion)
		if err != nil {
			return nil, err
		}
		carriers = append(carriers, wstransport.Carrier{Name: protocol.CarrierAlternateUDP, Bind: a.altUDP.socket, Optional: true,
			DatagramMax: protocol.CarrierProofMax, SendFailed: a.nativeUDPSendFailed(protocol.CarrierAlternateUDP)})
	}
	if a.info.UDPSelect && (a.udp != nil || a.altUDP != nil) {
		a.udpLost = make(chan nativeUDPLoss, 1)
	}
	a.quic = newAdaptiveQUIC(response.Adaptive, base, origin, options)
	if a.info.RelaySelect && adaptiveUDPAllowed(base, options) {
		a.relay = newAdaptiveRelay(options.IPVersion, a.info.RelayPerformance)
		carriers = append(carriers, wstransport.Carrier{Name: protocol.CarrierRelayUDP, Bind: a.relay.socket, Optional: true, DatagramMax: protocol.CarrierProofMax})
	}
	if a.quic != nil {
		a.quic.bind, err = wstransport.NewQUICBind(options.QUICSendWait)
		if err != nil {
			return nil, err
		}
		if a.info.PathSelect && a.info.Performance && !options.AdaptiveQUICDiagnostic {
			ws.EnableDemandRTT()
		}
		ws.AllowDeferredInitialDial(unavailableWebSocketUpgrade)
		carriers = append(carriers, wstransport.Carrier{Name: protocol.CarrierQUIC, Bind: a.quic.bind, DatagramMax: protocol.CarrierWSSDatagramMax})
	}
	if a.info.PathSelect && (a.quic != nil || a.relay != nil || (a.info.UDPSelect && (a.udp != nil || a.altUDP != nil))) {
		a.wssLost = make(chan time.Time, 1)
		ws.OnPeerDisconnected = func(string, conn.Endpoint) { a.signalWSSLoss() }
	}
	a.bind, err = wstransport.NewAdaptiveBind(1, carriers...)
	if err != nil {
		return nil, err
	}
	a.lane, err = a.bind.RegisterLane(a.info.LaneID, wstransport.MaxWireGuardDatagram(a.info.TunnelMTU))
	if err != nil {
		return nil, err
	}
	if a.relay != nil || (a.info.Child && a.wssLost != nil) {
		a.bind.EnableLaneDemand(a.lane)
	}
	// Redial replaces the physical connection while WireGuard retains the
	// same logical endpoint. The initial Open publishes its bind after the
	// callback, so the first attachment is completed below.
	var attachMu sync.Mutex
	var attached conn.Endpoint
	attach := func() error {
		attachMu.Lock()
		defer attachMu.Unlock()
		endpoint, err := ws.CarrierEndpoint("remote")
		if err != nil || endpoint == attached {
			return err
		}
		_, epoch, _ := a.bind.LaneState(a.lane)
		a.mu.Lock()
		defer a.mu.Unlock()
		err = a.bind.AttachStream(a.lane, epoch, wstransport.QualifiedPath{
			ID: protocol.CarrierWSS, Carrier: protocol.CarrierWSS, Endpoint: endpoint,
			SendMax: protocol.CarrierWSSDatagramMax, ReceiveMax: protocol.CarrierWSSDatagramMax, ValidUntil: a.expires,
		})
		if err == nil {
			attached = endpoint
		}
		return err
	}
	ws.OnPeerConnected = func(string, conn.Endpoint) { _ = attach() }
	config.Bind = a.bind
	if mtu := a.info.TunnelMTU; mtu > 0 {
		config.MTU = mtu
	}
	config.PinPeerEndpoints = true
	stack, err := wgnet.New(config)
	if err != nil {
		cleanup := a.bind.Close()
		if !response.Adaptive.Child && a.upgradeUnavailable.Load() && cleanup == nil {
			err = errors.Join(errAdaptiveCarrierUnavailable, err)
		}
		return nil, errors.Join(err, cleanup)
	}
	if _, open := a.bind.CarrierPort(protocol.CarrierDirectUDP); !open {
		a.udp = nil
	}
	if _, open := a.bind.CarrierPort(protocol.CarrierAlternateUDP); !open {
		a.altUDP = nil
	}
	if _, open := a.bind.CarrierPort(protocol.CarrierRelayUDP); !open {
		a.relay = nil
	}
	if dialErr := ws.InitialDialError(); dialErr != nil {
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := a.bootstrapHTTPOrQUIC(ctx)
		cancel()
		if err != nil {
			cleanup := stack.Close()
			if !response.Adaptive.Child && a.upgradeUnavailable.Load() && cleanup == nil && unavailableCarrierAttempt(err) {
				err = errors.Join(errAdaptiveCarrierUnavailable, err)
			}
			return nil, errors.Join(fmt.Errorf("adaptive WebSocket upgrade: %w", dialErr),
				fmt.Errorf("alternate adaptive carrier startup: %w", err), cleanup)
		}
	} else if err := attach(); err != nil {
		return nil, errors.Join(err, stack.Close())
	}
	if err := stack.AddPeer(wgnet.Endpoint{PublicKey: response.ServerPublicKey, Address: allowedIPsForFamily(clientIP) + "@" + a.lane.DstToString()}); err != nil {
		return nil, errors.Join(err, stack.Close())
	}
	return &connectionNetwork{stack: stack, adaptive: a, clientIP: clientIP, serverIP: serverIP, useWS: true, response: response}, nil
}
