package server

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

// udpRelayBindKeepalive is how often a bound UDP-relay session resends
// FrameRelayBind: refreshing both this leg's NAT mapping and the relay's
// idle timeout for the session. Comfortably under a typical NAT UDP
// binding's ~30s idle timeout, the same margin reflectInterval keeps for the
// direct-UDP upgrade's self-reflection (see directudp.go).
const udpRelayBindKeepalive = 15 * time.Second

// udpRelayAllocateTimeout bounds one AllocateUDPSession round trip over the
// relay's control connection.
const udpRelayAllocateTimeout = 5 * time.Second

// udpSessionAllocator is the subset of *RelayAgent's UDP-relay methods
// udpRelay depends on, narrowed so tests can substitute a fake and exercise
// sessionFor's idempotency/error handling without a live relay control
// connection.
type udpSessionAllocator interface {
	AllocateUDPSession(ctx context.Context) (token, serverAddr string, err error)
	ReleaseUDPSession(token string)
}

// udpRelay is the server's relay-mediated UDP forwarding state: per-client
// allocations obtained from the relay's control connection, one bind-and-
// keepalive loop each, released on session end. Unlike directUDP (gated
// behind relay.advertise_direct because it leaks the server's real
// address), this is created unconditionally whenever the relay offers the
// tier -- see EnableUDPRelay and RelayConfig's doc comment on
// AdvertiseDirect for why that asymmetry is deliberate.
type udpRelay struct {
	bind      *wstransport.FilterBind
	stack     *wgnet.Stack
	agent     udpSessionAllocator
	relayAddr string
	log       *slog.Logger

	mu       sync.Mutex
	sessions map[string]*udpRelaySessionState // keyed by WireGuard public key, stable across /v1/renew
}

type udpRelaySessionState struct {
	token      string
	serverAddr string
	stop       chan struct{}
}

// EnableUDPRelay wires the server's UDP-relay forwarding tier for
// relayAddr, the relay's shared client-facing UDP-relay address from this
// registration (RelayRegisterResponse.UDPRelayAddr). The caller --
// cmd/ntwire-server, wiring RelayAgent.OnUDPRelayAddr -- calls this
// unconditionally whenever the relay reports a non-empty address; unlike
// EnableDirectUpgrade there is no relay.advertise_direct-style gate to
// check first, because this tier never reveals the server's real address to
// a client.
//
// A later call (e.g. after a control-connection reconnect) replaces any
// previous state and stops its sessions' keepalive goroutines; a client
// whose session was lost this way simply re-allocates on its next
// /v1/udp-relay call, the same as it would after any other transient relay
// hiccup.
func (s *Server) EnableUDPRelay(agent *RelayAgent, relayAddr string) {
	prev := s.udpr.Swap(nil)
	if prev != nil {
		prev.stopAll()
	}
	if relayAddr == "" || s.data == nil || s.data.ws == nil {
		return
	}
	bind, ok := s.data.ws.UDP.(*wstransport.FilterBind)
	if !ok {
		s.log.Warn("UDP-relay forwarding unavailable: WireGuard UDP bind is not a FilterBind")
		return
	}
	u := &udpRelay{bind: bind, stack: s.data.stack, agent: agent, relayAddr: relayAddr, log: s.log, sessions: map[string]*udpRelaySessionState{}}
	s.udpr.Store(u)
}

// stopAll stops every session's keepalive goroutine, without releasing them
// on the relay: EnableUDPRelay calls this on a reconnect, where the old
// control connection (and thus the old RelayAgent.ReleaseUDPSession target)
// is already gone -- the relay's own idle timeout reclaims these sessions'
// pooled ports instead.
func (u *udpRelay) stopAll() {
	u.mu.Lock()
	sessions := u.sessions
	u.sessions = nil
	u.mu.Unlock()
	for _, st := range sessions {
		close(st.stop)
	}
}

// sessionFor is the idempotent entry point the /v1/udp-relay HTTP handler
// calls: a live allocation for clientPubKey is returned unchanged -- a
// client's upgrade ladder retries this endpoint on every retry cycle, every
// revert, and every renewal, so a non-idempotent allocate here would leak
// pooled relay ports relay-wide on any flapping client -- otherwise a new
// session is requested from the relay, this server's own WireGuard peer
// endpoint for clientPubKey is pointed at the allocated address, and the
// session's bind-and-keepalive loop is started.
func (u *udpRelay) sessionFor(ctx context.Context, clientPubKey string) protocol.UDPRelayResponse {
	u.mu.Lock()
	if st, ok := u.sessions[clientPubKey]; ok {
		u.mu.Unlock()
		return protocol.UDPRelayResponse{RelayAddr: u.relayAddr, Token: st.token}
	}
	u.mu.Unlock()

	actx, cancel := context.WithTimeout(ctx, udpRelayAllocateTimeout)
	defer cancel()
	token, serverAddr, err := u.agent.AllocateUDPSession(actx)
	if err != nil || token == "" || serverAddr == "" {
		return protocol.UDPRelayResponse{}
	}

	if err := u.stack.UpdateEndpoint(clientPubKey, serverAddr); err != nil {
		u.agent.ReleaseUDPSession(token)
		return protocol.UDPRelayResponse{}
	}

	st := &udpRelaySessionState{token: token, serverAddr: serverAddr, stop: make(chan struct{})}
	u.mu.Lock()
	if u.sessions == nil {
		// stopAll ran concurrently (a relay reconnect landed mid-allocation):
		// the tier this allocation belongs to is already gone, so don't
		// resurrect it under the new one.
		u.mu.Unlock()
		u.agent.ReleaseUDPSession(token)
		return protocol.UDPRelayResponse{}
	}
	u.sessions[clientPubKey] = st
	u.mu.Unlock()

	if err := u.bind.SendControl(wstransport.FrameRelayBind, []byte(token), serverAddr); err != nil {
		u.log.Debug("udp relay: initial bind send failed", "server_addr", serverAddr, "error", err)
	}
	go u.keepaliveLoop(st)

	return protocol.UDPRelayResponse{RelayAddr: u.relayAddr, Token: token}
}

func (u *udpRelay) keepaliveLoop(st *udpRelaySessionState) {
	ticker := time.NewTicker(udpRelayBindKeepalive)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := u.bind.SendControl(wstransport.FrameRelayBind, []byte(st.token), st.serverAddr); err != nil {
				u.log.Debug("udp relay: bind keepalive send failed", "server_addr", st.serverAddr, "error", err)
			}
		case <-st.stop:
			return
		}
	}
}

// release ends the UDP-relay session for pubKey, if one exists: stops its
// keepalive goroutine and tells the relay it can reclaim the session's
// pooled port immediately rather than waiting out its idle timeout. Called
// from dropSession, the same place that already tears down the WebSocket
// fallback's per-pubkey session (Bind.CloseSession).
func (u *udpRelay) release(pubKey string) {
	u.mu.Lock()
	st, ok := u.sessions[pubKey]
	if ok {
		delete(u.sessions, pubKey)
	}
	u.mu.Unlock()
	if !ok {
		return
	}
	close(st.stop)
	u.agent.ReleaseUDPSession(st.token)
}
