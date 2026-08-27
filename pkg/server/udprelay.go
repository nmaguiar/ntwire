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
	multipath *wstransport.ServerMultipathBind

	mu       sync.Mutex
	sessions map[string]*udpRelaySessionState // keyed by WireGuard public key, stable across /v1/renew
}

type udpRelaySessionState struct {
	token      string
	serverAddr string
	stop       chan struct{}
	stats      protocol.RelayUDPStats
	// clientStats is this session's most recently reported
	// UDPRelayRequest.Stats, echoed back to the client (see statsFor) as
	// UDPRelayHopStats.ClientObserved -- see protocol.ClientUDPRelayStats'
	// doc comment for why this closes the hop-telemetry loop.
	clientStats *protocol.ClientUDPRelayStats
}

// relayUDPStatsSummary is an alias for the wire-level
// protocol.UDPRelayHopStats: the token-free, operator-facing form of one
// UDP-relay allocation's cumulative hop counters, used both by the protected
// server dashboard and (as UDPRelayResponse.Stats) echoed back to the client
// itself -- the same shape either way, so this is a name, not a second
// struct to keep in sync.
type relayUDPStatsSummary = protocol.UDPRelayHopStats

func relayUDPStatsSummaryFrom(stats protocol.RelayUDPStats) relayUDPStatsSummary {
	return relayUDPStatsSummary{
		ClientPacketsReceived:  stats.ClientPacketsReceived,
		ClientBytesReceived:    stats.ClientBytesReceived,
		ServerPacketsForwarded: stats.ServerPacketsForwarded,
		ServerBytesForwarded:   stats.ServerBytesForwarded,
		ServerPacketsReceived:  stats.ServerPacketsReceived,
		ServerBytesReceived:    stats.ServerBytesReceived,
		ClientPacketsForwarded: stats.ClientPacketsForwarded,
		ClientBytesForwarded:   stats.ClientBytesForwarded,
	}
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
	u := &udpRelay{bind: bind, stack: s.data.stack, agent: agent, relayAddr: relayAddr, log: s.log, multipath: s.data.multipath, sessions: map[string]*udpRelaySessionState{}}
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

// recordStats associates a relay-reported snapshot only with a token this
// server allocated. Reports are cumulative and best effort, so retaining the
// latest snapshot is enough for diagnostics and cannot turn a missed control
// message into an apparent packet loss event.
func (u *udpRelay) recordStats(report protocol.RelayUDPStatsReport) {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, sample := range report.Sessions {
		for _, st := range u.sessions {
			if st.token == sample.Token {
				st.stats = sample
				break
			}
		}
	}
}

// statsFor returns the most recently reported cumulative relay-hop counters
// for clientPubKey, plus that same client's own most recently reported leg
// counters if any (see udpRelaySessionState.clientStats). The allocation
// token stays internal: callers get only a copied, token-free diagnostic
// summary suitable for an authenticated operator status surface or for
// echoing straight back to the client itself.
func (u *udpRelay) statsFor(clientPubKey string) (relayUDPStatsSummary, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	st := u.sessions[clientPubKey]
	if st == nil || st.stats.Token == "" {
		return relayUDPStatsSummary{}, false
	}
	summary := relayUDPStatsSummaryFrom(st.stats)
	summary.ClientObserved = st.clientStats
	return summary, true
}

// recordClientStats attaches the client's own reported UDP-relay leg
// counters to its live session, if one exists. A brand-new session (no
// entry yet, e.g. the very first /v1/udp-relay call that establishes it)
// silently has nothing to attach to -- expected, since the client cannot
// have observed any traffic on a candidate it has not registered yet.
func (u *udpRelay) recordClientStats(clientPubKey string, stats *protocol.ClientUDPRelayStats) {
	if stats == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if st, ok := u.sessions[clientPubKey]; ok {
		st.clientStats = stats
	}
}

// RecordUDPRelayStats accepts a report from whichever relay agent is
// currently preferred. Unknown or stale tokens are ignored deliberately:
// a relay reconnect can race an allocation replacement, and telemetry must
// never resurrect or alter a data-plane session.
func (s *Server) RecordUDPRelayStats(report protocol.RelayUDPStatsReport) {
	if u := s.udpr.Load(); u != nil {
		u.recordStats(report)
	}
}

// udpRelayStatsFor returns a best-effort relay-hop snapshot for one live
// WireGuard peer. Missing telemetry is normal for direct/WSS sessions, older
// relays, and a newly allocated UDP-relay session before its first report.
func (s *Server) udpRelayStatsFor(clientPubKey string) (relayUDPStatsSummary, bool) {
	if u := s.udpr.Load(); u != nil {
		return u.statsFor(clientPubKey)
	}
	return relayUDPStatsSummary{}, false
}

// sessionFor is the idempotent entry point the /v1/udp-relay HTTP handler
// calls: a live allocation for clientPubKey is returned unchanged -- a
// client's upgrade ladder retries this endpoint on every retry cycle, every
// revert, and every renewal, so a non-idempotent allocate here would leak
// pooled relay ports relay-wide on any flapping client -- otherwise a new
// session is requested from the relay, this server's own WireGuard peer
// endpoint for clientPubKey is pointed at the allocated address, and the
// session's bind-and-keepalive loop is started. clientStats, if present, is
// recorded against the existing session (if any) and the response always
// carries back whatever hop-telemetry summary this server currently has --
// see statsFor and protocol.UDPRelayResponse.Stats.
func (u *udpRelay) sessionFor(ctx context.Context, clientPubKey string, multipath, multipathV2, multipathV3, pathMTU bool, clientStats *protocol.ClientUDPRelayStats) protocol.UDPRelayResponse {
	u.recordClientStats(clientPubKey, clientStats)
	u.mu.Lock()
	if st, ok := u.sessions[clientPubKey]; ok {
		u.mu.Unlock()
		resp := protocol.UDPRelayResponse{RelayAddr: u.relayAddr, Token: st.token}
		if hop, ok := u.statsFor(clientPubKey); ok {
			resp.Stats = &hop
		}
		return resp
	}
	u.mu.Unlock()

	actx, cancel := context.WithTimeout(ctx, udpRelayAllocateTimeout)
	defer cancel()
	token, serverAddr, err := u.agent.AllocateUDPSession(actx)
	if err != nil || token == "" || serverAddr == "" {
		return protocol.UDPRelayResponse{}
	}

	if multipath && u.multipath != nil {
		ep, e := u.bind.ParseEndpoint(serverAddr)
		if e != nil {
			u.agent.ReleaseUDPSession(token)
			return protocol.UDPRelayResponse{}
		}
		u.multipath.RegisterPath(clientPubKey, "udp-relay", wstransport.PathUDPRelay, ep, multipathV2, multipathV3, pathMTU)
	} else if err := u.stack.UpdateEndpoint(clientPubKey, serverAddr); err != nil {
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
