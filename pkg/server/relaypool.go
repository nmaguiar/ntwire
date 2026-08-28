package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

// RelayPool keeps a server registered with every configured relay. All
// members share one listener, so an inbound connection arriving through any
// healthy member reaches the same TLS handler. Exactly one registered member
// is preferred at a time -- the source for optional UDP-relay/direct-upgrade
// facilities -- chosen by availability score (see relayPoolMember.score)
// only when there is no current preferred member or it has stopped being
// registered; see update/choosePreferred. Every other registered member
// keeps its own live control connection regardless (Run starts all of them
// unconditionally), so it is already a warm standby, not a cold one that
// needs separately keeping alive.
type RelayPool struct {
	listener  *relayListener
	members   []*relayPoolMember
	log       *slog.Logger
	mu        sync.Mutex
	closed    bool
	domain    string
	preferred *relayPoolMember

	// Callbacks run after the preferred healthy member changes. They are
	// intentionally optional so a pool also works for WebSocket-only relays.
	OnReflectAddr     func(string)
	OnUDPRelayAddr    func(*RelayAgent, string)
	OnNativeWireGuard func(string, string)
}

type relayPoolMember struct {
	agent      *RelayAgent
	registered bool
	response   protocol.RelayRegisterResponse
}

// score ranks a registered member for preferred selection: lower is better.
// A member currently offering no UDP-relay address is deprioritized (it can
// still carry the TLS/WSS control-plane traffic, but not the UDP-relay
// tier), then members are ranked by observed AllocateUDPSession failure
// rate. A member with no allocation attempts yet scores as neutral, never as
// if it had already failed: no data yet is not confirmed failure.
//
// Deliberately lifetime-cumulative, not EWMA/rolling-window like path RTT and
// loss: score only ever
// runs in choosePreferred, when there is no current preferred member at all
// (a rare, coarse-grained event), not on a packet hot path, so there is no
// windowing concern to smooth away transient noise for. The tradeoff is that
// a member with one bad past hour carries that failure rate indefinitely; if
// that turns out to matter in practice, moving to a rolling window here is
// the fix, not changing what feeds Scheduler.score -- this stays out of the
// per-packet path entirely.
func (m *relayPoolMember) score() float64 {
	sc := 0.0
	if m.response.UDPRelayAddr == "" {
		sc += 1.0
	}
	success, failure := m.agent.AllocationStats()
	if total := success + failure; total > 0 {
		sc += float64(failure) / float64(total)
	}
	return sc
}

// NewRelayPool creates either the legacy one-member pool or an active-active
// pool from relay.endpoints. Every endpoint inherits the tenant identity and
// reconnect policy from cfg, while its URL and TLS pin stay endpoint-local.
func NewRelayPool(cfg RelayConfig, log *slog.Logger) (*RelayPool, error) {
	if log == nil {
		log = slog.Default()
	}
	p := &RelayPool{listener: newRelayListener(), log: log}
	endpoints := cfg.Endpoints
	if len(endpoints) == 0 {
		endpoints = []RelayEndpoint{{URL: cfg.URL, Fingerprint: cfg.Fingerprint}}
	}
	for _, endpoint := range endpoints {
		memberCfg := cfg
		memberCfg.URL, memberCfg.Fingerprint, memberCfg.Endpoints = endpoint.URL, endpoint.Fingerprint, nil
		a, err := newRelayAgent(memberCfg, log, p.listener)
		if err != nil {
			_ = p.Close()
			return nil, err
		}
		member := &relayPoolMember{agent: a}
		a.OnRegistration = func(resp protocol.RelayRegisterResponse) {
			p.update(member, true, resp)
		}
		a.OnDisconnected = func() { p.update(member, false, protocol.RelayRegisterResponse{}) }
		p.members = append(p.members, member)
	}
	return p, nil
}

func (p *RelayPool) Listener() net.Listener { return p.listener }

// Agents returns the pool's stable relay-agent set. It is used for optional
// control-plane callbacks that must be attached before Run starts; callers
// receive a new slice and cannot change pool membership.
func (p *RelayPool) Agents() []*RelayAgent {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*RelayAgent, len(p.members))
	for i, member := range p.members {
		out[i] = member.agent
	}
	return out
}

// SetSocksTargets propagates the server's SOCKS egress targets to every pool member.
func (p *RelayPool) SetSocksTargets(targets []protocol.SocksTarget) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, m := range p.members {
		m.agent.SetSocksTargets(targets)
	}
}

// Run keeps all members active until ctx is canceled.
func (p *RelayPool) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, m := range p.members {
		wg.Add(1)
		go func(a *RelayAgent) { defer wg.Done(); a.Run(ctx) }(m.agent)
	}
	go func() { <-ctx.Done(); wg.Wait() }()
}

func (p *RelayPool) update(member *relayPoolMember, registered bool, response protocol.RelayRegisterResponse) {
	p.mu.Lock()
	if registered && response.Domain != "" && p.domain != "" && response.Domain != p.domain {
		registered = false
		p.log.Warn("relay pool member rejected: client domain differs from pool", "expected_domain", p.domain, "got_domain", response.Domain)
	}
	if registered && response.Domain != "" && p.domain == "" {
		p.domain = response.Domain
	}
	oldResponse := member.response
	oldPreferred := p.preferred
	member.registered, member.response = registered, response
	preferred := p.choosePreferred(oldPreferred)
	p.preferred = preferred
	changed := oldPreferred != preferred
	if preferred == member && registered && (oldResponse.ReflectAddr != response.ReflectAddr || oldResponse.UDPRelayAddr != response.UDPRelayAddr || oldResponse.NativeWireGuardAddr != response.NativeWireGuardAddr || oldResponse.NativeWireGuardToken != response.NativeWireGuardToken) {
		changed = true
	}
	reflectAddr := ""
	udpAddr := ""
	if preferred != nil {
		reflectAddr, udpAddr = preferred.response.ReflectAddr, preferred.response.UDPRelayAddr
	}
	onReflect, onUDP, onNative := p.OnReflectAddr, p.OnUDPRelayAddr, p.OnNativeWireGuard
	p.mu.Unlock()
	if changed && onReflect != nil {
		onReflect(reflectAddr)
	}
	if changed && onUDP != nil {
		var agent *RelayAgent
		if preferred != nil {
			agent = preferred.agent
		}
		onUDP(agent, udpAddr)
	}
	if changed && onNative != nil {
		if preferred == nil {
			onNative("", "")
		} else {
			onNative(preferred.response.NativeWireGuardAddr, preferred.response.NativeWireGuardToken)
		}
	}
}

// choosePreferred implements sticky preferred-member selection, called with
// p.mu already held. current is kept as long as it is still registered: a
// higher-scoring member reconnecting or re-registering must not itself
// force the current preferred's established UDP-relay sessions to tear down
// (see EnableUDPRelay/udpRelay.stopAll) -- "move only new allocations unless
// an established path has genuinely failed." Only when there is no current
// preferred, or it has stopped being registered, is a new one chosen, by
// lowest score (see relayPoolMember.score) among currently registered
// members.
func (p *RelayPool) choosePreferred(current *relayPoolMember) *relayPoolMember {
	if current != nil && current.registered {
		return current
	}
	var best *relayPoolMember
	for _, candidate := range p.members {
		if !candidate.registered {
			continue
		}
		if best == nil || candidate.score() < best.score() {
			best = candidate
		}
	}
	return best
}

// Healthy reports whether at least one relay control connection is live.
func (p *RelayPool) Healthy() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, m := range p.members {
		if m.registered {
			return true
		}
	}
	return false
}

func (p *RelayPool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()
	var first error
	for _, m := range p.members {
		if err := m.agent.Close(); err != nil && first == nil {
			first = err
		}
	}
	if err := p.listener.Close(); err != nil && first == nil {
		first = err
	}
	if first != nil {
		return fmt.Errorf("close relay pool: %w", first)
	}
	return nil
}
