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
// healthy member reaches the same TLS handler. The first healthy configured
// member is the preferred source for optional UDP/direct-upgrade facilities;
// losing it selects the next member without taking the server offline.
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
	OnReflectAddr  func(string)
	OnUDPRelayAddr func(*RelayAgent, string)
}

type relayPoolMember struct {
	agent      *RelayAgent
	registered bool
	response   protocol.RelayRegisterResponse
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
	var preferred *relayPoolMember
	for _, candidate := range p.members {
		if candidate.registered {
			preferred = candidate
			break
		}
	}
	p.preferred = preferred
	changed := oldPreferred != preferred
	if preferred == member && registered && (oldResponse.ReflectAddr != response.ReflectAddr || oldResponse.UDPRelayAddr != response.UDPRelayAddr) {
		changed = true
	}
	reflectAddr := ""
	udpAddr := ""
	if preferred != nil {
		reflectAddr, udpAddr = preferred.response.ReflectAddr, preferred.response.UDPRelayAddr
	}
	onReflect, onUDP := p.OnReflectAddr, p.OnUDPRelayAddr
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
