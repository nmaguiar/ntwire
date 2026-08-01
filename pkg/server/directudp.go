package server

import (
	"log/slog"
	"sync"
	"time"

	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

// reflectInterval is how often the server re-queries its own NAT-mapped UDP
// address once relay.advertise_direct is enabled. It is kept well under a
// typical NAT UDP binding's ~30s idle timeout so the cached candidate stays
// usable between refreshes rather than going stale right before a client
// asks for it in /v1/punch.
const reflectInterval = 20 * time.Second
const reflectRequestTimeout = 3 * time.Second

// wstransport.PrimeBurst/PrimeInterval (shared with pkg/client's own
// priming, so both ends of a punch attempt stay in sync) bound how many
// NAT-priming pings /v1/punch fires at a client-reported candidate: enough
// to open a short-lived NAT pinhole, small enough that an authenticated
// caller supplying an arbitrary ClientAddr (there is no way to verify it is
// really theirs) cannot turn this endpoint into a meaningful packet
// generator against a third party.

// directUDP is the server's opportunistic direct-connection upgrade state,
// created only when relay.advertise_direct is enabled: periodic
// self-reflection off the relay's UDP reflector, cached for /v1/punch to
// hand to authenticated clients, plus the NAT-priming send path.
type directUDP struct {
	bind         *wstransport.FilterBind
	relayReflect string
	log          *slog.Logger
	stop         chan struct{}

	mu        sync.RWMutex
	candidate string
}

// EnableDirectUpgrade starts (or, on a later relay reconnect, restarts) the
// server's self-reflection loop against a relay-provided UDP reflector
// address, and makes /v1/punch start answering. relayReflectAddr == ""
// (relay has no reflector configured, or gave none) disables it again.
//
// The caller -- cmd/ntwire-server, wiring RelayAgent.OnReflectAddr -- must
// only invoke this when relay.advertise_direct is set. That gate has to
// cover self-reflection itself, not just whether /v1/punch answers: a
// relayed server that leaves advertise_direct unset must never send even one
// packet toward the relay's reflector, since that packet alone would leak
// its real egress IP into the relay's logs -- precisely what choosing relay
// mode without this flag is meant to avoid.
func (s *Server) EnableDirectUpgrade(relayReflectAddr string) {
	s.mu.Lock()
	prev := s.direct
	s.direct = nil
	s.mu.Unlock()
	if prev != nil {
		close(prev.stop)
	}
	if relayReflectAddr == "" || s.data == nil || s.data.ws == nil {
		return
	}
	bind, ok := s.data.ws.UDP.(*wstransport.FilterBind)
	if !ok {
		s.log.Warn("direct-connection upgrade unavailable: WireGuard UDP bind is not a FilterBind")
		return
	}
	d := &directUDP{bind: bind, relayReflect: relayReflectAddr, log: s.log, stop: make(chan struct{})}
	s.mu.Lock()
	s.direct = d
	s.mu.Unlock()
	go d.reflectLoop()
}

func (d *directUDP) selfCandidate() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.candidate
}

func (d *directUDP) reflectLoop() {
	d.selfReflect()
	ticker := time.NewTicker(reflectInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			d.selfReflect()
		case <-d.stop:
			return
		}
	}
}

func (d *directUDP) selfReflect() {
	if err := d.bind.SendControl(wstransport.FrameReflectRequest, nil, d.relayReflect); err != nil {
		d.log.Debug("self-reflection request failed", "relay_reflect", d.relayReflect, "error", err)
		return
	}
	timer := time.NewTimer(reflectRequestTimeout)
	defer timer.Stop()
	for {
		select {
		case cp := <-d.bind.Control():
			if cp.Type != wstransport.FrameReflectResponse {
				continue // e.g. a client's NAT-priming ping, not our reply
			}
			d.mu.Lock()
			d.candidate = string(cp.Payload)
			d.mu.Unlock()
			return
		case <-timer.C:
			d.log.Debug("self-reflection response timed out", "relay_reflect", d.relayReflect)
			return
		case <-d.stop:
			return
		}
	}
}

// primeClient sends a short burst of NAT-priming pings directly to addr,
// opening this server's side of the NAT pinhole shortly before the client's
// own WireGuard handshake attempt arrives at the same address.
func (d *directUDP) primeClient(addr string) {
	for i := 0; i < wstransport.PrimeBurst; i++ {
		if err := d.bind.SendControl(wstransport.FramePrime, nil, addr); err != nil {
			d.log.Debug("NAT-priming send failed", "addr", addr, "error", err)
			return
		}
		if i < wstransport.PrimeBurst-1 {
			time.Sleep(wstransport.PrimeInterval)
		}
	}
}
