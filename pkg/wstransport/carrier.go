package wstransport

import (
	"fmt"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// Carrier configures one socket or connection group owned by AdaptiveBind.
// An alternate local UDP port uses its own carrier. A relay candidate may
// share a UDP carrier with other candidates when their remote tuples differ.
type Carrier struct {
	Name        string
	Bind        conn.Bind
	ListenPort  uint16
	Optional    bool // failure to open this non-primary bind leaves other carriers available
	DatagramMax int  // largest complete encrypted datagram this carrier can send
	// SendFailed may enqueue a local health signal. It must not block or
	// perform carrier selection from the WireGuard send worker.
	SendFailed func(error)
}

// QualifiedPath is a local handoff from the lane's authentication and
// qualification code. It is never decoded from a remote request.
type QualifiedPath struct {
	ID         string
	Carrier    string
	Endpoint   conn.Endpoint
	SendMax    int
	ReceiveMax int
	ValidUntil time.Time
}

type carrierSource struct {
	addr     netip.AddrPort
	instance *carrierInstance
}

// A connection identity, distinct from any reusable endpoint label.
type carrierInstance struct{ _ byte }

type identifiedCarrierEndpoint interface {
	carrierSource() carrierSource
}

func (e udpEndpoint) carrierSource() carrierSource {
	return carrierSource{addr: e.addr}
}

func (e endpoint) carrierSource() carrierSource {
	return carrierSource{instance: e.carrier}
}

func getCarrierSource(ep conn.Endpoint) (carrierSource, bool) {
	e, ok := ep.(identifiedCarrierEndpoint)
	if !ok {
		return carrierSource{}, false
	}
	s := e.carrierSource()
	return s, s.instance != nil || (s.addr.IsValid() && s.addr.Port() != 0 && !s.addr.Addr().IsUnspecified() && !s.addr.Addr().IsMulticast())
}

// CarrierEndpoint returns the current incarnation of an authenticated
// WebSocket peer for the adaptive controller to qualify. Send on this
// endpoint fails if the connection was replaced, even with the same id.
func (b *Bind) CarrierEndpoint(id string) (conn.Endpoint, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	p := b.peers[id]
	if p == nil {
		return nil, fmt.Errorf("WebSocket peer is not connected")
	}
	ep := p.endpoint
	ep.pinned = true
	return ep, nil
}

func validCarrierID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range []byte(s) {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
