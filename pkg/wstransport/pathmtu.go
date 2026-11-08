package wstransport

import (
	"encoding/binary"
	"time"
)

// PathMTUProbe is an authenticated, bounded candidate-path probe. Target is
// the UDP payload size, including the five-byte ntwire control header.
type PathMTUProbe struct {
	Nonce  [pathProbeSize]byte
	Target uint16
}

const minPathMTUProbe uint16 = 1200

func nextPathMTUProbe(current uint16) uint16 {
	switch current {
	case 1200:
		return 1400
	case 1400:
		return MaxRelayDatagram
	default:
		return 0
	}
}

// EncodePathMTUProbe pads the control payload to Target. The echoed ack is
// deliberately small, so the request is never an amplification primitive.
func EncodePathMTUProbe(nonce [pathProbeSize]byte, target uint16) []byte {
	if target < minPathMTUProbe || target > MaxRelayDatagram {
		return nil
	}
	b := make([]byte, int(target)-controlHeaderLen)
	copy(b, nonce[:])
	binary.LittleEndian.PutUint16(b[pathProbeSize:], target)
	return b
}
func DecodePathMTUProbe(b []byte) (PathMTUProbe, bool) {
	if len(b) < pathProbeSize+2 {
		return PathMTUProbe{}, false
	}
	var p PathMTUProbe
	copy(p.Nonce[:], b)
	p.Target = binary.LittleEndian.Uint16(b[pathProbeSize:])
	return p, p.Target >= minPathMTUProbe && p.Target <= MaxRelayDatagram && len(b) == int(p.Target)-controlHeaderLen
}
func EncodePathMTUAck(nonce [pathProbeSize]byte, target uint16) []byte {
	b := make([]byte, pathProbeSize+2)
	copy(b, nonce[:])
	binary.LittleEndian.PutUint16(b[pathProbeSize:], target)
	return b
}
func DecodePathMTUAck(b []byte) (PathMTUProbe, bool) {
	if len(b) != pathProbeSize+2 {
		return PathMTUProbe{}, false
	}
	var p PathMTUProbe
	copy(p.Nonce[:], b)
	p.Target = binary.LittleEndian.Uint16(b[pathProbeSize:])
	return p, p.Target >= minPathMTUProbe && p.Target <= MaxRelayDatagram
}

// DefaultTunnelMTU is the WireGuard netstack MTU ntwire uses unless a client
// opts into a smaller one.
const DefaultTunnelMTU = 1420

// wireGuardTransportOverhead is the per-packet WireGuard transport header
// and authentication tag added to an inner IP packet (16 + 16 bytes).
const wireGuardTransportOverhead = 32

// MTU states reported in PathStatus.MTUState by an MTU-aware bind. Without
// MultipathOptions.MTUAware the field stays empty.
const (
	MTUStateProbing = "probing"
	MTUStateOK      = "ok"
	MTUStateLimited = "limited"
)

const (
	mtuProbeTimeout = 2 * time.Second
	mtuMaxAttempts  = 3
)

// mtuPolicy is the opt-in MTU-aware probe ladder. The default (nil policy)
// keeps nextPathMTUProbe's diagnostic 1200 -> 1400 -> 1500 ladder with no
// retries and no selection effect.
type mtuPolicy struct {
	// required is the UDP payload a full-size tunnel packet needs.
	required uint16
	ladder   []uint16
}

// newMTUPolicy returns nil unless opts.MTUAware is set.
func newMTUPolicy(opts MultipathOptions) *mtuPolicy {
	if !opts.MTUAware {
		return nil
	}
	tunnel := opts.TunnelMTU
	if tunnel <= 0 {
		tunnel = DefaultTunnelMTU
	}
	required := uint16(tunnel + wireGuardTransportOverhead)
	if required < minPathMTUProbe {
		required = minPathMTUProbe
	}
	if required > MaxRelayDatagram {
		required = MaxRelayDatagram
	}
	ladder := []uint16{minPathMTUProbe}
	for _, step := range []uint16{1400, required, MaxRelayDatagram} {
		if step > ladder[len(ladder)-1] && step <= MaxRelayDatagram && (step <= required || step == MaxRelayDatagram) {
			ladder = append(ladder, step)
		}
	}
	return &mtuPolicy{required: required, ladder: ladder}
}

// next returns the ladder step after an acknowledged target, or 0 when the
// ladder is complete.
func (p *mtuPolicy) next(acked uint16) uint16 {
	for _, step := range p.ladder {
		if step > acked {
			return step
		}
	}
	return 0
}

// stateAfterGivingUp classifies a step that exhausted its retries: failing
// at or below the required size means full-size packets would be dropped.
func (p *mtuPolicy) stateAfterGivingUp(target uint16) string {
	if target <= p.required {
		return MTUStateLimited
	}
	return MTUStateOK
}

// stateAfterAck reports the state an acknowledged target proves, or "" when
// it proves nothing new.
func (p *mtuPolicy) stateAfterAck(target uint16) string {
	if target >= p.required {
		return MTUStateOK
	}
	return ""
}
