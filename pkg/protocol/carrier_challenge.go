package protocol

import (
	"crypto/rand"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

const carrierChallengeLifetime = 5 * time.Second

// CarrierUDPPath is a tuple observed by the local network reader. LocalPort
// distinguishes the primary and alternate listeners of the same host.
type CarrierUDPPath struct {
	LocalPort uint16
	Remote    netip.AddrPort
}

// CarrierChallenge records one outstanding direct UDP probe. Its owner must
// bound the number of outstanding challenges and invalidate them on renew,
// path replacement, or revocation.
type CarrierChallenge struct {
	mu       sync.Mutex
	scope    CarrierProofScope
	key      [32]byte
	expected CarrierProof
	path     CarrierUDPPath
	sent     time.Time
	consumed bool
}

// BeginCarrierChallenge issues a proof nonce for a known candidate socket
// and returns the datagram to send there. A successful challenge shows
// reachability and a tested datagram size. Lane key possession is verified
// separately by exchanging traffic through WireGuard.
func BeginCarrierChallenge(scope CarrierProofScope, key [32]byte, path CarrierUDPPath, direction CarrierDirection, size uint16, now time.Time) (*CarrierChallenge, []byte, error) {
	if path.LocalPort == 0 || !path.Remote.IsValid() || path.Remote.Port() == 0 || path.Remote.Addr().IsUnspecified() ||
		path.Remote.Addr().IsMulticast() || now.IsZero() {
		return nil, nil, fmt.Errorf("invalid carrier challenge endpoint")
	}
	proof := CarrierProof{Kind: CarrierProbe, Direction: direction, Size: size}
	if _, err := rand.Read(proof.Nonce[:]); err != nil {
		return nil, nil, fmt.Errorf("carrier challenge nonce: %w", err)
	}
	frame := EncodeCarrierProof(scope, key, proof)
	if frame == nil {
		return nil, nil, fmt.Errorf("invalid carrier challenge proof parameters")
	}
	proof.Kind = CarrierACK
	return &CarrierChallenge{scope: scope, key: key, expected: proof, path: path, sent: now}, frame, nil
}

// AcceptACK checks the observed UDP path before verifying the ACK.
// Exactly one successful response consumes the challenge.
func (c *CarrierChallenge) AcceptACK(path CarrierUDPPath, frame []byte, now time.Time) (rtt time.Duration, accepted bool) {
	if path != c.path {
		return 0, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	elapsed := now.Sub(c.sent)
	if elapsed >= carrierChallengeLifetime {
		c.consumed = true
	}
	if c.consumed || elapsed < 0 {
		return 0, false
	}
	proof, ok := DecodeCarrierProof(c.scope, c.key, frame)
	if !ok || proof != c.expected {
		return 0, false
	}
	c.consumed = true
	return elapsed, true
}
