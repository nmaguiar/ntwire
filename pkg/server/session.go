package server

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"sync"
	"time"
)

// Session identifies a principal by (Method, Identity): for SSH, Identity is
// the key fingerprint (mirrored in Fingerprint for existing callers); for
// OIDC, Identity is the verified email and Issuer/Groups are also populated.
type Session struct {
	ID, Token                                 string
	Method                                    string // "ssh" or "oidc"
	Identity                                  string
	Fingerprint, WireGuardPublicKey, TunnelIP string
	Issuer                                    string
	Groups                                    []string
	Tunnels                                   []protocol.Tunnel
	LatencyMillis, Reconnections              uint64
	Multipath                                 bool
	// MultipathV2 is true only when this session additionally negotiated
	// CapabilityMultipathV2; always false when Multipath is false.
	MultipathV2 bool
	Expires     time.Time
}
type Sessions struct {
	mu      sync.Mutex
	byToken map[string]Session
}

func NewSessions() *Sessions { return &Sessions{byToken: map[string]Session{}} }
func token() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("session: crypto/rand unavailable: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// CreateParams describes a new session. Method-specific fields
// (Fingerprint / Issuer+Groups) are left zero for the other method.
type CreateParams struct {
	Method                       string
	Identity                     string
	Fingerprint                  string
	Issuer                       string
	Groups                       []string
	WireGuardPublicKey, TunnelIP string
	Tunnels                      []protocol.Tunnel
	LatencyMillis, Reconnections uint64
	Multipath                    bool
	MultipathV2                  bool
	TTL                          time.Duration
}

func (s *Sessions) Create(p CreateParams) Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := Session{
		ID: token(), Token: token(),
		Method: p.Method, Identity: p.Identity, Fingerprint: p.Fingerprint,
		Issuer: p.Issuer, Groups: p.Groups,
		WireGuardPublicKey: p.WireGuardPublicKey, TunnelIP: p.TunnelIP,
		Tunnels: p.Tunnels, LatencyMillis: p.LatencyMillis, Reconnections: p.Reconnections, Multipath: p.Multipath, MultipathV2: p.MultipathV2, Expires: time.Now().Add(p.TTL),
	}
	s.byToken[v.Token] = v
	return v
}

// FindWireGuardPublicKey returns the live session using a WireGuard peer.
// A reconnect replaces that session while retaining its tunnel address.
func (s *Sessions) FindWireGuardPublicKey(key string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for token, v := range s.byToken {
		if now.After(v.Expires) {
			delete(s.byToken, token)
			continue
		}
		if key != "" && v.WireGuardPublicKey == key {
			return v, true
		}
	}
	return Session{}, false
}
func (s *Sessions) Get(t string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.byToken[t]
	if !ok || time.Now().After(v.Expires) {
		delete(s.byToken, t)
		return Session{}, false
	}
	return v, true
}
func (s *Sessions) Delete(t string) { s.mu.Lock(); defer s.mu.Unlock(); delete(s.byToken, t) }

// DeleteByID finds a live session by its ID (distinct from its bearer
// Token, which admin callers -- unlike the session's own owner -- never
// have) and atomically removes it, so a concurrent renew or expiry can't
// race an admin revoke into deleting the wrong generation of a session.
func (s *Sessions) DeleteByID(id string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for token, v := range s.byToken {
		if now.After(v.Expires) {
			delete(s.byToken, token)
			continue
		}
		if v.ID == id {
			delete(s.byToken, token)
			return v, true
		}
	}
	return Session{}, false
}

// CountIdentity counts live sessions for one principal, scoped by method so
// an SSH fingerprint and an OIDC email can never collide in the count.
func (s *Sessions) CountIdentity(method, identity string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	now := time.Now()
	for k, v := range s.byToken {
		if now.After(v.Expires) {
			delete(s.byToken, k)
			continue
		}
		if v.Method == method && v.Identity == identity {
			n++
		}
	}
	return n
}
func (s *Sessions) Reap() []Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	var dead []Session
	for k, v := range s.byToken {
		if now.After(v.Expires) {
			dead = append(dead, v)
			delete(s.byToken, k)
		}
	}
	return dead
}
func (s *Sessions) All() []Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Session, 0, len(s.byToken))
	for _, v := range s.byToken {
		out = append(out, v)
	}
	return out
}
