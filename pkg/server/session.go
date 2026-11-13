package server

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"sync"
	"time"
)

// Session retains the display identity separately from OIDC quota identity.
// SSH quotas use Identity (the key fingerprint); OIDC quotas use the verified
// OIDCIssuer and OIDCSubject, while Identity remains the verified email.
type Session struct {
	ID, Token                                 string
	Method                                    string // "ssh" or "oidc"
	Identity                                  string
	Fingerprint, WireGuardPublicKey, TunnelIP string
	Issuer                                    string
	OIDCIssuer, OIDCSubject                   string
	Groups                                    []string
	Tunnels                                   []protocol.Tunnel
	LatencyMillis, Reconnections              uint64
	Multipath                                 bool
	// PathMTU is true only when this session negotiated CapabilityPathMTUV1.
	PathMTU bool
	// Promote is true only when this session negotiated
	// CapabilityPathPromoteV1.
	Promote    bool
	ClientInfo protocol.ClientInfo
	Expires    time.Time
}

// Expired sessions remain until Reap transfers them to the resource cleanup owner.
// Lookups must reject them without discarding the cleanup record.
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
	OIDCIssuer, OIDCSubject      string
	Groups                       []string
	WireGuardPublicKey, TunnelIP string
	Tunnels                      []protocol.Tunnel
	LatencyMillis, Reconnections uint64
	Multipath                    bool
	PathMTU                      bool
	Promote                      bool
	ClientInfo                   protocol.ClientInfo
	TTL                          time.Duration
}

func (s *Sessions) Create(p CreateParams) Session {
	if key, err := wgnet.CanonicalPublicKey(p.WireGuardPublicKey); err == nil {
		p.WireGuardPublicKey = key
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v := Session{
		ID: token(), Token: token(),
		Method: p.Method, Identity: p.Identity, Fingerprint: p.Fingerprint,
		Issuer: p.Issuer, Groups: p.Groups, OIDCIssuer: p.OIDCIssuer, OIDCSubject: p.OIDCSubject,
		WireGuardPublicKey: p.WireGuardPublicKey, TunnelIP: p.TunnelIP,
		Tunnels: p.Tunnels, LatencyMillis: p.LatencyMillis, Reconnections: p.Reconnections, Multipath: p.Multipath, PathMTU: p.PathMTU, Promote: p.Promote, ClientInfo: p.ClientInfo, Expires: time.Now().Add(p.TTL),
	}
	s.byToken[v.Token] = v
	return v
}

// FindWireGuardPublicKey returns the live session using a WireGuard peer.
// A reconnect replaces that session while retaining its tunnel address.
func (s *Sessions) FindWireGuardPublicKey(key string) (Session, bool) {
	if canonical, err := wgnet.CanonicalPublicKey(key); err == nil {
		key = canonical
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, v := range s.byToken {
		if now.After(v.Expires) {
			continue
		}
		existing := v.WireGuardPublicKey
		if canonical, err := wgnet.CanonicalPublicKey(existing); err == nil {
			existing = canonical
		}
		if key != "" && existing == key {
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
		return Session{}, false
	}
	return v, true
}

// FindID returns a live session by its opaque ID. It is used only to bind a
// short-lived client certificate to the session that obtained it.
func (s *Sessions) FindID(id string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, v := range s.byToken {
		if now.After(v.Expires) {
			continue
		}
		if v.ID == id {
			return v, true
		}
	}
	return Session{}, false
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
	for _, v := range s.byToken {
		if now.After(v.Expires) {
			continue
		}
		if v.ID == id {
			delete(s.byToken, v.Token)
			return v, true
		}
	}
	return Session{}, false
}

// CountIdentity counts live sessions by SSH fingerprint or verified OIDC
// issuer and subject. Email changes and issuer aliases do not reset OIDC quotas.
func (s *Sessions) CountIdentity(method, identity, oidcIssuer, oidcSubject string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	now := time.Now()
	for _, v := range s.byToken {
		if now.After(v.Expires) {
			continue
		}
		sameIdentity := v.Identity == identity
		if method == "oidc" {
			sameIdentity = v.OIDCIssuer == oidcIssuer && v.OIDCSubject == oidcSubject
		}
		if v.Method == method && sameIdentity {
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
