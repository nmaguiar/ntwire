package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
)

// Session retains the display identity separately from OIDC quota identity.
// SSH quotas use Identity (the key fingerprint); OIDC quotas use the verified
// OIDCIssuer and OIDCSubject, while Identity remains the verified email.
type Session struct {
	ID, Token                                 string
	peerLifetime                              string // changes on fresh authentication, survives renewal
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
	Promote      bool
	Adaptive     *protocol.AdaptiveSession
	flowLifetime context.Context
	children     []sessionLane // immutable once stored in Sessions
	ClientInfo   protocol.ClientInfo
	Expires      time.Time
}

// Expired sessions remain until Reap transfers them to the resource cleanup owner.
// Lookups must reject them without discarding the cleanup record.
type Sessions struct {
	mu        sync.Mutex
	byToken   map[string]Session
	byIP      map[string]sessionPrincipal
	byKey     map[string]string // anchor key to bearer
	childKeys map[string]string // child key to parent bearer
}

type sessionLane struct {
	id, key, ip  string
	flowLifetime context.Context
}

type sessionPrincipal struct {
	token     string
	principal DataPlanePrincipal
}

func NewSessions() *Sessions {
	return &Sessions{byToken: map[string]Session{}, byIP: map[string]sessionPrincipal{},
		byKey: map[string]string{}, childKeys: map[string]string{}}
}
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
	Adaptive                     *protocol.AdaptiveSession
	FlowLifetime                 context.Context
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
		Tunnels: p.Tunnels, LatencyMillis: p.LatencyMillis, Reconnections: p.Reconnections, Multipath: p.Multipath, PathMTU: p.PathMTU, Promote: p.Promote, Adaptive: p.Adaptive, flowLifetime: p.FlowLifetime, ClientInfo: p.ClientInfo, Expires: time.Now().Add(p.TTL),
	}
	v.peerLifetime = v.ID
	s.storeLocked(v)
	return v
}

// renew rotates control credentials and updates the grants without exposing a
// gap in IP ownership to the data plane.
func (s *Sessions) renew(oldToken string, tunnels []protocol.Tunnel, ttl time.Duration, info protocol.ClientInfo, resetFlows func(*Session)) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.byToken[oldToken]
	if !ok || (v.TunnelIP != "" && s.byIP[v.TunnelIP].token != oldToken) {
		return Session{}, false
	}
	s.deleteLocked(v)
	v.ID, v.Token = token(), token()
	if v.Adaptive != nil {
		info := *v.Adaptive
		info.AuthGeneration++
		v.Adaptive = &info
	}
	if resetFlows != nil && !slices.Equal(v.Tunnels, tunnels) {
		v.children = slices.Clone(v.children)
		resetFlows(&v)
	}
	v.Tunnels, v.Expires = tunnels, time.Now().Add(ttl)
	v.LatencyMillis, v.Reconnections, v.ClientInfo = info.LatencyMillis, info.Reconnections, info
	s.storeLocked(v)
	return v, true
}

func (s *Sessions) storeLocked(v Session) {
	s.byToken[v.Token] = v
	if v.WireGuardPublicKey != "" {
		s.byKey[v.WireGuardPublicKey] = v.Token
	}
	if v.TunnelIP == "" {
		return
	}
	grants := make(map[string]bool, len(v.Tunnels))
	for _, t := range v.Tunnels {
		grants[t.Name] = true
	}
	s.storePrincipal(v, v.TunnelIP, v.peerLifetime, v.flowLifetime, grants)
	for _, child := range v.children {
		s.childKeys[child.key] = v.Token
		s.storePrincipal(v, child.ip, child.id, child.flowLifetime, grants)
	}
}

func (s *Sessions) storePrincipal(v Session, ip, lifetime string, ctx context.Context, grants map[string]bool) {
	addr, _ := netip.ParseAddr(ip)
	s.byIP[ip] = sessionPrincipal{token: v.Token, principal: DataPlanePrincipal{
		peerLifetime: lifetime, flowLifetime: ctx, Method: v.Method, Identity: v.Identity, TunnelIP: addr, Tunnels: grants,
	}}
}

// trackChild publishes the child to both data-plane indexes after the
// backend is ready. The caller serializes provisioning with operationMu.
func (s *Sessions) trackChild(token string, generation uint64, child sessionLane) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.byToken[token]
	if !ok || v.Adaptive == nil || v.Adaptive.AuthGeneration != generation || !time.Now().Before(v.Expires) ||
		s.byIP[child.ip].token != "" || s.byKey[child.key] != "" || s.childKeys[child.key] != "" {
		return false
	}
	v.children = append(slices.Clone(v.children), child)
	s.byToken[token], s.childKeys[child.key] = v, token
	s.storePrincipal(v, child.ip, child.id, child.flowLifetime, s.byIP[v.TunnelIP].principal.Tunnels)
	return true
}

func (s *Sessions) forgetChild(v Session, laneID string) (sessionLane, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.byToken[v.Token]
	if !ok {
		return sessionLane{}, false
	}
	for i, child := range current.children {
		if child.id == laneID {
			current.children = slices.Delete(slices.Clone(current.children), i, i+1)
			s.byToken[v.Token] = current
			delete(s.childKeys, child.key)
			delete(s.byIP, child.ip)
			return child, true
		}
	}
	return sessionLane{}, false
}

func (s *Sessions) childKeyInUse(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.childKeys[key] != ""
}

func (s *Sessions) childCount(owner Session) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, v := range s.byToken {
		if v.Method != owner.Method {
			continue
		}
		same := v.Identity == owner.Identity
		if v.Method == "oidc" {
			same = v.OIDCIssuer == owner.OIDCIssuer && v.OIDCSubject == owner.OIDCSubject
		}
		if same {
			n += len(v.children)
		}
	}
	return n
}

// FindWireGuardPublicKey returns the live session using a WireGuard peer.
// A reconnect replaces that session while retaining its tunnel address.
func (s *Sessions) FindWireGuardPublicKey(key string) (Session, bool) {
	if canonical, err := wgnet.CanonicalPublicKey(key); err == nil {
		key = canonical
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.byToken[s.byKey[key]]
	if ok && time.Now().Before(v.Expires) {
		return v, true
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

// principalForIP returns a principal whose grant map is read-only.
func (s *Sessions) principalForIP(ip string) (DataPlanePrincipal, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.byIP[ip]
	if !ok || !time.Now().Before(s.byToken[entry.token].Expires) {
		return DataPlanePrincipal{}, false
	}
	return entry.principal, true
}

func (s *Sessions) Delete(t string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.byToken[t]; ok {
		s.deleteLocked(v)
	}
}

func (s *Sessions) deleteLocked(v Session) {
	delete(s.byToken, v.Token)
	if s.byIP[v.TunnelIP].token == v.Token {
		delete(s.byIP, v.TunnelIP)
	}
	if s.byKey[v.WireGuardPublicKey] == v.Token {
		delete(s.byKey, v.WireGuardPublicKey)
	}
	for _, child := range v.children {
		delete(s.byIP, child.ip)
		delete(s.childKeys, child.key)
	}
}

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
			s.deleteLocked(v)
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
	for _, v := range s.byToken {
		if now.After(v.Expires) {
			dead = append(dead, v)
			s.deleteLocked(v)
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
