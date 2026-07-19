package server

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"sync"
	"time"
)

type Session struct {
	ID, Token, Fingerprint, WireGuardPublicKey, TunnelIP string
	Tunnels                                              []protocol.Tunnel
	Expires                                              time.Time
}
type Sessions struct {
	mu      sync.Mutex
	byToken map[string]Session
}

func NewSessions() *Sessions { return &Sessions{byToken: map[string]Session{}} }
func token() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func (s *Sessions) Create(fp, wgKey, tunnelIP string, ts []protocol.Tunnel, ttl time.Duration) Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := Session{ID: token(), Token: token(), Fingerprint: fp, WireGuardPublicKey: wgKey, TunnelIP: tunnelIP, Tunnels: ts, Expires: time.Now().Add(ttl)}
	s.byToken[v.Token] = v
	return v
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
func (s *Sessions) CountFingerprint(fp string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	now := time.Now()
	for k, v := range s.byToken {
		if now.After(v.Expires) {
			delete(s.byToken, k)
			continue
		}
		if v.Fingerprint == fp {
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
