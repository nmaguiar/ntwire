package server

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/nmaguiar/nwire/pkg/protocol"
	"sync"
	"time"
)

type Session struct {
	ID, Token, Fingerprint string
	Tunnels                []protocol.Tunnel
	Expires                time.Time
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
func (s *Sessions) Create(fp string, ts []protocol.Tunnel, ttl time.Duration) Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := Session{token(), token(), fp, ts, time.Now().Add(ttl)}
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
