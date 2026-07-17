package server

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"github.com/nmaguiar/nwire/pkg/protocol"
	"github.com/nmaguiar/nwire/pkg/sshkey"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Server struct {
	Config   Config
	sessions *Sessions
	nonces   map[string]time.Time
	mu       sync.Mutex
	log      *slog.Logger
}

func New(c Config, l *slog.Logger) *Server {
	if l == nil {
		l = slog.Default()
	}
	return &Server{Config: c, sessions: NewSessions(), nonces: map[string]time.Time{}, log: l}
}
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /v1/info", s.info)
	m.HandleFunc("POST /v1/auth", s.auth)
	m.HandleFunc("POST /v1/renew", s.renew)
	m.HandleFunc("POST /v1/disconnect", s.disconnect)
	return m
}
func (s *Server) info(w http.ResponseWriter, _ *http.Request) {
	write(w, http.StatusOK, map[string]any{"version": protocol.Version, "capabilities": []string{"ssh-auth", "tcp"}})
}
func (s *Server) auth(w http.ResponseWriter, r *http.Request) {
	var a protocol.AuthRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&a); err != nil {
		fail(w, 400, "invalid request")
		return
	}
	at, err := protocol.ParseTimestamp(a.Timestamp)
	if err != nil || time.Since(at) > 2*time.Minute || time.Until(at) > 2*time.Minute {
		fail(w, 401, "timestamp outside permitted window")
		return
	}
	if !s.useNonce(a.Nonce) {
		fail(w, 401, "replayed nonce")
		return
	}
	key, comment, err := sshkey.ParsePublicString(a.PublicKey)
	if err != nil || !s.authorized(key) {
		fail(w, 401, "unknown public key")
		return
	}
	p, err := protocol.SigningPayload(a)
	if err != nil || sshkey.Verify(key, p, a.Signature) != nil {
		fail(w, 401, "invalid signature")
		return
	}
	fp := sshkey.Fingerprint(key)
	grants := s.grants(fp, comment)
	grants, ttl, err := s.authorize(r, fp, comment, a.Info, grants)
	if err != nil {
		s.log.Warn("authorization denied", "fingerprint", fp, "error", err)
		fail(w, 403, "authorization denied")
		return
	}
	v := make([]protocol.Tunnel, 0, len(grants))
	for _, t := range grants {
		v = append(v, protocol.Tunnel{Name: t.Name, Description: t.Description, VirtualPort: t.VirtualPort, TargetHint: t.Target})
	}
	session := s.sessions.Create(fp, v, ttl)
	s.log.Info("authentication allowed", "fingerprint", fp, "session", session.ID)
	write(w, 200, protocol.AuthResponse{SessionID: session.ID, Token: session.Token, TTLSeconds: int(ttl.Seconds()), Tunnels: v, UDP: s.Config.Network.AdvertisedEndpoint})
}
func (s *Server) renew(w http.ResponseWriter, r *http.Request) {
	t := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	old, ok := s.sessions.Get(t)
	if !ok {
		fail(w, 401, "invalid session")
		return
	}
	var body protocol.RenewRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body) != nil {
		fail(w, 400, "invalid request")
		return
	}
	grants := make([]TunnelConfig, 0)
	for _, p := range old.Tunnels {
		for _, c := range s.Config.Tunnels {
			if c.Name == p.Name {
				grants = append(grants, c)
			}
		}
	}
	grants, ttl, err := s.authorize(r, old.Fingerprint, "", body.Info, grants)
	if err != nil {
		s.sessions.Delete(t)
		fail(w, 403, "authorization denied")
		return
	}
	v := make([]protocol.Tunnel, 0, len(grants))
	for _, g := range grants {
		v = append(v, protocol.Tunnel{Name: g.Name, Description: g.Description, VirtualPort: g.VirtualPort, TargetHint: g.Target})
	}
	s.sessions.Delete(t)
	n := s.sessions.Create(old.Fingerprint, v, ttl)
	write(w, 200, protocol.AuthResponse{SessionID: n.ID, Token: n.Token, TTLSeconds: int(ttl.Seconds()), Tunnels: v, UDP: s.Config.Network.AdvertisedEndpoint})
}
func (s *Server) disconnect(w http.ResponseWriter, r *http.Request) {
	t := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if _, ok := s.sessions.Get(t); !ok {
		fail(w, 401, "invalid session")
		return
	}
	s.sessions.Delete(t)
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) useNonce(n string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n == "" {
		return false
	}
	if _, ok := s.nonces[n]; ok {
		return false
	}
	now := time.Now()
	s.nonces[n] = now
	for k, v := range s.nonces {
		if now.Sub(v) > 5*time.Minute {
			delete(s.nonces, k)
		}
	}
	return true
}
func (s *Server) authorized(k interface{ Marshal() []byte }) bool {
	entries, err := os.ReadDir(s.Config.Auth.AuthorizedKeysDir)
	if err != nil {
		return false
	}
	wanted := sshkey.Digest(k.Marshal())
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, er := os.ReadFile(filepath.Join(s.Config.Auth.AuthorizedKeysDir, e.Name()))
		if er != nil {
			continue
		}
		p, _, er := sshkey.ParsePublic(b)
		if er == nil && subtle.ConstantTimeCompare([]byte(wanted), []byte(sshkey.Digest(p.Marshal()))) == 1 {
			return true
		}
	}
	return false
}
func (s *Server) grants(fp, comment string) []TunnelConfig {
	var out []TunnelConfig
	for _, t := range s.Config.Tunnels {
		for _, a := range t.Allow {
			if a == "*" || a == fp || a == comment {
				out = append(out, t)
				break
			}
		}
	}
	return out
}
func (s *Server) authorize(r *http.Request, fp, comment string, info protocol.ClientInfo, grants []TunnelConfig) ([]TunnelConfig, time.Duration, error) {
	names := make([]string, len(grants))
	for i, g := range grants {
		names[i] = g.Name
	}
	extra := map[string]string{"os": info.OS, "arch": info.Arch, "hostname": info.Hostname, "username": info.Username, "client_version": info.ClientVersion}
	for k, v := range info.Extra {
		extra[k] = v
	}
	result, err := Authorize(r.Context(), s.Config.Authorizer, AuthorizationInput{SourceIP: r.RemoteAddr, KeyFingerprint: fp, KeyComment: comment, ClientInfo: extra, GrantedTunnels: names, RequestedAt: time.Now()})
	if err != nil || !result.Allow {
		return nil, 0, fmt.Errorf("%v", err)
	}
	if result.AllowedTunnels != "*" {
		allowed := map[string]bool{}
		if a, ok := result.AllowedTunnels.([]any); ok {
			for _, x := range a {
				if n, ok := x.(string); ok {
					allowed[n] = true
				}
			}
		}
		f := grants[:0]
		for _, g := range grants {
			if allowed[g.Name] {
				f = append(f, g)
			}
		}
		grants = f
	}
	ttl := s.Config.Auth.SessionTTL
	if result.TTLSeconds > 0 && time.Duration(result.TTLSeconds)*time.Second < ttl {
		ttl = time.Duration(result.TTLSeconds) * time.Second
	}
	return grants, ttl, nil
}

// Reload safely replaces only runtime configuration. Listener and TLS changes
// are intentionally ignored until restart.
func (s *Server) Reload(c Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.Listen = s.Config.Listen
	c.TLS = s.Config.TLS
	c.Network.TunnelCIDR = s.Config.Network.TunnelCIDR
	s.Config = c
	s.log.Info("configuration reloaded")
}
func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, msg string) {
	write(w, status, protocol.Error{Error: msg})
}
