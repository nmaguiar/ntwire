package server

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"github.com/nmaguiar/nwire/pkg/protocol"
	"github.com/nmaguiar/nwire/pkg/sshkey"
	"log/slog"
	"net"
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
	data     *dataPlane
	rates    map[string]*rateState
}

func New(c Config, l *slog.Logger) *Server {
	if l == nil {
		l = slog.Default()
	}
	return &Server{Config: c, sessions: NewSessions(), nonces: map[string]time.Time{}, log: l, rates: map[string]*rateState{}}
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
	if !s.allowSource(r.RemoteAddr) {
		fail(w, http.StatusTooManyRequests, "too many authentication attempts")
		return
	}
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
	if s.Config.Auth.MaxSessionsPerKey > 0 && s.sessions.CountFingerprint(sshkey.Fingerprint(key)) >= s.Config.Auth.MaxSessionsPerKey {
		fail(w, 429, "maximum sessions for key reached")
		return
	}
	p, err := protocol.SigningPayload(a)
	if err != nil || sshkey.Verify(key, p, a.Signature) != nil {
		fail(w, 401, "invalid signature")
		return
	}
	fp := sshkey.Fingerprint(key)
	grants := s.grants(fp, comment)
	grants, ttl, err := s.authorize(r, fp, comment, "", a.Info, grants)
	if err != nil {
		s.log.Warn("authorization denied", "fingerprint", fp, "error", err)
		fail(w, 403, "authorization denied")
		return
	}
	v := make([]protocol.Tunnel, 0, len(grants))
	for _, t := range grants {
		v = append(v, protocol.Tunnel{Name: t.Name, Description: t.Description, VirtualPort: t.VirtualPort, TargetHint: t.Target})
	}
	tunnelIP := ""
	serverKey := ""
	if s.data != nil {
		if a.WireGuardPublicKey == "" {
			fail(w, 400, "wireguard_public_key is required")
			return
		}
		tunnelIP, err = s.allocateIP()
		if err != nil {
			fail(w, 503, err.Error())
			return
		}
		if err = s.addPeer(a.WireGuardPublicKey, tunnelIP); err != nil {
			fail(w, 400, "invalid wireguard key")
			return
		}
		serverKey = s.data.stack.PublicKey()
	}
	session := s.sessions.Create(fp, a.WireGuardPublicKey, tunnelIP, v, ttl)
	s.log.Info("authentication allowed", "fingerprint", fp, "session", session.ID)
	s.audit("auth_allowed", session, "", 0)
	write(w, 200, protocol.AuthResponse{SessionID: session.ID, Token: session.Token, TunnelIP: tunnelIP, ServerPublicKey: serverKey, TTLSeconds: int(ttl.Seconds()), Tunnels: v, UDP: s.Config.Network.AdvertisedEndpoint})
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
	grants, ttl, err := s.authorize(r, old.Fingerprint, "", old.ID, body.Info, grants)
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
	s.dropSession(old)
	n := s.sessions.Create(old.Fingerprint, old.WireGuardPublicKey, old.TunnelIP, v, ttl)
	if old.WireGuardPublicKey != "" {
		_ = s.addPeer(old.WireGuardPublicKey, old.TunnelIP)
	}
	write(w, 200, protocol.AuthResponse{SessionID: n.ID, Token: n.Token, TTLSeconds: int(ttl.Seconds()), Tunnels: v, UDP: s.Config.Network.AdvertisedEndpoint})
}
func (s *Server) disconnect(w http.ResponseWriter, r *http.Request) {
	t := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	old, ok := s.sessions.Get(t)
	if !ok {
		fail(w, 401, "invalid session")
		return
	}
	s.sessions.Delete(t)
	s.dropSession(old)
	s.audit("session_disconnected", old, "", 0)
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
func (s *Server) authorizedFingerprint(fp string) bool {
	entries, err := os.ReadDir(s.Config.Auth.AuthorizedKeysDir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, er := os.ReadFile(filepath.Join(s.Config.Auth.AuthorizedKeysDir, e.Name()))
		if er != nil {
			continue
		}
		p, _, er := sshkey.ParsePublic(b)
		if er == nil && subtle.ConstantTimeCompare([]byte(fp), []byte(sshkey.Fingerprint(p))) == 1 {
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
func (s *Server) authorize(r *http.Request, fp, comment, sessionID string, info protocol.ClientInfo, grants []TunnelConfig) ([]TunnelConfig, time.Duration, error) {
	names := make([]string, len(grants))
	for i, g := range grants {
		names[i] = g.Name
	}
	extra := map[string]string{"os": info.OS, "arch": info.Arch, "hostname": info.Hostname, "username": info.Username, "client_version": info.ClientVersion}
	for k, v := range info.Extra {
		extra[k] = v
	}
	result, err := Authorize(r.Context(), s.Config.Authorizer, AuthorizationInput{SourceIP: r.RemoteAddr, KeyFingerprint: fp, KeyComment: comment, SessionID: sessionID, ClientInfo: extra, GrantedTunnels: names, RequestedAt: time.Now()})
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
	for _, v := range s.sessions.All() {
		if !s.authorizedFingerprint(v.Fingerprint) {
			s.sessions.Delete(v.Token)
			s.dropSession(v)
			continue
		}
		allowed := map[string]bool{}
		for _, g := range s.grants(v.Fingerprint, "") {
			allowed[g.Name] = true
		}
		kept := v.Tunnels[:0]
		for _, t := range v.Tunnels {
			if allowed[t.Name] {
				kept = append(kept, t)
			}
		}
		if len(kept) != len(v.Tunnels) {
			s.sessions.Delete(v.Token)
			s.dropSession(v)
		}
	}
	s.log.Info("configuration reloaded")
}

type rateState struct {
	n     int
	since time.Time
}

func (s *Server) allowSource(remote string) bool {
	host, _, _ := net.SplitHostPort(remote)
	if host == "" {
		host = remote
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.rates[host]
	if v == nil || time.Since(v.since) > time.Minute {
		s.rates[host] = &rateState{n: 1, since: time.Now()}
		return true
	}
	v.n++
	return v.n <= 20
}
func (s *Server) audit(event string, session Session, reason string, risk int) {
	s.log.Info("audit", "event", event, "session_id", session.ID, "fingerprint", session.Fingerprint, "reason", reason, "risk_score", risk)
}
func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, msg string) {
	write(w, status, protocol.Error{Error: msg})
}
