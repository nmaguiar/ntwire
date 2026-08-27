package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"github.com/nmaguiar/ntwire/pkg/oidcauth"
	"github.com/nmaguiar/ntwire/pkg/pac"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/socks"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Server struct {
	Config   Config
	sessions *Sessions
	nonces   map[string]time.Time
	mu       sync.Mutex
	// operationMu serializes control-plane operations that combine config,
	// authorization, session allocation, and data-plane peer ownership.
	// Sessions has its own map lock, but that alone cannot make a reload and a
	// concurrent renewal atomic as a policy decision.
	operationMu     sync.Mutex
	log             *slog.Logger
	data            *dataPlane
	rates           map[string]*rateState
	tunnelStats     sync.Map // map[string]*serverTunnelStats, keyed by tunnel IP and name
	oidc            *oidcauth.Verifiers
	tlsManager      *TLSManager
	auditLog        *slog.Logger
	lifecycle       *lifecycleCounters
	direct          *directUDP
	udpr            atomic.Pointer[udpRelay]
	nativeRelayMu   sync.Mutex
	nativeRelayStop chan struct{}
	policies        map[string]*compiledPolicy
	asn             *socks.ASNIndex
}

func New(c Config, l *slog.Logger) *Server {
	if l == nil {
		l = slog.Default()
	}
	s := &Server{Config: c, sessions: NewSessions(), nonces: map[string]time.Time{}, log: l, rates: map[string]*rateState{}, lifecycle: newLifecycleCounters(), policies: map[string]*compiledPolicy{}, asn: socks.NewASNIndex()}
	for name, policy := range c.DestinationPolicies {
		if compiled, err := compilePolicy(policy, s.asn); err == nil {
			s.policies[name] = compiled
		}
	}
	if len(c.Auth.OIDC.Issuers) > 0 {
		s.oidc = newVerifiers(c, l)
	}
	s.logSecurityCapabilities(c)
	return s
}

// SetTLSManager attaches the TLS certificate manager whose Config() the
// caller is serving with, so a later Reload picks up a cert/key file change
// (e.g. a renewed certificate) without restarting the listener.
func (s *Server) SetTLSManager(m *TLSManager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tlsManager = m
}

// SetAuditLog attaches the logger audit() uses instead of the main log,
// e.g. one built over logging.NewMultiHandler so an audit event still
// reaches the main log while also landing in a dedicated audit sink. A nil
// logger (the default) makes audit() fall back to the main log alone.
func (s *Server) SetAuditLog(l *slog.Logger) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditLog = l
}
func newVerifiers(c Config, l *slog.Logger) *oidcauth.Verifiers {
	cfgs := make([]oidcauth.IssuerConfig, 0, len(c.Auth.OIDC.Issuers))
	for _, iss := range c.Auth.OIDC.Issuers {
		cfgs = append(cfgs, oidcauth.IssuerConfig{Name: iss.Name, Issuer: iss.Issuer, ClientID: iss.ClientID, GroupsClaim: iss.GroupsClaim, RequireVerifiedEmail: iss.RequireVerified()})
	}
	return oidcauth.NewVerifiers(cfgs, l)
}
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /v1/info", s.info)
	m.HandleFunc("POST /v1/auth", s.auth)
	m.HandleFunc("POST /v1/auth/oidc", s.authOIDC)
	m.HandleFunc("POST /v1/renew", s.renew)
	m.HandleFunc("POST /v1/disconnect", s.disconnect)
	m.HandleFunc("GET /v1/wg", s.websocket)
	m.HandleFunc("POST /v1/punch", s.punch)
	m.HandleFunc("POST /v1/transport/direct", s.registerDirectTransport)
	m.HandleFunc("POST /v1/udp-relay", s.udpRelayHandler)
	m.HandleFunc("POST /v1/masque/certificate", s.masqueCertificate)
	m.HandleFunc("GET /v1/portal", s.portalHandler)
	m.HandleFunc("POST /v1/portal/action", s.portalActionHandler)
	m.HandleFunc("GET /proxy.pac", func(w http.ResponseWriter, r *http.Request) {
		s.servePAC(w, r, "", false)
	})
	m.HandleFunc("GET /proxy-ios.pac", func(w http.ResponseWriter, r *http.Request) {
		s.servePAC(w, r, "", true)
	})
	m.HandleFunc("GET /proxy.ios.pac", func(w http.ResponseWriter, r *http.Request) {
		s.servePAC(w, r, "", true)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path != "/proxy.pac" && r.URL.Path != "/proxy-ios.pac" && r.URL.Path != "/proxy.ios.pac" && strings.HasPrefix(r.URL.Path, "/proxy") && strings.HasSuffix(r.URL.Path, ".pac") {
			s.handleNamedPAC(w, r)
			return
		}
		m.ServeHTTP(w, r)
	})
}

// ServerTunnelIP returns the server's netstack IPv4 address within network.tunnel_cidr.
func (s *Server) ServerTunnelIP() string {
	s.mu.Lock()
	cidr := s.Config.Network.TunnelCIDR
	s.mu.Unlock()
	if cidr == "" {
		cidr = "100.64.0.0/16"
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "100.64.0.1"
	}
	return prefix.Addr().Next().String()
}

func (s *Server) socksTunnels() []TunnelConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []TunnelConfig
	for _, t := range s.Config.Tunnels {
		if t.IsSocks() {
			out = append(out, t)
		}
	}
	return out
}

func (s *Server) findSocksTunnel(name string) (TunnelConfig, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.Config.Tunnels {
		if t.IsSocks() && t.Name == name {
			return t, true
		}
	}
	return TunnelConfig{}, false
}

// SocksTargets returns protocol descriptor objects for all configured SOCKS egress tunnels.
func (s *Server) SocksTargets() []protocol.SocksTarget {
	s.mu.Lock()
	defer s.mu.Unlock()
	tunnelIP := s.ServerTunnelIP()
	var out []protocol.SocksTarget
	for _, t := range s.Config.Tunnels {
		if t.IsSocks() {
			st := protocol.SocksTarget{
				Name:        t.Name,
				LocalPort:   t.LocalPort,
				VirtualPort: t.VirtualPort,
				TunnelIP:    tunnelIP,
			}
			if t.Socks != nil {
				st.DomainFilters = append([]string(nil), t.Socks.DomainFilters...)
				st.Filters = append([]string(nil), t.Socks.Filters...)
			}
			out = append(out, st)
		}
	}
	return out
}

func (s *Server) handleNamedPAC(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if !strings.HasSuffix(path, ".pac") {
		http.NotFound(w, r)
		return
	}
	raw := strings.TrimSuffix(path, ".pac")
	var name string
	isIOS := false
	if strings.HasPrefix(raw, "/proxy-ios-") {
		isIOS = true
		name = strings.TrimPrefix(raw, "/proxy-ios-")
	} else if strings.HasPrefix(raw, "/proxy.ios-") {
		isIOS = true
		name = strings.TrimPrefix(raw, "/proxy.ios-")
	} else if strings.HasPrefix(raw, "/proxy-") {
		name = strings.TrimPrefix(raw, "/proxy-")
	} else {
		http.NotFound(w, r)
		return
	}

	if name == "" {
		http.NotFound(w, r)
		return
	}
	s.servePAC(w, r, name, isIOS)
}

func (s *Server) servePAC(w http.ResponseWriter, r *http.Request, targetName string, isIOS bool) {
	if !isIOS && (r.URL.Query().Has("ios") || r.URL.Query().Get("platform") == "ios") {
		isIOS = true
	}
	platform := "desktop"
	if isIOS {
		platform = "ios"
	}
	s.observe("pac_served", platform)

	socksTunnels := s.socksTunnels()
	if len(socksTunnels) == 0 {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("no socks egress tunnels configured\n"))
		return
	}

	var target TunnelConfig
	if targetName == "" {
		target = socksTunnels[0]
	} else {
		found, ok := s.findSocksTunnel(targetName)
		if !ok {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprintf(w, "socks target %q not found\n", targetName)
			return
		}
		target = found
	}

	var host string
	var port int
	if isIOS {
		host = s.ServerTunnelIP()
		port = target.VirtualPort
		if port <= 0 {
			port = target.LocalPort
		}
	} else {
		host = "127.0.0.1"
		port = target.LocalPort
		if port <= 0 {
			port = target.VirtualPort
		}
	}
	if port <= 0 {
		port = 10080
	}

	var domainFilters []string
	var ipFilters []string
	if target.Socks != nil {
		domainFilters = target.Socks.DomainFilters
		ipFilters = target.Socks.Filters
	}

	pacScript := pac.Generate(host, port, domainFilters, ipFilters)
	w.Header().Set("Content-Type", pac.ContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(pacScript))
}

func (s *Server) dashboardAllowed(r *http.Request) bool {
	s.mu.Lock()
	token := s.Config.Admin.WebUIToken
	s.mu.Unlock()
	return token != "" && subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("token")), []byte(token)) == 1
}

type dashboardTunnelStats struct {
	BytesToTarget   uint64 `json:"bytes_to_target"`
	BytesFromTarget uint64 `json:"bytes_from_target"`
	Connections     uint64 `json:"connections"`
	Active          int64  `json:"active_connections"`
}

type dashboardTunnel struct {
	SessionID     string               `json:"session_id"`
	Name          string               `json:"name"`
	Description   string               `json:"description"`
	Target        string               `json:"target"`
	VirtualPort   int                  `json:"virtual_port"`
	Identity      string               `json:"identity"`
	Method        string               `json:"method"`
	TunnelIP      string               `json:"tunnel_ip"`
	Expires       time.Time            `json:"expires"`
	LatencyMillis uint64               `json:"latency_millis"`
	Reconnections uint64               `json:"reconnections"`
	Stats         dashboardTunnelStats `json:"stats"`
	// RelayUDP is present only when this session has a live UDP-relay
	// allocation and the relay has sent a diagnostic counter report. It is a
	// token-free hop summary; see relayUDPStatsSummary.
	RelayUDP  *relayUDPStatsSummary `json:"relay_udp,omitempty"`
	PACURL    string                `json:"pac_url,omitempty"`
	PACURLiOS string                `json:"pac_url_ios,omitempty"`
}

func (s *Server) dashboardStatus(w http.ResponseWriter, r *http.Request) {
	if !s.dashboardAllowed(r) {
		http.NotFound(w, r)
		return
	}
	sessions := s.sessions.All()
	out := make([]dashboardTunnel, 0)
	for _, session := range sessions {
		for _, tunnel := range session.Tunnels {
			config, ok := s.tunnelConfig(tunnel.Name)
			if !ok {
				continue
			}
			dt := dashboardTunnel{SessionID: session.ID, Name: tunnel.Name, Description: config.Description, Target: config.Target, VirtualPort: tunnel.VirtualPort, Identity: session.Identity, Method: session.Method, TunnelIP: session.TunnelIP, Expires: session.Expires, LatencyMillis: session.LatencyMillis, Reconnections: session.Reconnections, Stats: s.statsFor(session.TunnelIP, tunnel.Name).snapshot()}
			if relayStats, ok := s.udpRelayStatsFor(session.WireGuardPublicKey); ok {
				dt.RelayUDP = &relayStats
			}
			if config.IsSocks() {
				dt.PACURL = pac.PathForPlatform(tunnel.Name, false)
				dt.PACURLiOS = pac.PathForPlatform(tunnel.Name, true)
			}
			out = append(out, dt)
		}
	}
	var pacURLs []string
	socksT := s.socksTunnels()
	if len(socksT) > 0 {
		pacURLs = append(pacURLs, pac.PathForPlatform("", false), pac.PathForPlatform("", true))
		if len(socksT) > 1 {
			for _, st := range socksT {
				pacURLs = append(pacURLs, pac.PathForPlatform(st.Name, false), pac.PathForPlatform(st.Name, true))
			}
		}
	}
	write(w, http.StatusOK, struct {
		Sessions             int               `json:"sessions"`
		Tunnels              []dashboardTunnel `json:"tunnels"`
		SecurityCapabilities []string          `json:"security_capabilities"`
		PACURLs              []string          `json:"pac_urls,omitempty"`
	}{Sessions: len(sessions), Tunnels: out, SecurityCapabilities: s.SecurityCapabilities(), PACURLs: pacURLs})
}

func (s *Server) tunnelConfig(name string) (TunnelConfig, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, tunnel := range s.Config.Tunnels {
		if tunnel.Name == name {
			return tunnel, true
		}
	}
	return TunnelConfig{}, false
}

type serverTunnelStats struct {
	toTarget, fromTarget, connections atomic.Uint64
	active                            atomic.Int64
}

func (v *serverTunnelStats) snapshot() dashboardTunnelStats {
	return dashboardTunnelStats{BytesToTarget: v.toTarget.Load(), BytesFromTarget: v.fromTarget.Load(), Connections: v.connections.Load(), Active: v.active.Load()}
}
func statsKey(ip, name string) string { return ip + "\x00" + name }
func (s *Server) statsFor(ip, name string) *serverTunnelStats {
	v, _ := s.tunnelStats.LoadOrStore(statsKey(ip, name), &serverTunnelStats{})
	return v.(*serverTunnelStats)
}
func (s *Server) info(w http.ResponseWriter, _ *http.Request) {
	caps := []string{"tcp"}
	if s.Config.Relay.Enabled {
		caps = append(caps, "multipath")
	}
	var issuers []protocol.OIDCIssuerInfo
	if s.Config.Auth.AuthorizedKeysDir != "" {
		caps = append(caps, "ssh-auth")
	}
	if len(s.Config.Auth.OIDC.Issuers) > 0 {
		caps = append(caps, "oidc-auth")
		for _, iss := range s.Config.Auth.OIDC.Issuers {
			issuers = append(issuers, protocol.OIDCIssuerInfo{Name: iss.Name, Issuer: iss.Issuer, ClientID: iss.ClientID, Scopes: iss.Scopes, GroupsClaim: iss.GroupsClaim})
		}
	}
	info := protocol.InfoResponse{Version: protocol.Version, Capabilities: caps, OIDCIssuers: issuers}
	if s.Config.MASQUE.Enabled {
		info.Capabilities = append(info.Capabilities, protocol.CapabilityMASQUERelayV1)
		info.MASQUE = &protocol.MASQUEInfo{HTTP2URL: s.Config.MASQUE.HTTP2URL, HTTP3URL: s.Config.MASQUE.HTTP3URL, MatchDomains: append([]string(nil), s.Config.MASQUE.MatchDomains...)}
	}
	write(w, http.StatusOK, info)
}

// transportCapabilitiesAvailable describes transport features this server can
// actually negotiate now. It intentionally depends on the live data plane,
// not just relay.enabled, so a required capability fails during authentication
// instead of producing a session that later fails in the data plane.
func (s *Server) transportCapabilitiesAvailable() []string {
	if s.Config.MultipathEnabled() && s.data != nil && s.data.multipath != nil {
		// Payload-progress acknowledgements (multipath-v3) are not advertised
		// until they are safe on the WebSocket fallback data plane. Negotiation
		// is fail-closed: clients retain v1/v2 and path-MTU support, but cannot
		// enable v3 merely because they implement it.
		return []string{protocol.CapabilityMultipathV1, protocol.CapabilityMultipathV2, protocol.CapabilityPathMTUV1}
	}
	return nil
}
func (s *Server) auth(w http.ResponseWriter, r *http.Request) {
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	succeeded := false
	defer func() {
		if !succeeded {
			s.observe("authentication_failed", "ssh")
			s.auditLifecycle("authentication_failed", "ssh", "rejected")
		}
	}()
	if !s.allowSource(r.RemoteAddr) {
		fail(w, http.StatusTooManyRequests, protocol.ErrorRateLimited, "too many authentication attempts")
		return
	}
	var a protocol.AuthRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&a); err != nil {
		fail(w, 400, protocol.ErrorInvalidRequest, "invalid request")
		return
	}
	// SSH authentication used to omit this check even though OIDC and relay
	// registration enforce it. Reject an incompatible signed envelope before
	// nonce use or authorization, rather than failing later unpredictably.
	if a.Version != protocol.Version {
		fail(w, 400, protocol.ErrorInvalidRequest, "unsupported protocol version")
		return
	}
	if err := protocol.ValidateRequiredCapabilities(s.transportCapabilitiesAvailable(), a.RequiredTransportCapabilities); err != nil {
		fail(w, http.StatusBadRequest, protocol.ErrorUnsupportedCapability, err.Error())
		return
	}
	at, err := protocol.ParseTimestamp(a.Timestamp)
	if err != nil || time.Since(at) > 2*time.Minute || time.Until(at) > 2*time.Minute {
		fail(w, 401, protocol.ErrorClockSkew, "timestamp outside permitted window")
		return
	}
	if !s.useNonce(a.Nonce) {
		fail(w, 401, protocol.ErrorReplayedNonce, "replayed nonce")
		return
	}
	key, comment, err := sshkey.ParsePublicString(a.PublicKey)
	if err != nil || !s.authorized(key) {
		fail(w, 401, protocol.ErrorUnknownKey, "unknown public key")
		return
	}
	p, err := protocol.SigningPayload(a)
	if err != nil || sshkey.Verify(key, p, a.Signature) != nil {
		fail(w, 401, protocol.ErrorBadSignature, "invalid signature")
		return
	}
	fp := sshkey.Fingerprint(key)
	grants := s.grants(grantSubject{Method: "ssh", Fingerprint: fp, Comment: comment})
	succeeded = s.establishSession(w, r, sessionRequest{
		Method: "ssh", Identity: fp, Fingerprint: fp, Comment: comment,
		WireGuardPublicKey: a.WireGuardPublicKey, Info: a.Info, TransportCapabilities: a.TransportCapabilities, QueryOnly: a.QueryOnly,
	}, grants)
}

// authOIDC authenticates with a verified ID token in place of an SSH
// signature. There is no nonce cache: the ID token's own exp/iat bound
// replay, and allowSource rate-limits repeated attempts per source IP.
func (s *Server) authOIDC(w http.ResponseWriter, r *http.Request) {
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	succeeded := false
	defer func() {
		if !succeeded {
			s.observe("authentication_failed", "oidc")
			s.auditLifecycle("authentication_failed", "oidc", "rejected")
		}
	}()
	if !s.allowSource(r.RemoteAddr) {
		fail(w, http.StatusTooManyRequests, protocol.ErrorRateLimited, "too many authentication attempts")
		return
	}
	var a protocol.OIDCAuthRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&a); err != nil {
		fail(w, 400, protocol.ErrorInvalidRequest, "invalid request")
		return
	}
	if a.Version != protocol.Version {
		fail(w, 400, protocol.ErrorInvalidRequest, "unsupported protocol version")
		return
	}
	if err := protocol.ValidateRequiredCapabilities(s.transportCapabilitiesAvailable(), a.RequiredTransportCapabilities); err != nil {
		fail(w, http.StatusBadRequest, protocol.ErrorUnsupportedCapability, err.Error())
		return
	}
	at, err := protocol.ParseTimestamp(a.Timestamp)
	if err != nil || time.Since(at) > 2*time.Minute || time.Until(at) > 2*time.Minute {
		fail(w, 401, protocol.ErrorClockSkew, "timestamp outside permitted window")
		return
	}
	s.mu.Lock()
	verifiers := s.oidc
	s.mu.Unlock()
	if verifiers == nil {
		fail(w, 400, protocol.ErrorInvalidRequest, "oidc authentication is not configured")
		return
	}
	identity, err := verifiers.Verify(r.Context(), a.IssuerName, a.IDToken)
	if err != nil {
		s.log.Warn("oidc verification failed", "event", "authentication_failed", "method", "oidc", "reason_category", "invalid_token")
		fail(w, 401, protocol.ErrorOIDCInvalidToken, "invalid id token")
		return
	}
	grants := s.grants(grantSubject{Method: "oidc", Email: identity.Email, Domain: identity.Domain, Groups: identity.Groups})
	succeeded = s.establishSession(w, r, sessionRequest{
		Method: "oidc", Identity: identity.Email, Issuer: identity.IssuerName, Groups: identity.Groups,
		WireGuardPublicKey: a.WireGuardPublicKey, Info: a.Info, TransportCapabilities: a.TransportCapabilities, QueryOnly: a.QueryOnly,
	}, grants)
}

// sessionRequest carries the method-specific fields establishSession needs
// once a request has already been authenticated (SSH signature verified, or
// OIDC ID token verified).
type sessionRequest struct {
	Method                string
	Identity              string
	Fingerprint           string   // ssh only
	Comment               string   // ssh only
	Issuer                string   // oidc only
	Groups                []string // oidc only
	WireGuardPublicKey    string
	Info                  protocol.ClientInfo
	TransportCapabilities []string
	// QueryOnly: see protocol.AuthRequest.QueryOnly.
	QueryOnly bool
}

// establishSession is the common tail shared by SSH and OIDC authentication:
// session cap check, authorizer hook, IP allocation, WireGuard peer add, and
// session creation. A QueryOnly request stops after the authorizer hook and
// returns just the allowed tunnel list, so a caller that only wants to look
// (e.g. `ntwire list`) never occupies a max_sessions_per_key slot or a
// WireGuard peer/IP.
func (s *Server) establishSession(w http.ResponseWriter, r *http.Request, req sessionRequest, grants []TunnelConfig) bool {
	if !req.QueryOnly && s.Config.Auth.MaxSessionsPerKey > 0 && s.sessions.CountIdentity(req.Method, req.Identity) >= s.Config.Auth.MaxSessionsPerKey {
		fail(w, 429, protocol.ErrorMaxSessions, "maximum sessions for key reached")
		return false
	}
	grants, ttl, err := s.authorize(r, authContext{
		Method: req.Method, Identity: req.Identity, Fingerprint: req.Fingerprint, Comment: req.Comment,
		Issuer: req.Issuer, Groups: req.Groups,
	}, req.Info, grants)
	if err != nil {
		s.observe("authorization_denied", req.Method)
		// Authorizer errors may originate outside ntwire (and can therefore
		// signal while logging only a stable category.
		s.log.Warn("authorization denied", "event", "authorization_denied", "method", req.Method, "reason_category", "authorization_failed")
		fail(w, 403, protocol.ErrorNotAllowed, "authorization denied")
		return false
	}
	v := make([]protocol.Tunnel, 0, len(grants))
	for _, t := range grants {
		v = append(v, protocol.Tunnel{Name: t.Name, Description: t.Description, VirtualPort: t.VirtualPort, Protocol: t.Protocol, UDPIdleTimeout: t.UDPIdleTimeout, LocalPort: t.LocalPort, LocalHost: t.LocalHost, TargetHint: t.Target,
			Instructions: t.Instructions, DocsURL: t.DocsURL})
	}
	if req.QueryOnly {
		s.observe("authentication_success", req.Method)
		s.log.Info("query-only authentication allowed", "method", req.Method, "identity", req.Identity)
		write(w, 200, protocol.AuthResponse{Tunnels: v, Identity: req.Identity, Method: req.Method, PortalEnabled: s.Config.Portal.Enabled})
		return true
	}
	tunnelIP := ""
	serverKey := ""
	serverTunnelIP := ""
	if s.data != nil {
		if req.WireGuardPublicKey == "" {
			fail(w, 400, protocol.ErrorInvalidRequest, "wireguard_public_key is required")
			return false
		}
		if old, ok := s.sessions.FindWireGuardPublicKey(req.WireGuardPublicKey); ok {
			tunnelIP = old.TunnelIP
			s.sessions.Delete(old.Token)
		} else {
			tunnelIP, err = s.allocateIP()
			if err != nil {
				fail(w, 503, protocol.ErrorNoCapacity, err.Error())
				return false
			}
		}
		if err = s.addPeer(req.WireGuardPublicKey, tunnelIP); err != nil {
			fail(w, 400, protocol.ErrorInvalidWireGuardKey, "invalid wireguard key")
			return false
		}
		serverKey = s.data.stack.PublicKey()
		serverTunnelIP = s.data.serverIP.String()
	}
	negotiatedTransport := protocol.IntersectCapabilities(req.TransportCapabilities, s.transportCapabilitiesAvailable())
	multipathV1 := protocol.HasCapability(negotiatedTransport, protocol.CapabilityMultipathV1)
	multipathV2 := protocol.HasCapability(negotiatedTransport, protocol.CapabilityMultipathV2)
	multipathV3 := multipathV2 && protocol.HasCapability(negotiatedTransport, protocol.CapabilityMultipathV3)
	pathMTU := protocol.HasCapability(negotiatedTransport, protocol.CapabilityPathMTUV1)
	multipath := multipathV1
	multipathV2 = multipath && multipathV2
	multipathV3 = multipathV2 && multipathV3
	pathMTU = multipath && pathMTU
	session := s.sessions.Create(CreateParams{
		Method: req.Method, Identity: req.Identity, Fingerprint: req.Fingerprint, Issuer: req.Issuer, Groups: req.Groups,
		WireGuardPublicKey: req.WireGuardPublicKey, TunnelIP: tunnelIP, Tunnels: v, TTL: ttl,
		LatencyMillis: req.Info.LatencyMillis, Reconnections: req.Info.Reconnections,
		Multipath: multipath, MultipathV2: multipathV2, MultipathV3: multipathV3, PathMTU: pathMTU,
	})
	s.log.Info("authentication allowed", "method", session.Method, "identity", session.Identity, "session", session.ID)
	s.log.Debug("session established", "session", session.ID, "wireguard_public_key", req.WireGuardPublicKey, "tunnel_ip", tunnelIP, "tunnels", tunnelNames(v), "ttl_seconds", int(ttl.Seconds()))
	s.observe("authentication_success", session.Method)
	s.observe("session_created", session.Method)
	s.audit("auth_allowed", session, "", 0)
	write(w, 200, protocol.AuthResponse{SessionID: session.ID, Token: session.Token, TunnelIP: tunnelIP, ServerTunnelIP: serverTunnelIP, ServerPublicKey: serverKey, TTLSeconds: int(ttl.Seconds()), Tunnels: v, UDP: s.advertisedUDPEndpoint(), WebSocket: websocketURL(r), Identity: session.Identity, Method: session.Method, ServerName: s.Config.Listen.Name, PortalEnabled: s.Config.Portal.Enabled, Multipath: multipath, TransportCapabilities: transportCapabilities(multipath, multipathV2, multipathV3, pathMTU)})
	return true
}

// transportCapabilities echoes back which multipath capability this session
// actually negotiated -- multipathV2 is only ever true alongside multipath
// (see establishSession), so it's always sent together with
// CapabilityMultipathV1, never alone.
func transportCapabilities(multipath, multipathV2, multipathV3, pathMTU bool) []string {
	if !multipath {
		return nil
	}
	if multipathV3 && pathMTU {
		return []string{protocol.CapabilityMultipathV1, protocol.CapabilityMultipathV2, protocol.CapabilityMultipathV3, protocol.CapabilityPathMTUV1}
	}
	if multipathV3 {
		return []string{protocol.CapabilityMultipathV1, protocol.CapabilityMultipathV2, protocol.CapabilityMultipathV3}
	}
	if multipathV2 && pathMTU {
		return []string{protocol.CapabilityMultipathV1, protocol.CapabilityMultipathV2, protocol.CapabilityPathMTUV1}
	}
	if multipathV2 {
		return []string{protocol.CapabilityMultipathV1, protocol.CapabilityMultipathV2}
	}
	if pathMTU {
		return []string{protocol.CapabilityMultipathV1, protocol.CapabilityPathMTUV1}
	}
	return []string{protocol.CapabilityMultipathV1}
}

// tunnelNames extracts the tunnel names granted in a session, for compact
// debug-level logging (the full protocol.Tunnel slice is verbose).
func tunnelNames(v []protocol.Tunnel) []string {
	names := make([]string, len(v))
	for i, t := range v {
		names[i] = t.Name
	}
	return names
}
func websocketURL(r *http.Request) string {
	scheme := "wss"
	if r.TLS == nil {
		scheme = "ws"
	}
	return (&url.URL{Scheme: scheme, Host: r.Host, Path: "/v1/wg"}).String()
}

// advertisedUDPEndpoint resolves network.advertised_endpoint's host to a
// literal IP. It is sent to clients as AuthResponse.UDP and, on the client,
// passed straight into wireguard-go's "endpoint=" UAPI line (see
// wgnet.Stack.AddPeer), which is parsed with netip.ParseAddr and never does
// DNS resolution itself -- a hostname there fails with an opaque IPC error
// instead of connecting. Resolved on every call rather than once at startup
// so dynamic DNS (e.g. a home server behind a changing IP) stays usable
// across reconnects without a server restart.
func (s *Server) advertisedUDPEndpoint() string {
	hostport := s.Config.Network.AdvertisedEndpoint
	if hostport == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		s.log.Warn("network.advertised_endpoint is not a valid host:port", "value", hostport, "error", err)
		return ""
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return hostport // already a literal IP; skip the DNS round trip
	}
	ips, err := net.DefaultResolver.LookupIPAddr(context.Background(), host)
	if err != nil || len(ips) == 0 {
		s.log.Warn("failed to resolve network.advertised_endpoint", "host", host, "error", err)
		return ""
	}
	ip := ips[0].IP
	for _, addr := range ips {
		if v4 := addr.IP.To4(); v4 != nil {
			ip = v4
			break
		}
	}
	return net.JoinHostPort(ip.String(), port)
}
func (s *Server) websocket(w http.ResponseWriter, r *http.Request) {
	if s.data == nil || s.data.ws == nil {
		http.Error(w, "data plane unavailable", http.StatusServiceUnavailable)
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	v, ok := s.sessions.Get(token)
	if !ok {
		s.log.Debug("WebSocket fallback rejected: invalid session")
		http.Error(w, "invalid session", http.StatusUnauthorized)
		return
	}
	// Keyed by WireGuardPublicKey, not session ID: the key is stable across a
	// renewal (which mints a new session ID) so the fallback connection the
	// client opened once at Connect time keeps working after renewal instead
	// of being torn down (see dropSession / renew).
	s.log.Debug("WebSocket fallback connected", "session", v.ID, "wireguard_public_key", v.WireGuardPublicKey)
	if err := s.data.ws.WebSocket.ServeHTTP(w, r, v.WireGuardPublicKey); err != nil {
		s.log.Warn("WebSocket fallback rejected", "error", err)
	}
}

// punch answers the opportunistic direct-UDP upgrade's candidate exchange
// (see directudp.go). It always requires a valid session, even on a caller's
// first, addr-less request that only wants RelayReflectAddr: an
// unauthenticated caller has no business learning either the server's own
// NAT-mapped candidate or the relay's reflector address.
func (s *Server) punch(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	sess, ok := s.sessions.Get(token)
	if !ok {
		fail(w, 401, protocol.ErrorInvalidRequest, "invalid session")
		return
	}
	s.mu.Lock()
	d := s.direct
	s.mu.Unlock()
	if d == nil {
		http.Error(w, "direct-connection upgrade not available", http.StatusNotFound)
		return
	}
	var body protocol.PunchRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body) != nil {
		fail(w, 400, protocol.ErrorInvalidRequest, "invalid request")
		return
	}
	if body.ClientAddr != "" {
		if addr, err := netip.ParseAddrPort(body.ClientAddr); err == nil {
			go d.primeClient(addr.String())
			if s.data != nil && s.data.multipath != nil && sess.Multipath && s.data.ws != nil {
				if ep, err := s.data.ws.UDP.ParseEndpoint(addr.String()); err == nil {
					s.data.multipath.RegisterPath(sess.WireGuardPublicKey, "direct-udp", wstransport.PathDirect, ep, sess.MultipathV2, sess.MultipathV3, sess.PathMTU)
				}
			}
		}
	}
	candidate := protocol.DirectCandidate{ServerAddr: d.selfCandidate(), RelayReflectAddr: d.relayReflect}
	// Preserve scalar fields for clients that predate relay pools while making
	// the pairing explicit for newer clients. RelayPool can later publish more
	// than one matching mapping without another wire-format change.
	write(w, 200, protocol.PunchResponse{ServerAddr: candidate.ServerAddr, RelayReflectAddr: candidate.RelayReflectAddr, Candidates: []protocol.DirectCandidate{candidate}})
}

// registerDirectTransport associates an authenticated client's reflected UDP
// source address with its stable server-side multipath peer. This makes the
// direct and WSS candidates usable in both directions for ordinary servers;
// relay-mode direct upgrades keep using /v1/punch as before.
func (s *Server) registerDirectTransport(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	sess, ok := s.sessions.Get(token)
	if !ok {
		fail(w, 401, protocol.ErrorInvalidRequest, "invalid session")
		return
	}
	if !sess.Multipath || s.data == nil || s.data.multipath == nil || s.data.ws == nil {
		http.Error(w, "multipath transport is not active", http.StatusConflict)
		return
	}
	var body protocol.TransportPathRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body) != nil {
		fail(w, 400, protocol.ErrorInvalidRequest, "invalid request")
		return
	}
	if _, err := netip.ParseAddrPort(body.Address); err != nil {
		fail(w, 400, protocol.ErrorInvalidRequest, "invalid UDP address")
		return
	}
	ep, err := s.data.ws.UDP.ParseEndpoint(body.Address)
	if err != nil {
		fail(w, 400, protocol.ErrorInvalidRequest, "invalid UDP address")
		return
	}
	if !s.data.multipath.RegisterPath(sess.WireGuardPublicKey, "direct-udp", wstransport.PathDirect, ep, sess.MultipathV2, sess.MultipathV3, sess.PathMTU) {
		http.Error(w, "UDP address is already registered to another session", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// udpRelayHandler answers a client's request for a session on the relay's
// UDP-relay forwarding tier (see pkg/server/udprelay.go) -- the middle rung
// between the WebSocket fallback and the full direct-UDP escape /v1/punch
// answers. Like punch, it always requires a valid session: an
// unauthenticated caller has no business obtaining a forwarding session. A
// 404 (tier not available, or this server isn't relaying at all) is the
// expected steady state when relay.enabled is false or the relay hasn't
// enabled listen.udp_relay -- postUDPRelay on the client side treats it
// exactly like a 404 from /v1/punch, not an error worth logging.
func (s *Server) udpRelayHandler(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	sess, ok := s.sessions.Get(token)
	if !ok {
		fail(w, 401, protocol.ErrorInvalidRequest, "invalid session")
		return
	}
	u := s.udpr.Load()
	if u == nil || sess.WireGuardPublicKey == "" {
		http.Error(w, "udp relay tier not available", http.StatusNotFound)
		return
	}
	// A malformed or empty body just means no client-observed stats this
	// call -- the same "missing telemetry is normal" tolerance every other
	// best-effort counter in this codebase gets, not a request error.
	var body protocol.UDPRelayRequest
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body)
	write(w, 200, u.sessionFor(r.Context(), sess.WireGuardPublicKey, sess.Multipath, sess.MultipathV2, sess.MultipathV3, sess.PathMTU, body.Stats))
}

func (s *Server) renew(w http.ResponseWriter, r *http.Request) {
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	t := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	old, ok := s.sessions.Get(t)
	if !ok {
		fail(w, 401, protocol.ErrorInvalidRequest, "invalid session")
		return
	}
	var body protocol.RenewRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body) != nil {
		fail(w, 400, protocol.ErrorInvalidRequest, "invalid request")
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
	grants, ttl, err := s.authorize(r, authContext{
		Method: old.Method, Identity: old.Identity, Fingerprint: old.Fingerprint, Issuer: old.Issuer, Groups: old.Groups, SessionID: old.ID,
	}, body.Info, grants)
	if err != nil {
		s.sessions.Delete(t)
		s.dropSession(old)
		s.observe("authorization_denied", old.Method)
		s.audit("authorization_denied", old, "renewal authorization denied", 0)
		fail(w, 403, protocol.ErrorNotAllowed, "authorization denied")
		return
	}
	v := make([]protocol.Tunnel, 0, len(grants))
	for _, g := range grants {
		v = append(v, protocol.Tunnel{Name: g.Name, Description: g.Description, VirtualPort: g.VirtualPort, Protocol: g.Protocol, UDPIdleTimeout: g.UDPIdleTimeout, LocalPort: g.LocalPort, LocalHost: g.LocalHost, TargetHint: g.Target,
			Instructions: g.Instructions, DocsURL: g.DocsURL})
	}
	s.sessions.Delete(t)
	// Deliberately not dropSession here: WireGuardPublicKey and TunnelIP carry
	// over unchanged into the renewed session below, and both the WireGuard
	// device peer and the WebSocket fallback connection are keyed by that
	// public key (not the session ID/token that just changed), so they stay
	// valid across renewal without being torn down and reopened.
	n := s.sessions.Create(CreateParams{
		Method: old.Method, Identity: old.Identity, Fingerprint: old.Fingerprint, Issuer: old.Issuer, Groups: old.Groups,
		WireGuardPublicKey: old.WireGuardPublicKey, TunnelIP: old.TunnelIP, Tunnels: v, TTL: ttl,
		LatencyMillis: body.Info.LatencyMillis, Reconnections: body.Info.Reconnections,
		Multipath: old.Multipath, MultipathV2: old.MultipathV2, MultipathV3: old.MultipathV3, PathMTU: old.PathMTU,
	})
	if old.WireGuardPublicKey != "" {
		_ = s.addPeer(old.WireGuardPublicKey, old.TunnelIP)
	}
	s.log.Debug("session renewed", "old_session", old.ID, "session", n.ID, "identity", n.Identity, "tunnels", tunnelNames(v), "ttl_seconds", int(ttl.Seconds()))
	s.observe("session_renewed", n.Method)
	s.audit("session_renewed", n, "", 0)
	write(w, 200, protocol.AuthResponse{SessionID: n.ID, Token: n.Token, TTLSeconds: int(ttl.Seconds()), Tunnels: v, UDP: s.advertisedUDPEndpoint(), Identity: n.Identity, Method: n.Method, ServerName: s.Config.Listen.Name, PortalEnabled: s.Config.Portal.Enabled, Multipath: n.Multipath, TransportCapabilities: transportCapabilities(n.Multipath, n.MultipathV2, n.MultipathV3, n.PathMTU)})
}
func (s *Server) disconnect(w http.ResponseWriter, r *http.Request) {
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	t := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	old, ok := s.sessions.Get(t)
	if !ok {
		fail(w, 401, protocol.ErrorInvalidRequest, "invalid session")
		return
	}
	s.sessions.Delete(t)
	s.dropSession(old)
	s.log.Debug("session disconnected", "session", old.ID, "identity", old.Identity)
	s.observe("session_disconnected", old.Method)
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

// grantSubject is the principal a tunnel's allow list is matched against.
// Matching stays scoped to Method so an SSH key comment can never be
// confused for an OIDC email, and vice versa (see docs/PROTOCOL.md).
type grantSubject struct {
	Method      string // "ssh" or "oidc"
	Fingerprint string
	Comment     string
	Email       string
	Domain      string // includes the leading "@"
	Groups      []string
}

func matchesAllow(sub grantSubject, entry string) bool {
	if entry == "*" {
		return true
	}
	switch sub.Method {
	case "ssh":
		return entry == sub.Fingerprint || (sub.Comment != "" && entry == sub.Comment)
	case "oidc":
		if entry == sub.Email || (sub.Domain != "" && entry == sub.Domain) {
			return true
		}
		if group, ok := strings.CutPrefix(entry, "group:"); ok {
			for _, g := range sub.Groups {
				if g == group {
					return true
				}
			}
		}
	}
	return false
}

func (s *Server) grants(sub grantSubject) []TunnelConfig {
	var out []TunnelConfig
	for _, t := range s.Config.Tunnels {
		for _, a := range t.Allow {
			if matchesAllow(sub, a) {
				out = append(out, t)
				break
			}
		}
	}
	return out
}

// authContext carries the identity fields authorize() forwards to the
// authorizer hook; method-specific fields are zero for the other method.
type authContext struct {
	Method      string
	Identity    string
	Fingerprint string
	Comment     string
	Issuer      string
	Groups      []string
	SessionID   string
}

func (s *Server) authorize(r *http.Request, ac authContext, info protocol.ClientInfo, grants []TunnelConfig) ([]TunnelConfig, time.Duration, error) {
	names := make([]string, len(grants))
	for i, g := range grants {
		names[i] = g.Name
	}
	extra := map[string]string{"os": info.OS, "arch": info.Arch, "hostname": info.Hostname, "username": info.Username, "client_version": info.ClientVersion}
	for k, v := range info.Extra {
		extra[k] = v
	}
	result, err := Authorize(r.Context(), s.Config.Authorizer, AuthorizationInput{
		SourceIP: r.RemoteAddr, KeyFingerprint: ac.Fingerprint, KeyComment: ac.Comment,
		AuthMethod: ac.Method, Identity: ac.Identity, Issuer: ac.Issuer, Groups: ac.Groups,
		SessionID: ac.SessionID, ClientInfo: extra, GrantedTunnels: names, RequestedAt: time.Now(),
	})
	if err != nil {
		if s.Config.Authorizer.WebhookURL != "" || s.Config.Authorizer.Exec != "" {
			s.observe("authorization_hook_denied", ac.Method)
			s.auditLifecycle("authorization_hook_denied", ac.Method, "hook_error")
			s.log.Warn("authorization hook denied request", "event", "authorization_hook_denied", "method", ac.Method, "reason_category", "hook_error")
		}
		return nil, 0, err
	}
	if !result.Allow {
		if s.Config.Authorizer.WebhookURL != "" || s.Config.Authorizer.Exec != "" {
			s.observe("authorization_hook_denied", ac.Method)
			s.auditLifecycle("authorization_hook_denied", ac.Method, "hook_denied")
			s.log.Info("authorization hook denied request", "event", "authorization_hook_denied", "method", ac.Method, "reason_category", "hook_denied")
		}
		return nil, 0, fmt.Errorf("authorizer denied")
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

// Reload safely replaces runtime configuration. Tunnel additions, removals,
// and target/virtual_port changes take effect immediately by recycling the
// affected data-plane listeners, and an explicit TLS cert_file/key_file pair
// is re-read from disk so a renewed certificate is served without a
// restart. Listener address, cert_file/key_file *paths*, tunnel-CIDR, and
// relay changes are intentionally ignored until restart: relay mode changes
// which net.Listener cmd/ntwire-server passes to ServeTLS, which Handler()
// never sees, so there is nothing here for it to hot-reload.
func (s *Server) Reload(c Config) {
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	c.Listen = s.Config.Listen
	c.TLS = s.Config.TLS
	c.Relay = s.Config.Relay
	c.Network.TunnelCIDR = s.Config.Network.TunnelCIDR
	c.Network.WireGuardPrivateKeyFile = s.Config.Network.WireGuardPrivateKeyFile
	oldNative := s.Config.NativeWireGuard.Peers
	oldNativeEnabled := s.Config.NativeWireGuard.Enabled
	oldIssuers := s.Config.Auth.OIDC.Issuers
	s.Config = c
	s.policies = map[string]*compiledPolicy{}
	for name, policy := range c.DestinationPolicies {
		if compiled, err := compilePolicy(policy, s.asn); err == nil {
			s.policies[name] = compiled
		}
	}
	if !reflect.DeepEqual(oldIssuers, c.Auth.OIDC.Issuers) {
		s.oidc = newVerifiers(c, s.log)
	}
	if s.tlsManager != nil {
		if err := s.tlsManager.Reload(); err != nil {
			s.log.Warn("TLS certificate reload failed, keeping previous certificate", "error", err)
		}
	}
	s.reloadTunnels(c.Tunnels)
	if oldNativeEnabled != c.NativeWireGuard.Enabled || !reflect.DeepEqual(oldNative, c.NativeWireGuard.Peers) {
		if !oldNativeEnabled {
			oldNative = nil
		}
		nextNative := c.NativeWireGuard.Peers
		if !c.NativeWireGuard.Enabled {
			nextNative = nil
		}
		s.reconcileNativePeers(oldNative, nextNative)
	}
	validIssuers := map[string]bool{}
	for _, iss := range c.Auth.OIDC.Issuers {
		validIssuers[iss.Name] = true
	}
	for _, v := range s.sessions.All() {
		if v.Method == "oidc" {
			if !validIssuers[v.Issuer] {
				s.sessions.Delete(v.Token)
				s.dropSession(v)
				s.observe("authorization_revoked", v.Method)
				auditRecord(s.auditLog, s.log, "authorization_revoked", v, "issuer removed on configuration reload", 0)
				continue
			}
			allowed := map[string]bool{}
			for _, g := range s.grants(grantSubject{Method: "oidc", Email: v.Identity, Domain: emailDomain(v.Identity), Groups: v.Groups}) {
				allowed[g.Name] = true
			}
			s.reconcileTunnels(v, allowed)
			continue
		}
		if !s.authorizedFingerprint(v.Fingerprint) {
			s.sessions.Delete(v.Token)
			s.dropSession(v)
			s.observe("authorization_revoked", v.Method)
			auditRecord(s.auditLog, s.log, "authorization_revoked", v, "SSH authorization removed on configuration reload", 0)
			continue
		}
		allowed := map[string]bool{}
		for _, g := range s.grants(grantSubject{Method: "ssh", Fingerprint: v.Fingerprint}) {
			allowed[g.Name] = true
		}
		s.reconcileTunnels(v, allowed)
	}
	s.log.Info("lifecycle event", "event", "configuration_reloaded")
	s.observe("configuration_reloaded", "")
	s.logSecurityCapabilities(c)
}

func (s *Server) reconcileTunnels(v Session, allowed map[string]bool) {
	kept := make([]protocol.Tunnel, 0, len(v.Tunnels))
	for _, t := range v.Tunnels {
		if allowed[t.Name] {
			kept = append(kept, t)
		}
	}
	if len(kept) != len(v.Tunnels) {
		s.sessions.Delete(v.Token)
		s.dropSession(v)
		s.observe("tunnel_grant_revoked", v.Method)
		auditRecord(s.auditLog, s.log, "tunnel_grant_revoked", v, "tunnel grant changed on configuration reload", 0)
	}
}

func emailDomain(email string) string {
	if i := strings.LastIndex(email, "@"); i >= 0 {
		return email[i:]
	}
	return ""
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
	now := time.Now()
	for k, v := range s.rates {
		if now.Sub(v.since) > time.Minute {
			delete(s.rates, k)
		}
	}
	v := s.rates[host]
	if v == nil || time.Since(v.since) > time.Minute {
		s.rates[host] = &rateState{n: 1, since: time.Now()}
		return true
	}
	v.n++
	return v.n <= 20
}
func (s *Server) audit(event string, session Session, reason string, risk int) {
	s.mu.Lock()
	l := s.auditLog
	s.mu.Unlock()
	auditRecord(l, s.log, event, session, reason, risk)
}

func auditRecord(l, fallback *slog.Logger, event string, session Session, reason string, risk int) {
	if l == nil {
		l = fallback
	}
	l.Info("audit", "event", event, "session_id", session.ID, "method", session.Method, "fingerprint", session.Fingerprint, "reason", reason, "risk_score", risk)
}
func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, code, msg string) {
	write(w, status, protocol.Error{Error: msg, Code: code})
}
