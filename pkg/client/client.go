// Package client implements the HTTPS authentication side of ntwire.
package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nmaguiar/ntwire/pkg/browseropen"
	"github.com/nmaguiar/ntwire/pkg/buildinfo"
	"github.com/nmaguiar/ntwire/pkg/client/webui"
	"github.com/nmaguiar/ntwire/pkg/instructions"
	"github.com/nmaguiar/ntwire/pkg/oidcclient"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	urlpkg "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

type Collector interface {
	Collect() (map[string]string, error)
}
type ExecCollector struct{ Command string }

func BuiltinInfo() protocol.ClientInfo {
	h, _ := os.Hostname()
	u := os.Getenv("USER")
	return protocol.ClientInfo{OS: runtime.GOOS, Arch: runtime.GOARCH, Hostname: h, Username: u, ClientVersion: buildinfo.String(), Extra: map[string]string{}}
}
func (c ExecCollector) Collect() (map[string]string, error) {
	out, err := exec.Command("sh", "-c", c.Command).Output()
	if err != nil {
		return nil, err
	}
	if len(out) > 64<<10 {
		return nil, fmt.Errorf("collector output exceeds 64KiB")
	}
	var v map[string]string
	if err = json.Unmarshal(out, &v); err != nil {
		return nil, fmt.Errorf("collector must emit a JSON object: %w", err)
	}
	for k, x := range v {
		if len(k) > 256 || len(x) > 4096 {
			return nil, fmt.Errorf("collector value too large")
		}
	}
	return v, nil
}
func Authenticate(url, keyPath string, info protocol.ClientInfo) (protocol.AuthResponse, error) {
	return AuthenticateWithOptions(url, keyPath, info, Options{})
}

// Options controls the client-side TLS and connection lifecycle.
type Options struct {
	Ports            map[string]int
	CAFile           string
	Insecure         bool
	KnownServersFile string
	NoWebUI          bool
	StatusFile       string
	UseWebSocket     bool

	// NoDirectUpgrade disables the opportunistic upgrade ladder
	// (directupgrade.go) that a WebSocket-fallback session otherwise
	// attempts in the background -- both the UDP-relay forwarding rung and
	// the full direct-UDP escape above it. It has no effect when
	// UseWebSocket is false to begin with (already the best available
	// path).
	NoDirectUpgrade bool
	// DirectUpgradeTiming overrides the direct-UDP upgrade's pacing. Leave
	// nil for the production defaults; see DirectUpgradeTiming's doc.
	DirectUpgradeTiming *DirectUpgradeTiming

	// BindAddress is the local IP address tunnel listeners bind to. Empty
	// (the default) means 127.0.0.1: tunneled targets are reachable only
	// from this host. Setting it to another address (a LAN IP, or 0.0.0.0
	// for every interface) makes those targets reachable from other hosts
	// on that network -- there is no additional access control at the
	// listener, so this is an advanced, opt-in escape hatch, not a default
	// any profile should carry silently. Must be a numeric IP address; a
	// hostname is rejected rather than resolved.
	BindAddress string

	// KeyPassphrase decrypts an encrypted SSH private key at KeyPath. Callers
	// resolve it up front (e.g. an interactive prompt) since it must survive
	// into background reconnect, which cannot prompt.
	KeyPassphrase string

	// SSO forces OIDC authentication even when an SSH key is available.
	// Without it, an SSH key (found or given via -i) is preferred; SSO is
	// only the default when no key is available and the server advertises
	// oidc-auth.
	SSO bool
	// Provider selects an oidc issuer by name; required only when the
	// server advertises more than one.
	Provider string
	// NoBrowser skips opening the system browser for SSO login (falling
	// back to the OAuth device flow) in addition to its existing meaning of
	// not opening the local status UI.
	NoBrowser bool
	// TokenCacheFile overrides ~/.ntwire/tokens.json.
	TokenCacheFile string
	Logger         *slog.Logger

	// QueryOnly asks the server for the caller's allowed tunnels without
	// establishing a tunnel session: no WireGuard keypair is generated and
	// no session is created server-side, so repeated calls (e.g. `ntwire
	// list`) never occupy a max_sessions_per_key slot.
	QueryOnly bool

	// OnEvent, when non-nil, is called from the connection's background
	// renewal goroutine on control-plane lifecycle transitions (see Event).
	// It is the only push-style hook into a Connection's state; callers that
	// don't need push updates can poll Status instead.
	//
	// It is called synchronously from that goroutine, so it must not block
	// and must not call back into this Connection (Status, DisplayName,
	// ReplacePort, Close all take the same lock the caller may be holding
	// indirectly) -- do no more than a non-blocking send on a buffered
	// channel or an atomic update. It is never called from Close.
	OnEvent func(Event)
}

// EventKind identifies which control-plane lifecycle transition an Event
// describes.
type EventKind int

const (
	// EventReconnecting fires once, when a scheduled renewal first fails and
	// the connection begins retrying with backoff.
	EventReconnecting EventKind = iota
	// EventReconnectFailed fires for each retry attempt after the first,
	// while still reconnecting.
	EventReconnectFailed
	// EventReconnected fires when a connection recovers after at least one
	// failed renewal attempt.
	EventReconnected
	// EventRenewed fires on every successful renewal, including the routine
	// case where the very first attempt in a cycle succeeds.
	EventRenewed
)

// Event describes one control-plane lifecycle transition, delivered via
// Options.OnEvent.
type Event struct {
	Kind EventKind
	// Err is set for EventReconnecting and EventReconnectFailed.
	Err error
	// RetryIn is set for EventReconnecting and EventReconnectFailed.
	RetryIn time.Duration
	// TTLSeconds is set for EventRenewed.
	TTLSeconds int
}

func (c *Connection) fireEvent(e Event) {
	if c.options.OnEvent != nil {
		c.options.OnEvent(e)
	}
}

// UnknownCertificateError is returned for a server that has not yet been
// pinned in known_servers. Call TrustServer and retry after user confirmation.
type UnknownCertificateError struct{ Host, Fingerprint, Previous string }

func (e *UnknownCertificateError) Error() string {
	return fmt.Sprintf("unknown server certificate for %s (%s)", e.Host, e.Fingerprint)
}

// AuthError preserves a server's additive machine-readable code while still
// being useful with older servers that only return an HTTP status/body.
type AuthError struct{ Status, Code, Message string }

func (e *AuthError) Error() string {
	switch e.Code {
	case protocol.ErrorUnknownKey:
		if e.Message != "" {
			return "the server does not recognize your SSH key; ask the admin to add your .pub key to authorized_keys_dir, or use --sso"
		}
	case protocol.ErrorClockSkew:
		return "your computer's clock differs from the server's by more than 2 minutes"
	case protocol.ErrorNotAllowed:
		return "authentication succeeded but this identity is not allowed by the server"
	case protocol.ErrorRateLimited:
		return "too many authentication attempts; wait a minute and try again"
	}
	if e.Message != "" {
		return "authentication failed: " + e.Message
	}
	return "authentication failed: " + e.Status
}
func decodeAuthError(resp *http.Response, keyPath, keyPassphrase string) error {
	var body protocol.Error
	_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body)
	e := &AuthError{Status: resp.Status, Code: body.Code, Message: body.Error}
	if e.Code == protocol.ErrorUnknownKey && keyPath != "" {
		if k, err := sshkey.PublicFromPrivateWithPassphrase(keyPath, []byte(keyPassphrase)); err == nil {
			e.Message = fmt.Sprintf("the server does not recognize your key (%s); ask the admin to add %s.pub to authorized_keys_dir, or use --sso", k, keyPath)
		}
	}
	return e
}

func defaultKnownServersFile() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(h, ".ntwire", "known_servers")
}

type knownServers struct {
	Servers map[string]string `yaml:"servers"`
}

func TrustServer(path, host, fingerprint string) error {
	if path == "" {
		path = defaultKnownServersFile()
	}
	if path == "" {
		return fmt.Errorf("cannot determine known_servers path")
	}
	v := knownServers{Servers: map[string]string{}}
	if b, err := os.ReadFile(path); err == nil {
		_ = yaml.Unmarshal(b, &v)
	}
	if v.Servers == nil {
		v.Servers = map[string]string{}
	}
	v.Servers[host] = fingerprint
	b, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

func httpClient(url string, o Options) (*http.Client, error) {
	if !strings.HasPrefix(strings.ToLower(url), "https://") {
		return resilientHTTPClient(nil), nil
	}
	if o.Insecure {
		return resilientHTTPClient(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}), nil
	} // #nosec G402 -- explicit CLI escape hatch
	if o.CAFile != "" {
		b, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("no certificate found in %s", o.CAFile)
		}
		return resilientHTTPClient(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}), nil
	}
	path := o.KnownServersFile
	if path == "" {
		path = defaultKnownServersFile()
	}
	v := knownServers{Servers: map[string]string{}}
	if b, err := os.ReadFile(path); err == nil {
		_ = yaml.Unmarshal(b, &v)
	}
	host := strings.TrimPrefix(strings.SplitN(url, "/", 4)[2], "")
	return resilientHTTPClient(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, VerifyConnection: func(cs tls.ConnectionState) error { // #nosec G402 -- verification is the pin below
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("server supplied no certificate")
		}
		s := sha256.Sum256(cs.PeerCertificates[0].Raw)
		fp := "SHA256:" + base64.RawStdEncoding.EncodeToString(s[:])
		if v.Servers[host] != fp {
			return &UnknownCertificateError{Host: host, Fingerprint: fp, Previous: v.Servers[host]}
		}
		return nil
	}}), nil
}

// resilientHTTPClient races resolved addresses for a shared relay hostname.
// A normal net.Dialer retries same-family DNS answers serially, which leaves
// a client stuck behind one failed relay replica. The hostname and TLS SNI
// remain unchanged; only the TCP address selection becomes pool-aware.
func resilientHTTPClient(tlsConfig *tls.Config) *http.Client {
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: tlsConfig, DialContext: raceResolvedDial}
	return &http.Client{Transport: transport}
}

func raceResolvedDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) != nil {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) < 2 {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	type result struct {
		conn net.Conn
		err  error
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan result, len(addrs))
	for i, ip := range addrs {
		go func(i int, ip net.IP) {
			if i > 0 {
				t := time.NewTimer(time.Duration(i) * 150 * time.Millisecond)
				defer t.Stop()
				select {
				case <-child.Done():
					results <- result{err: child.Err()}
					return
				case <-t.C:
				}
			}
			conn, dialErr := (&net.Dialer{}).DialContext(child, network, net.JoinHostPort(ip.String(), port))
			results <- result{conn: conn, err: dialErr}
		}(i, ip.IP)
	}
	var first error
	for range addrs {
		select {
		case r := <-results:
			if r.err == nil {
				return r.conn, nil
			}
			if first == nil && !errors.Is(r.err, context.Canceled) {
				first = r.err
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if first == nil {
		first = fmt.Errorf("all resolved addresses for %s failed", host)
	}
	return nil, first
}

func AuthenticateWithOptions(url, keyPath string, info protocol.ClientInfo, options Options) (protocol.AuthResponse, error) {
	var err error
	url, err = NormalizeServerURL(url)
	if err != nil {
		return protocol.AuthResponse{}, err
	}
	wgPublic := ""
	if !options.QueryOnly {
		k, err := wgnet.GenerateKey()
		if err != nil {
			return protocol.AuthResponse{}, err
		}
		wgPublic = k.Public
	}
	h, err := httpClient(url, options)
	if err != nil {
		return protocol.AuthResponse{}, err
	}
	res, err := authenticateAny(h, url, keyPath, info, wgPublic, options, "", "")
	return res.response, err
}

// NormalizeServerURL accepts host[:port] and applies HTTPS's standard port
// when no port is supplied. Paths and non-HTTP schemes are deliberately not
// accepted because ntwire owns the control-plane path.
func NormalizeServerURL(raw string) (string, error) {
	v := strings.TrimSpace(strings.TrimRight(raw, "/"))
	if v == "" {
		return "", fmt.Errorf("server URL is required")
	}
	if !strings.Contains(v, "://") {
		v = "https://" + v
	}
	u, err := urlpkg.Parse(v)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid server URL %q", raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("server URL scheme must be http or https")
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("server URL must not include a path")
	}
	u.Path, u.RawQuery, u.Fragment = "", "", ""
	return strings.TrimRight(u.String(), "/"), nil
}

// authResult remembers which method (and, for OIDC, which issuer) a session
// was established with, so reconnect can redo the same choice deterministically
// instead of re-deciding (and potentially picking a different issuer).
type authResult struct {
	response protocol.AuthResponse
	method   string // "ssh" or "oidc"
	issuer   string // oidc only
}

func fetchInfo(h *http.Client, base string) (protocol.InfoResponse, error) {
	resp, err := h.Get(base + "/v1/info")
	if err != nil {
		return protocol.InfoResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return protocol.InfoResponse{}, fmt.Errorf("fetching server info: %s", resp.Status)
	}
	var out protocol.InfoResponse
	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}

func selectIssuer(info protocol.InfoResponse, name string) (protocol.OIDCIssuerInfo, error) {
	if len(info.OIDCIssuers) == 0 {
		return protocol.OIDCIssuerInfo{}, fmt.Errorf("server does not advertise any SSO issuers")
	}
	if name != "" {
		for _, iss := range info.OIDCIssuers {
			if iss.Name == name {
				return iss, nil
			}
		}
		return protocol.OIDCIssuerInfo{}, fmt.Errorf("server does not advertise SSO issuer %q", name)
	}
	if len(info.OIDCIssuers) == 1 {
		return info.OIDCIssuers[0], nil
	}
	names := make([]string, len(info.OIDCIssuers))
	for i, iss := range info.OIDCIssuers {
		names[i] = iss.Name
	}
	return protocol.OIDCIssuerInfo{}, fmt.Errorf("server advertises multiple SSO issuers %v; select one with --provider", names)
}

// decideMethod picks SSH or OIDC when neither was pinned by a prior
// authentication on this connection. An SSH key (found or given via -i) is
// preferred; SSO is only the default when no key is available.
func decideMethod(o Options, keyPath string, info protocol.InfoResponse) (method string, issuer protocol.OIDCIssuerInfo, err error) {
	if o.SSO {
		iss, err := selectIssuer(info, o.Provider)
		return "oidc", iss, err
	}
	if keyPath != "" {
		return "ssh", protocol.OIDCIssuerInfo{}, nil
	}
	if len(info.OIDCIssuers) > 0 {
		iss, err := selectIssuer(info, o.Provider)
		return "oidc", iss, err
	}
	return "", protocol.OIDCIssuerInfo{}, fmt.Errorf("no SSH private key available and the server does not support SSO")
}

// authenticateAny authenticates by SSH or OIDC. When pinnedMethod is "ssh" it
// skips the /v1/info round trip entirely, keeping the common SSH path at its
// original cost; pinnedMethod/pinnedIssuer let reconnect redo the exact
// method a session started with instead of re-deciding.
func authenticateAny(h *http.Client, base, keyPath string, info protocol.ClientInfo, wgPublic string, o Options, pinnedMethod, pinnedIssuer string) (authResult, error) {
	if pinnedMethod == "ssh" {
		if o.Logger != nil {
			o.Logger.Debug("authenticating", "method", "ssh")
		}
		r, err := authenticateSSH(h, base, keyPath, info, wgPublic, o)
		return authResult{response: r, method: "ssh"}, err
	}
	serverInfo, err := fetchInfo(h, base)
	if err != nil {
		return authResult{}, err
	}
	method, issuerName := pinnedMethod, pinnedIssuer
	if method == "" {
		m, iss, err := decideMethod(o, keyPath, serverInfo)
		if err != nil {
			return authResult{}, err
		}
		method, issuerName = m, iss.Name
	}
	if o.Logger != nil {
		o.Logger.Debug("authenticating", "method", method, "issuer", issuerName)
	}
	switch method {
	case "ssh":
		r, err := authenticateSSH(h, base, keyPath, info, wgPublic, o)
		return authResult{response: r, method: "ssh"}, err
	case "oidc":
		iss, err := selectIssuer(serverInfo, issuerName)
		if err != nil {
			return authResult{}, err
		}
		r, err := authenticateOIDC(h, base, iss, info, wgPublic, o)
		return authResult{response: r, method: "oidc", issuer: iss.Name}, err
	default:
		return authResult{}, fmt.Errorf("unknown authentication method %q", method)
	}
}

func authenticateOIDC(h *http.Client, base string, issuer protocol.OIDCIssuerInfo, info protocol.ClientInfo, wgPublic string, o Options) (protocol.AuthResponse, error) {
	cache, err := oidcclient.OpenCache(o.TokenCacheFile)
	if err != nil {
		return protocol.AuthResponse{}, err
	}
	tok, err := oidcclient.TokensForIssuer(context.Background(), cache, base, issuer, oidcclient.ForIssuerOptions{NoBrowser: o.NoBrowser})
	if err != nil {
		return protocol.AuthResponse{}, fmt.Errorf("sso login: %w", err)
	}
	r := protocol.OIDCAuthRequest{
		Version: protocol.Version, IssuerName: issuer.Name, IDToken: tok.IDToken,
		WireGuardPublicKey: wgPublic, Timestamp: time.Now().UTC().Format(time.RFC3339), Info: info,
		QueryOnly: o.QueryOnly,
	}
	b, _ := json.Marshal(r)
	resp, err := h.Post(base+"/v1/auth/oidc", "application/json", bytes.NewReader(b))
	if err != nil {
		return protocol.AuthResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return protocol.AuthResponse{}, decodeAuthError(resp, "", "")
	}
	var out protocol.AuthResponse
	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}

// Logout clears any cached SSO tokens for serverURL, so the next
// authentication reopens the browser (or device flow) instead of silently
// refreshing.
func Logout(tokenCacheFile, serverURL string) error {
	var err error
	serverURL, err = NormalizeServerURL(serverURL)
	if err != nil {
		return err
	}
	cache, err := oidcclient.OpenCache(tokenCacheFile)
	if err != nil {
		return err
	}
	return cache.DeleteServer(serverURL)
}

func authenticateSSH(h *http.Client, url, keyPath string, info protocol.ClientInfo, wgPublic string, o Options) (protocol.AuthResponse, error) {
	pub, err := sshkey.PublicFromPrivateWithPassphrase(keyPath, []byte(o.KeyPassphrase))
	if err != nil {
		return protocol.AuthResponse{}, err
	}
	n := make([]byte, 32)
	if _, err = rand.Read(n); err != nil {
		return protocol.AuthResponse{}, err
	}
	r := protocol.AuthRequest{Version: protocol.Version, PublicKey: pub, WireGuardPublicKey: wgPublic, Timestamp: time.Now().UTC().Format(time.RFC3339), Nonce: base64.RawURLEncoding.EncodeToString(n), Info: info, QueryOnly: o.QueryOnly}
	p, err := protocol.SigningPayload(r)
	if err != nil {
		return protocol.AuthResponse{}, err
	}
	r.Signature, err = sshkey.SignFileWithPassphrase(keyPath, p, []byte(o.KeyPassphrase))
	if err != nil {
		return protocol.AuthResponse{}, err
	}
	b, _ := json.Marshal(r)
	resp, err := h.Post(strings.TrimRight(url, "/")+"/v1/auth", "application/json", bytes.NewReader(b))
	if err != nil {
		return protocol.AuthResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return protocol.AuthResponse{}, decodeAuthError(resp, keyPath, o.KeyPassphrase)
	}
	var out protocol.AuthResponse
	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}

// Connection is a persistent, local-listener view of one WireGuard session.
type Connection struct {
	Response       protocol.AuthResponse
	Stack          *wgnet.Stack
	tunnels        []*localTunnel
	LocalAddresses []string
	token, base    string
	mu             sync.Mutex
	info           protocol.ClientInfo
	http           *http.Client
	ports          map[string]int
	stop           chan struct{}
	ui             *http.Server
	UIURL          string
	statusFile     string
	keyPath        string
	bindAddr       string // resolved from options.BindAddress; see resolveBindAddress
	options        Options
	method, issuer string // remembers how this session authenticated, for reconnect
	log            *slog.Logger
	reconnections  atomic.Uint64
	latencyMillis  atomic.Uint64
	transport      atomic.Uint32
	// transportReason explains why the initial transport isn't direct UDP
	// (see selectTransport); empty when it is. Surfaced by TransportReason
	// so the connect CLI can tell the user why, not just that.
	transportReason string

	// hybrid and serverTunnelIP are set only in WebSocket-fallback mode; see
	// directupgrade.go's opportunistic direct-UDP upgrade. upgradeTiming is
	// resolved once at connect time and never mutated after, so
	// directUpgradeLoop's goroutine can read it without locking.
	hybrid         *wstransport.Hybrid
	serverTunnelIP netip.Addr
	upgradeTiming  directUpgradeTiming
}

type connectionTransport uint32

const (
	transportUnknown connectionTransport = iota
	transportUDPDirect
	transportWSSFallback
	transportWSSRelay
	// transportUDPRelay is the middle rung of the relay upgrade ladder (see
	// directupgrade.go): WireGuard traffic rides UDP forwarded through the
	// relay's UDP-relay tier, rather than WebSocket/TCP -- faster than
	// transportWSSRelay, but unlike transportUDPRelayReflector it never
	// reveals the server's real address, since the relay stays in the data
	// path throughout.
	transportUDPRelay
	transportUDPRelayReflector
)

func (t connectionTransport) String() string {
	switch t {
	case transportUDPDirect:
		return "UDP direct"
	case transportWSSFallback:
		return "WSS fallback"
	case transportWSSRelay:
		return "WSS through relay"
	case transportUDPRelay:
		return "UDP via relay"
	case transportUDPRelayReflector:
		return "UDP direct via relay reflector"
	default:
		return "unknown"
	}
}

func initialTransport(useWS bool, udp string) connectionTransport {
	if !useWS {
		return transportUDPDirect
	}
	if udp == "" {
		return transportWSSRelay
	}
	return transportWSSFallback
}

// ConnectionType reports the current WireGuard data-plane transport in
// human-readable form (e.g. "UDP direct", "WSS through relay"), including any
// opportunistic direct-UDP upgrade directupgrade.go has since completed.
func (c *Connection) ConnectionType() string {
	return connectionTransport(c.transport.Load()).String()
}

// TransportReason explains why the connection did not start on direct UDP,
// or "" if it did. It reflects only the initial choice made in
// ConnectWithOptions -- once connected, directupgrade.go's background loop
// logs its own reasons (at Warn, on the CLI's default log level) if an
// opportunistic upgrade attempt fails or a successful upgrade later reverts.
func (c *Connection) TransportReason() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.transportReason
}

// DisplayName returns the operator-configured listen.name this server
// advertised (protocol.AuthResponse.ServerName), or, when it left that unset,
// the host:port the client connected to. It lets logs, the CLI, and the local
// status UI tell apart several ntwire connections running at once.
func (c *Connection) DisplayName() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.displayName()
}

// displayName is DisplayName without locking c.mu; callers must hold it.
func (c *Connection) displayName() string {
	if c.Response.ServerName != "" {
		return c.Response.ServerName
	}
	if u, err := urlpkg.Parse(c.base); err == nil && u.Host != "" {
		return u.Host
	}
	return c.base
}

// TunnelStats is the traffic observed by a local listener for one tunnel.
// BytesToTunnel flow from the local application to the remote virtual port;
// BytesFromTunnel flow in the opposite direction.
type TunnelStats struct {
	BytesToTunnel   uint64 `json:"bytes_to_tunnel"`
	BytesFromTunnel uint64 `json:"bytes_from_tunnel"`
	Connections     uint64 `json:"connections"`
	Active          int64  `json:"active_connections"`
}

type localTunnel struct {
	name         string
	virtualPort  int
	listener     net.Listener
	localAddr    string
	target       string
	toTunnel     atomic.Uint64
	fromTunnel   atomic.Uint64
	connections  atomic.Uint64
	active       atomic.Int64
	lastDialWarn atomic.Int64
}

type countingWriter struct {
	w       io.Writer
	counter *atomic.Uint64
}

func (w countingWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if n > 0 {
		w.counter.Add(uint64(n))
	}
	return n, err
}

func (t *localTunnel) stats() TunnelStats {
	return TunnelStats{BytesToTunnel: t.toTunnel.Load(), BytesFromTunnel: t.fromTunnel.Load(), Connections: t.connections.Load(), Active: t.active.Load()}
}

// AuthMethod reports the method used for the current authenticated session.
func (c *Connection) AuthMethod() string { c.mu.Lock(); defer c.mu.Unlock(); return c.method }

func Connect(url, keyPath string, info protocol.ClientInfo, ports map[string]int) (*Connection, error) {
	return ConnectWithOptions(url, keyPath, info, Options{Ports: ports})
}

func ConnectWithOptions(url, keyPath string, info protocol.ClientInfo, options Options) (*Connection, error) {
	var err error
	url, err = NormalizeServerURL(url)
	if err != nil {
		return nil, err
	}
	bindAddr, err := resolveBindAddress(options.BindAddress)
	if err != nil {
		return nil, err
	}
	key, err := wgnet.GenerateKey()
	if err != nil {
		return nil, err
	}
	h, err := httpClient(url, options)
	if err != nil {
		return nil, err
	}
	authStart := time.Now()
	auth, err := authenticateAny(h, url, keyPath, info, key.Public, options, "", "")
	if err != nil {
		return nil, err
	}
	r := auth.response
	clientIP, err := netip.ParseAddr(r.TunnelIP)
	if err != nil {
		return nil, fmt.Errorf("server did not return a tunnel IP: %w", err)
	}
	useWS, err := selectTransport(options.UseWebSocket, r.UDP, r.WebSocket)
	if err != nil {
		return nil, err
	}
	stackConfig := wgnet.Config{PrivateKey: key.Private, Addresses: []netip.Addr{clientIP}}
	// hybrid is non-nil only in WebSocket-fallback mode; it is what the
	// opportunistic direct-UDP upgrade (directupgrade.go) uses to
	// self-reflect, prime, and move the peer's endpoint between transports.
	// A direct-UDP session (useWS false) already has the best available
	// path and has nothing to upgrade to.
	var hybrid *wstransport.Hybrid
	if useWS {
		hybrid = wstransport.NewHybridClient(r.WebSocket, h, http.Header{"Authorization": {"Bearer " + r.Token}})
		stackConfig.Bind = hybrid
	}
	st, err := wgnet.New(stackConfig)
	if err != nil {
		return nil, err
	}
	endpoint := r.UDP
	if useWS {
		endpoint = wstransport.WSSentinel
	}
	serverIP, err := resolveServerTunnelIP(r.ServerTunnelIP, clientIP)
	if err != nil {
		st.Close()
		return nil, err
	}
	if err = st.AddPeer(wgnet.Endpoint{PublicKey: r.ServerPublicKey, Address: allowedIPsForFamily(clientIP) + "@" + endpoint}); err != nil {
		st.Close()
		return nil, err
	}
	c := &Connection{
		Response: r, Stack: st, token: r.Token, base: url, info: info, http: h, ports: options.Ports,
		hybrid: hybrid, serverTunnelIP: serverIP, upgradeTiming: resolveDirectUpgradeTiming(options.DirectUpgradeTiming),
		stop: make(chan struct{}), statusFile: options.StatusFile, keyPath: keyPath,
		bindAddr: bindAddr, options: options, method: auth.method, issuer: auth.issuer,
		log: options.Logger,
	}
	c.transport.Store(uint32(initialTransport(useWS, r.UDP)))
	c.latencyMillis.Store(uint64(time.Since(authStart).Milliseconds()))
	if c.log == nil {
		c.log = slog.Default()
	}
	transport := "udp"
	if useWS {
		transport = "websocket"
		// transportReason is left empty when the caller passed --websocket:
		// they already know why. It's only worth surfacing (in the connect
		// CLI's banner, and as Warn-level noise if the background
		// direct-upgrade loop then fails) for the auto-selected case, where
		// the server simply never advertised a UDP endpoint -- the
		// surprising, often-support-question-worthy one.
		if !options.UseWebSocket {
			c.transportReason = "server did not advertise a direct UDP WireGuard endpoint"
		}
	}
	c.log.Debug("control-plane session established", "server", c.DisplayName(), "transport", transport, "reason", c.transportReason, "tunnel_ip", clientIP, "ttl_seconds", r.TTLSeconds)
	if bindAddr != "127.0.0.1" && bindAddr != "::1" {
		c.log.Warn("tunnel listeners are bound beyond loopback; tunneled targets are reachable from other hosts on this address", "bind_address", bindAddr)
	}
	for _, t := range r.Tunnels {
		p, explicitPort := options.Ports[t.Name]
		if !explicitPort {
			p = t.LocalPort
		}
		if p < 0 || p > 65535 {
			c.Close()
			return nil, fmt.Errorf("invalid local port for tunnel %q", t.Name)
		}
		l, e := listenLocal(bindAddr, p, !explicitPort)
		if e != nil {
			c.Close()
			return nil, e
		}
		target := net.JoinHostPort(serverIP.String(), fmt.Sprint(t.VirtualPort))
		lt := &localTunnel{name: t.Name, virtualPort: t.VirtualPort, listener: l, localAddr: l.Addr().String(), target: target}
		c.tunnels = append(c.tunnels, lt)
		c.LocalAddresses = append(c.LocalAddresses, l.Addr().String())
		c.log.Debug("tunnel listener bound", "tunnel", t.Name, "local_address", l.Addr().String(), "target", target)
		go c.forward(lt, l, target)
	}
	go c.renewLoop()
	if hybrid != nil && !options.NoDirectUpgrade {
		go c.directUpgradeLoop()
	}
	c.startWebUI()
	if !options.NoWebUI && c.UIURL != "" {
		if err := browseropen.Open(c.UIURL); err != nil {
			c.log.Warn("could not open browser; open URL manually", "url", c.UIURL, "error", err)
		}
	}
	if err := c.writeCurrentStatus(); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// selectTransport decides whether the WireGuard data plane uses the
// WebSocket fallback instead of UDP. explicit is the caller's --websocket
// flag; udp and websocket are AuthResponse.UDP/WebSocket. A relay-only
// server advertises no UDP endpoint (udp == ""), so this auto-selects
// WebSocket instead of requiring the caller to know that in advance — a
// direct server with a misconfigured empty advertised_endpoint used to
// simply error here; it now silently works over WebSocket instead, which is
// strictly better but is a deliberate behavior change (see PLAN-RELAY.md §F).
func selectTransport(explicit bool, udp, websocket string) (useWS bool, err error) {
	useWS = explicit || (udp == "" && websocket != "")
	if useWS && websocket == "" {
		return false, fmt.Errorf("server did not advertise a WebSocket endpoint")
	}
	if !useWS && udp == "" {
		return false, fmt.Errorf("server did not advertise a WireGuard endpoint")
	}
	return useWS, nil
}

// resolveServerTunnelIP determines the server's own tunnel address. Before
// AuthResponse.ServerTunnelIP existed, the client guessed it by convention
// (server = host .1 of the client's network) — an IPv4-only convention that
// panics for an IPv6 clientIP. The fallback is kept only for an old server
// that predates this field, and only for an IPv4 clientIP.
func resolveServerTunnelIP(serverTunnelIP string, clientIP netip.Addr) (netip.Addr, error) {
	if serverTunnelIP != "" {
		addr, err := netip.ParseAddr(serverTunnelIP)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("server returned an invalid tunnel address %q: %w", serverTunnelIP, err)
		}
		return addr, nil
	}
	if clientIP.Is4() {
		a := clientIP.As4()
		a[3] = 1
		return netip.AddrFrom4(a), nil
	}
	return netip.Addr{}, fmt.Errorf("server did not return its tunnel address; upgrade the server for IPv6 support")
}

// allowedIPsForFamily returns the tunnel's default-route AllowedIPs entry
// for the client's own tunnel address family.
func allowedIPsForFamily(clientIP netip.Addr) string {
	if clientIP.Is6() {
		return "::/0"
	}
	return "0.0.0.0/0"
}

// resolveBindAddress validates Options.BindAddress and applies its default.
// Empty resolves to the loopback-only default, 127.0.0.1. A non-empty value
// must be a numeric IP address -- a hostname is rejected rather than
// resolved, so a typo or a DNS response cannot silently move tunnel
// listeners onto an unexpected interface.
func resolveBindAddress(addr string) (string, error) {
	if addr == "" {
		return "127.0.0.1", nil
	}
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return "", fmt.Errorf("invalid bind address %q: must be a numeric IP address (e.g. 0.0.0.0 or a specific interface IP)", addr)
	}
	return ip.String(), nil
}

// listenLocal prefers port when it is supplied by the server configuration.
// A configured local port is a convenience default, so fall back to an
// ephemeral port on the same bind address when another process already owns
// it. Explicit client port mappings remain strict overrides.
func listenLocal(bindAddr string, port int, fallbackOnInUse bool) (net.Listener, error) {
	l, err := net.Listen("tcp", net.JoinHostPort(bindAddr, fmt.Sprint(port)))
	if err == nil || !fallbackOnInUse || port == 0 || !errors.Is(err, syscall.EADDRINUSE) {
		return l, err
	}
	return net.Listen("tcp", net.JoinHostPort(bindAddr, "0"))
}

// ReplacePort atomically switches a tunnel to a new listener on the
// connection's configured bind address (loopback by default). Existing
// connections continue on the old listener while new connections use the port.
func (c *Connection) ReplacePort(name string, port int) (string, error) {
	if name == "" || port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid tunnel name or local port")
	}
	bindAddr := c.bindAddr
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}
	c.mu.Lock()
	var tunnel *localTunnel
	for _, t := range c.tunnels {
		if t.name == name {
			tunnel = t
			break
		}
	}
	if tunnel == nil || c.Stack == nil {
		c.mu.Unlock()
		return "", fmt.Errorf("unknown or disconnected tunnel %q", name)
	}
	if _, currentPort, err := net.SplitHostPort(tunnel.localAddr); err == nil && currentPort == fmt.Sprint(port) {
		addr := tunnel.localAddr
		c.mu.Unlock()
		return addr, nil
	}
	c.mu.Unlock()

	l, err := net.Listen("tcp", net.JoinHostPort(bindAddr, fmt.Sprint(port)))
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	if c.Stack == nil {
		c.mu.Unlock()
		_ = l.Close()
		return "", fmt.Errorf("connection is closed")
	}
	// Re-check that the tunnel still exists after binding the new port.
	var index = -1
	for i, t := range c.tunnels {
		if t == tunnel {
			index = i
			break
		}
	}
	if index < 0 {
		c.mu.Unlock()
		_ = l.Close()
		return "", fmt.Errorf("unknown tunnel %q", name)
	}
	old := tunnel.listener
	tunnel.listener, tunnel.localAddr = l, l.Addr().String()
	c.LocalAddresses[index] = tunnel.localAddr
	addr := tunnel.localAddr
	c.mu.Unlock()
	_ = old.Close()
	go c.forward(tunnel, l, tunnel.target)
	_ = c.writeCurrentStatus()
	return addr, nil
}

func (c *Connection) writeCurrentStatus() error {
	c.mu.Lock()
	s := Status{PID: os.Getpid(), Server: c.base, Name: c.displayName(), UIURL: c.UIURL, LocalAddresses: append([]string(nil), c.LocalAddresses...)}
	c.mu.Unlock()
	return writeStatus(c.statusFile, s)
}

func (c *Connection) renewLoop() {
	for {
		c.mu.Lock()
		ttl := c.Response.TTLSeconds
		c.mu.Unlock()
		if ttl <= 0 {
			ttl = 60
		}
		d := min(time.Duration(ttl)*time.Second*2/3, 15*time.Second)
		if d < time.Second {
			d = time.Second
		}
		t := time.NewTimer(d)
		select {
		case <-c.stop:
			t.Stop()
			return
		case <-t.C:
		}
		for delay := time.Second; ; delay = min(delay*2, time.Minute) {
			err := c.renew()
			if err != nil {
				err = c.reconnect()
			}
			if err == nil {
				if delay > time.Second {
					c.log.Warn("control-plane connection reconnected", "server", c.DisplayName())
					c.fireEvent(Event{Kind: EventReconnected})
				}
				c.mu.Lock()
				newTTL := c.Response.TTLSeconds
				c.mu.Unlock()
				c.log.Debug("control-plane session renewed", "server", c.DisplayName(), "ttl_seconds", newTTL)
				c.fireEvent(Event{Kind: EventRenewed, TTLSeconds: newTTL})
				break
			}
			if delay == time.Second {
				c.log.Warn("control-plane renewal failed; reconnecting", "server", c.DisplayName(), "retry_in", delay)
				c.fireEvent(Event{Kind: EventReconnecting, Err: err, RetryIn: delay})
			} else {
				c.log.Debug("control-plane reconnect failed", "server", c.DisplayName(), "retry_in", delay)
				c.fireEvent(Event{Kind: EventReconnectFailed, Err: err, RetryIn: delay})
			}
			select {
			case <-c.stop:
				return
			case <-time.After(delay):
			}
		}
	}
}

// reconnect creates a replacement control-plane session while retaining the
// existing WireGuard private key and local listeners. The server therefore
// recognizes the same peer once it is available again.
func (c *Connection) reconnect() error {
	c.mu.Lock()
	if c.Stack == nil {
		c.mu.Unlock()
		return fmt.Errorf("connection is closed")
	}
	public := c.Stack.PublicKey()
	method, issuer := c.method, c.issuer
	c.mu.Unlock()
	info := c.connectionInfo()
	info.Reconnections++
	started := time.Now()
	auth, err := authenticateAny(c.http, c.base, c.keyPath, info, public, c.options, method, issuer)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.Response = auth.response
	c.token = auth.response.Token
	c.method, c.issuer = auth.method, auth.issuer
	c.latencyMillis.Store(uint64(time.Since(started).Milliseconds()))
	c.reconnections.Store(info.Reconnections)
	c.mu.Unlock()
	return nil
}

func (c *Connection) renew() error {
	b, _ := json.Marshal(protocol.RenewRequest{Info: c.connectionInfo()})
	c.mu.Lock()
	token := c.token
	c.mu.Unlock()
	req, err := http.NewRequest(http.MethodPost, c.base+"/v1/renew", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	started := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("session renewal failed: %s", resp.Status)
	}
	var out protocol.AuthResponse
	if err = json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	c.mu.Lock()
	// A renewal reuses the same WireGuard peer and tunnel address, so the
	// server does not repeat the addressing fields in its response. Carry
	// them over instead of letting them be zeroed: Connection.Response is
	// the session view the status UI and instruction templates read from.
	if out.TunnelIP == "" {
		out.TunnelIP = c.Response.TunnelIP
	}
	if out.ServerTunnelIP == "" {
		out.ServerTunnelIP = c.Response.ServerTunnelIP
	}
	if out.ServerPublicKey == "" {
		out.ServerPublicKey = c.Response.ServerPublicKey
	}
	c.Response = out
	c.token = out.Token
	c.latencyMillis.Store(uint64(time.Since(started).Milliseconds()))
	c.mu.Unlock()
	return nil
}

func (c *Connection) connectionInfo() protocol.ClientInfo {
	c.mu.Lock()
	info := c.info
	c.mu.Unlock()
	info.LatencyMillis = c.latencyMillis.Load()
	info.Reconnections = c.reconnections.Load()
	return info
}

func (c *Connection) startWebUI() {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return
	}
	access := base64.RawURLEncoding.EncodeToString(b)
	fsys, err := webui.Files()
	if err != nil {
		return
	}
	mux := http.NewServeMux()
	allowed := func(r *http.Request) bool { return r.URL.Query().Get("token") == access }
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if !allowed(r) {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(c.webStatus())
	})
	mux.HandleFunc("/instructions", func(w http.ResponseWriter, r *http.Request) {
		if !allowed(r) {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(c.webInstructions())
	})
	mux.HandleFunc("/tunnels/", func(w http.ResponseWriter, r *http.Request) {
		if !allowed(r) {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPut {
			w.Header().Set("Allow", http.MethodPut)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/tunnels/")
		if name == "" || strings.Contains(name, "/") {
			http.Error(w, "invalid tunnel name", http.StatusBadRequest)
			return
		}
		var in struct {
			LocalPort int `json:"local_port"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&in); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		address, err := c.ReplacePort(name, in.LocalPort)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"local_address": address})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !allowed(r) {
			http.NotFound(w, r)
			return
		}
		http.FileServer(http.FS(fsys)).ServeHTTP(w, r)
	})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return
	}
	c.ui = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	c.UIURL = "http://" + l.Addr().String() + "/?token=" + access
	go func() { _ = c.ui.Serve(l) }()
}

// WebTunnel is the live status of one tunnel on a running connect process,
// as reported by its local status UI's /status endpoint.
type WebTunnel struct {
	Name         string      `json:"name"`
	VirtualPort  int         `json:"virtual_port"`
	Description  string      `json:"description"`
	LocalAddress string      `json:"local_address"`
	Stats        TunnelStats `json:"stats"`
}

// WebStatus is the JSON reported by a running connect process's local
// status UI (see Connection.webStatus and FetchWebStatus), exported so
// other callers (e.g. the CLI's list/status commands) can decode it.
type WebStatus struct {
	Connected bool   `json:"connected"`
	Server    string `json:"server"`
	// ServerName is Connection.DisplayName(): the operator-configured
	// listen.name, or the host:port connected to when that was left unset.
	// It is what the status UI shows to tell several running clients apart.
	ServerName string `json:"server_name"`
	// ConnectionType describes the live WireGuard data path, for example
	// "UDP direct", "WSS through relay", or "UDP direct via relay reflector".
	ConnectionType string      `json:"connection_type"`
	Tunnels        []WebTunnel `json:"tunnels"`
	TTLSeconds     int         `json:"ttl_seconds"`
	LatencyMillis  uint64      `json:"latency_millis"`
	Reconnections  uint64      `json:"reconnections"`
}

// Status returns a race-free snapshot of this connection's live state -- the
// same value the local status UI serves at GET /status. reconnect and renew
// replace Response and the tunnel list wholesale under c.mu from a
// background goroutine, so reading Response/LocalAddresses/Stack directly
// from any other goroutine is a data race; Status is the safe alternative.
func (c *Connection) Status() WebStatus { return c.webStatus() }

func (c *Connection) webStatus() WebStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	granted := c.grantedByName()
	tunnels := make([]WebTunnel, 0, len(c.tunnels))
	for _, t := range c.tunnels {
		wt := WebTunnel{Name: t.name, VirtualPort: t.virtualPort, LocalAddress: t.localAddr, Stats: t.stats()}
		wt.Description = granted[t.name].Description
		tunnels = append(tunnels, wt)
	}
	return WebStatus{Connected: c.Stack != nil, Server: c.base, ServerName: c.displayName(), ConnectionType: connectionTransport(c.transport.Load()).String(), Tunnels: tunnels, TTLSeconds: c.Response.TTLSeconds, LatencyMillis: c.latencyMillis.Load(), Reconnections: c.reconnections.Load()}
}

// grantedByName indexes the tunnels the server granted this session by name.
// Local listeners keep the order they were created in while c.Response is
// replaced wholesale on every renew, so the two slices must not be paired by
// position: a renew that drops or reorders a grant would otherwise attach one
// tunnel's description -- or its setup instructions, and the port inside them
// -- to a different tunnel. Callers must hold c.mu.
func (c *Connection) grantedByName() map[string]protocol.Tunnel {
	m := make(map[string]protocol.Tunnel, len(c.Response.Tunnels))
	for _, t := range c.Response.Tunnels {
		m[t.Name] = t
	}
	return m
}

// WebInstructions is the rendered setup guidance for one tunnel, as reported
// by a running connect process's local status UI. It is served separately from
// WebStatus because it is static for the lifetime of a local listener, while
// WebStatus is polled every few seconds and is also decoded by the CLI.
type WebInstructions struct {
	Name string `json:"name"`
	// DocsURL is the server-supplied "see more" link, when it is a usable
	// absolute http(s) URL.
	DocsURL string `json:"docs_url,omitempty"`
	// Blocks is the tunnel's Markdown instructions, templated against this
	// client's live values and parsed into renderable blocks.
	Blocks []instructions.Block `json:"blocks,omitempty"`
}

// WebInstructionsList is the payload of the local status UI's /instructions
// endpoint: one entry per tunnel that has instructions or a docs link.
type WebInstructionsList struct {
	Tunnels []WebInstructions `json:"tunnels"`
}

// Instructions returns this connection's rendered per-tunnel setup
// guidance, the same value the local status UI serves at GET /instructions.
func (c *Connection) Instructions() WebInstructionsList { return c.webInstructions() }

// DashboardURL returns this connection's local status UI address, with its
// access token embedded -- the same URL Options.NoBrowser (or NoWebUI's
// sibling, not auto-opening it) would otherwise leave the caller to find
// some other way. startWebUI sets it once, synchronously, before
// ConnectWithOptions returns, and nothing mutates it afterward; it is read
// under c.mu anyway for consistency with Status/Instructions rather than
// relying on that invariant holding forever.
func (c *Connection) DashboardURL() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.UIURL
}

func (c *Connection) webInstructions() WebInstructionsList {
	c.mu.Lock()
	defer c.mu.Unlock()
	granted := c.grantedByName()
	out := WebInstructionsList{Tunnels: make([]WebInstructions, 0, len(c.tunnels))}
	for _, t := range c.tunnels {
		g := granted[t.name]
		wi := WebInstructions{Name: t.name}
		if instructions.SafeURL(g.DocsURL) {
			wi.DocsURL = strings.TrimSpace(g.DocsURL)
		}
		host, port, err := net.SplitHostPort(t.localAddr)
		if err != nil {
			host = t.localAddr
		}
		// A tunnel bound with --bind to a wildcard address (0.0.0.0, ::)
		// reports that literal address in t.localAddr, which is accurate
		// for status/dashboard display but not something a copy-pasted
		// curl command can dial (and is invalid outright on Windows).
		// Instructions substitute the loopback host instead, since the
		// listener always also accepts connections from this host itself.
		instructionHost := host
		if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
			if ip.To4() != nil {
				instructionHost = "127.0.0.1"
			} else {
				instructionHost = "::1"
			}
		}
		p, _ := strconv.Atoi(port)
		wi.Blocks = instructions.Render(g.Instructions, instructions.Data{
			Name: t.name, Description: g.Description,
			LocalAddress: net.JoinHostPort(instructionHost, port), LocalHost: instructionHost, LocalPort: p,
			VirtualPort: t.virtualPort, TargetHint: g.TargetHint,
			TunnelIP: c.Response.TunnelIP, ServerTunnelIP: c.Response.ServerTunnelIP,
			Server: c.base,
		})
		if wi.DocsURL == "" && len(wi.Blocks) == 0 {
			continue
		}
		out.Tunnels = append(out.Tunnels, wi)
	}
	return out
}

// FetchWebStatus retrieves live per-tunnel status from a running connect
// process's local status UI (Status.UIURL). It is used on a best-effort
// basis by commands like `list` and `status` that want to enrich their
// output with live data when a connection happens to be running.
func FetchWebStatus(uiURL string) (WebStatus, error) {
	var ws WebStatus
	if uiURL == "" {
		return ws, errors.New("no local status UI")
	}
	u, err := urlpkg.Parse(uiURL)
	if err != nil || u.Scheme != "http" || u.Host == "" {
		return ws, errors.New("running client does not expose a local status UI")
	}
	u.Path = "/status"
	h := &http.Client{Timeout: 2 * time.Second}
	resp, err := h.Get(u.String())
	if err != nil {
		return ws, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ws, fmt.Errorf("fetch status: %s", resp.Status)
	}
	if err = json.NewDecoder(resp.Body).Decode(&ws); err != nil {
		return ws, err
	}
	return ws, nil
}

func (c *Connection) forward(tunnel *localTunnel, listener net.Listener, target string) {
	for {
		in, e := listener.Accept()
		if e != nil {
			return
		}
		go func() {
			defer in.Close()
			c.mu.Lock()
			stack := c.Stack
			c.mu.Unlock()
			if stack == nil {
				return
			}
			out, e := stack.DialContext(context.Background(), "tcp", target)
			if e != nil {
				now := time.Now().Unix()
				last := tunnel.lastDialWarn.Load()
				if now-last >= 30 && tunnel.lastDialWarn.CompareAndSwap(last, now) {
					if c.log != nil {
						c.log.Warn("tunnel dial failed", "tunnel", tunnel.name, "target", target, "error", e)
					}
				}
				return
			}
			defer out.Close()
			tunnel.connections.Add(1)
			tunnel.active.Add(1)
			defer tunnel.active.Add(-1)
			started := time.Now()
			remote := in.RemoteAddr().String()
			if c.log != nil {
				c.log.Debug("tunnel connection opened", "tunnel", tunnel.name, "remote", remote)
			}
			toStart, fromStart := tunnel.toTunnel.Load(), tunnel.fromTunnel.Load()
			var copies sync.WaitGroup
			copies.Add(1)
			go func() {
				defer copies.Done()
				_, _ = io.Copy(countingWriter{w: out, counter: &tunnel.toTunnel}, in)
			}()
			_, _ = io.Copy(countingWriter{w: in, counter: &tunnel.fromTunnel}, out)
			copies.Wait()
			if c.log != nil {
				c.log.Debug("tunnel connection closed", "tunnel", tunnel.name, "remote", remote,
					"bytes_to_tunnel", tunnel.toTunnel.Load()-toStart, "bytes_from_tunnel", tunnel.fromTunnel.Load()-fromStart, "duration", time.Since(started))
			}
		}()
	}
}
func (c *Connection) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Best effort: expiry remains the server-side safety net if this cannot be
	// delivered (for example after a network outage).
	if c.http != nil && c.token != "" {
		req, err := http.NewRequest(http.MethodPost, c.base+"/v1/disconnect", nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+c.token)
			resp, err := c.http.Do(req)
			if err == nil && resp != nil {
				_ = resp.Body.Close()
			}
		}
	}
	for _, t := range c.tunnels {
		_ = t.listener.Close()
	}
	c.tunnels = nil
	select {
	case <-c.stop:
	default:
		close(c.stop)
	}
	if c.ui != nil {
		_ = c.ui.Close()
	}
	if c.statusFile == "" {
		c.statusFile = DefaultStatusFile()
	}
	if c.statusFile != "" {
		_ = os.Remove(c.statusFile)
	}
	if c.Stack != nil {
		_ = c.Stack.Close()
		c.Stack = nil
	}
}
