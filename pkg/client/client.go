// Package client implements the HTTPS authentication side of ntwire.
package client

import (
	"bufio"
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
	"github.com/nmaguiar/ntwire/pkg/pac"
	"github.com/nmaguiar/ntwire/pkg/portal"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"golang.org/x/net/proxy"
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
	"time"

	"gopkg.in/yaml.v3"
)

type Collector interface {
	Collect() (map[string]string, error)
}
type ExecCollector struct{ Command string }

// These indirections keep the browser-launch boundary testable without
// starting a desktop browser from a unit test.
var (
	openSocksBrowser = browseropen.OpenSocks
	openBrowser      = browseropen.Open
)

func BuiltinInfo() protocol.ClientInfo {
	h, _ := os.Hostname()
	u := os.Getenv("USER")
	return protocol.ClientInfo{OS: runtime.GOOS, Arch: runtime.GOARCH, Hostname: h, Username: u, ClientVersion: buildinfo.String(), Extra: map[string]string{}, PortalCapabilities: []string{"local_ports", "socks", "open_url", "portal_native", "launch_browser_with_socks"}}
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
	Ports map[string]int
	// Hosts is a per-tunnel loopback address override (e.g.
	// "127.70.0.1"), keyed by tunnel name. It is a strict override like
	// Ports: an address that fails to bind aborts the connect. Empty
	// (the default) defers to the tunnel's server-suggested LocalHost,
	// which is a soft preference that falls back to 127.0.0.1 on failure.
	// BindAddress, when explicitly set, takes precedence over both.
	Hosts    map[string]string
	CAFile   string
	Insecure bool
	// HTTPSProxy is an explicit HTTP, HTTPS, SOCKS5, or SOCKS5h proxy URL for
	// the HTTPS control plane and WSS data plane. When set, it takes precedence
	// over proxy environment variables. Authentication credentials in the URL
	// are supported.
	HTTPSProxy string
	// NoSystemProxy bypasses HTTP_PROXY, HTTPS_PROXY, and NO_PROXY. It has no
	// effect when HTTPSProxy is set.
	NoSystemProxy bool
	// IPVersion restricts every connection ntwire makes -- control-plane
	// HTTPS/WebSocket, direct-UDP WireGuard data plane, and the
	// WebSocket-fallback's UDP-based self-reflection, NAT priming, and
	// direct/UDP-relay upgrade rungs -- to one IP family. "" (default) races
	// every resolved address regardless of family and leaves the UDP data
	// plane dual-stack; "4" restricts everything to IPv4; "6" restricts
	// everything to IPv6 -- the excluded family is never attempted, even if
	// the chosen family fails outright. Any other value is rejected.
	//
	// A server-advertised direct-UDP endpoint of the excluded family is
	// treated as unusable: the connection falls back to the WebSocket
	// transport instead of dialing it (see ConnectWithOptions). The UDP
	// bind itself is also restricted at the transport layer (pkg/ipfamily),
	// so even a relay-punched or NAT-roamed candidate of the excluded
	// family can never carry traffic.
	IPVersion        string
	KnownServersFile string
	NoWebUI          bool
	StatusFile       string
	UseWebSocket     bool

	// NoDirectUpgrade disables the opportunistic upgrade ladder
	// (directupgrade.go) that a WebSocket-fallback session otherwise
	// attempts in the background -- both the UDP-relay forwarding rung and
	// the full direct-UDP escape above it. It only matters for a session
	// that auto-selected WebSocket (e.g. a relay-only server) rather than
	// one forced into it via UseWebSocket -- the latter already skips the
	// ladder unconditionally, since a caller-forced transport is meant to
	// stay put.
	NoDirectUpgrade bool
	// DirectUpgradeTiming overrides the direct-UDP upgrade's pacing. Leave
	// nil for the production defaults; see DirectUpgradeTiming's doc.
	DirectUpgradeTiming *DirectUpgradeTiming

	// Multipath overrides v3's bounded reactive-duplication budget. Leave nil
	// for the production default.
	Multipath *MultipathOptions

	// Transport selects a preferred or forced transport mode ("auto",
	// "direct-udp", "udp-relay", "wss"). When set to a specific transport,
	// the client forces that transport as primary while healthy, and
	// automatically falls back to the best available healthy transport
	// if the forced transport becomes unavailable or degraded.
	Transport string

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
	// OIDCClientSecret supplies the optional client secret required by some
	// public OIDC clients. When empty, NTWIRE_OIDC_CLIENT_SECRET is used for
	// backwards compatibility with the command-line client.
	//
	// Callers must keep this value private: it is only sent to the issuer's
	// token endpoint and is never included in ntwire protocol messages.
	OIDCClientSecret string
	Logger           *slog.Logger

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

	// SettingsURL, when set, is a caller-supplied link to a settings UI for
	// this connection: ntwire-gui's settings window, or cmd/ntwire's own
	// local settings page (see startSettingsUI) for the persisted
	// ~/.ntwire/config.yaml a plain `ntwire connect` reads. It is surfaced
	// to the local status UI (WebStatus.SettingsURL) as a "Settings" link.
	SettingsURL string

	// Profile is an optional identifier for the connection profile (such as
	// a GUI profile ID). When non-empty, browser profile directories and keys
	// are namespaced under this profile (e.g. "<profile>-<tunnel>"), aligning
	// the web UI's "Open in browser" behavior with the tray menu's per-profile
	// browser instances. When empty, defaults to "client-<tunnel>".
	Profile string
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
	c.mu.Lock()
	switch e.Kind {
	case EventReconnecting, EventReconnectFailed:
		c.reconnectState.Reconnecting = true
		c.reconnectState.Attempts++
		if e.Err != nil {
			c.reconnectState.LastError = e.Err.Error()
		}
		if e.RetryIn > 0 {
			retryAt := time.Now().Add(e.RetryIn)
			c.reconnectState.RetryAt = &retryAt
		}
	case EventReconnected, EventRenewed:
		c.reconnectState.Reconnecting = false
		c.reconnectState.RetryAt = nil
		c.reconnectState.LastError = ""
	}
	c.mu.Unlock()
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

// RedactProxyURL removes passwords from a proxy URL string so it is safe to log
// or return in error messages.
func RedactProxyURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := urlpkg.Parse(raw)
	if err != nil {
		return redactUserinfoString(raw)
	}
	return u.Redacted()
}

func redactUserinfoString(raw string) string {
	if idx := strings.Index(raw, "://"); idx != -1 {
		prefix := raw[:idx+3]
		rest := raw[idx+3:]
		if at := strings.Index(rest, "@"); at != -1 {
			userinfo := rest[:at]
			after := rest[at+1:]
			if colon := strings.Index(userinfo, ":"); colon != -1 {
				userinfo = userinfo[:colon] + ":xxxxx"
			}
			return prefix + userinfo + "@" + after
		}
	}
	return raw
}

type socksForwardDialer struct {
	ipVersion string
}

func (d *socksForwardDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *socksForwardDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return raceResolvedDial(ctx, network, address, d.ipVersion)
}

func newSOCKS5Dialer(proxyURL *urlpkg.URL, ipVersion string) (proxy.Dialer, error) {
	proxyHost := proxyURL.Hostname()
	proxyPort := proxyURL.Port()
	if proxyPort == "" {
		proxyPort = "1080"
	}
	proxyAddr := net.JoinHostPort(proxyHost, proxyPort)

	var auth *proxy.Auth
	if proxyURL.User != nil {
		auth = &proxy.Auth{
			User: proxyURL.User.Username(),
		}
		if pass, ok := proxyURL.User.Password(); ok {
			auth.Password = pass
		}
	}

	forward := &socksForwardDialer{ipVersion: ipVersion}
	return proxy.SOCKS5("tcp", proxyAddr, auth, forward)
}

// configureProxy configures the HTTP proxy func and DialContext dialer based on
// the requested proxy scheme (http, https, socks5, socks5h) and options.
func configureProxy(o Options) (func(*http.Request) (*urlpkg.URL, error), func(context.Context, string, string) (net.Conn, error), error) {
	if o.HTTPSProxy != "" {
		proxyURL, err := urlpkg.Parse(o.HTTPSProxy)
		if err != nil || proxyURL.Hostname() == "" {
			return nil, nil, fmt.Errorf("invalid HTTPS proxy %q: must be an http://, https://, socks5://, or socks5h:// URL", RedactProxyURL(o.HTTPSProxy))
		}
		switch proxyURL.Scheme {
		case "http", "https":
			return http.ProxyURL(proxyURL), func(ctx context.Context, network, address string) (net.Conn, error) {
				return raceResolvedDial(ctx, network, address, o.IPVersion)
			}, nil
		case "socks5":
			// socks5://: destination hostname is resolved locally before asking SOCKS proxy to connect.
			d, err := newSOCKS5Dialer(proxyURL, o.IPVersion)
			if err != nil {
				return nil, nil, err
			}
			return nil, func(ctx context.Context, network, address string) (net.Conn, error) {
				return raceSOCKSResolvedDial(ctx, d, network, address, o.IPVersion)
			}, nil
		case "socks5h":
			// socks5h://: destination hostname is passed directly to SOCKS proxy for remote resolution.
			// Client-side address racing for the destination is bypassed because DNS resolution happens on the proxy.
			d, err := newSOCKS5Dialer(proxyURL, o.IPVersion)
			if err != nil {
				return nil, nil, err
			}
			return nil, func(ctx context.Context, network, address string) (net.Conn, error) {
				if cd, ok := d.(proxy.ContextDialer); ok {
					return cd.DialContext(ctx, network, address)
				}
				return d.Dial(network, address)
			}, nil
		default:
			return nil, nil, fmt.Errorf("invalid HTTPS proxy %q: must be an http://, https://, socks5://, or socks5h:// URL", RedactProxyURL(o.HTTPSProxy))
		}
	}
	var pFunc func(*http.Request) (*urlpkg.URL, error)
	if !o.NoSystemProxy {
		pFunc = http.ProxyFromEnvironment
	}
	return pFunc, func(ctx context.Context, network, address string) (net.Conn, error) {
		return raceResolvedDial(ctx, network, address, o.IPVersion)
	}, nil
}

func httpClient(url string, o Options) (*http.Client, error) {
	if o.IPVersion != "" && o.IPVersion != "4" && o.IPVersion != "6" {
		return nil, fmt.Errorf("invalid IP version %q: must be \"4\" or \"6\"", o.IPVersion)
	}
	proxy, dialContext, err := configureProxy(o)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(strings.ToLower(url), "https://") {
		return resilientHTTPClient(nil, proxy, dialContext), nil
	}
	if o.Insecure {
		return resilientHTTPClient(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}, proxy, dialContext), nil
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
		return resilientHTTPClient(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}, proxy, dialContext), nil
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
	}}, proxy, dialContext), nil
}

// proxyFunc selects the HTTPS control-plane proxy if an HTTP/HTTPS proxy is configured.
// An explicit proxy wins; otherwise callers may opt out of the process-wide proxy environment.
func proxyFunc(o Options) (func(*http.Request) (*urlpkg.URL, error), error) {
	pFunc, _, err := configureProxy(o)
	return pFunc, err
}

// resilientHTTPClient creates an http.Client configured with custom TLS, proxy, and dialer.
func resilientHTTPClient(tlsConfig *tls.Config, proxy func(*http.Request) (*urlpkg.URL, error), dialContext func(context.Context, string, string) (net.Conn, error)) *http.Client {
	transport := &http.Transport{Proxy: proxy, TLSClientConfig: tlsConfig, DialContext: dialContext}
	return &http.Client{Transport: transport}
}

// filterIPVersion drops every address not of the family named by ipVersion
// ("4" or "6"), preserving resolver order. It returns addrs unchanged for
// "" (httpClient rejects any other value before this is ever reached).
func filterIPVersion(addrs []net.IPAddr, ipVersion string) []net.IPAddr {
	if ipVersion == "" {
		return addrs
	}
	wantV4 := ipVersion == "4"
	out := make([]net.IPAddr, 0, len(addrs))
	for _, a := range addrs {
		if (a.IP.To4() != nil) == wantV4 {
			out = append(out, a)
		}
	}
	return out
}

func raceDialAddrs(ctx context.Context, dialFn func(context.Context, string) (net.Conn, error), addrs []net.IPAddr, port, host string) (net.Conn, error) {
	if len(addrs) == 1 {
		return dialFn(ctx, net.JoinHostPort(addrs[0].IP.String(), port))
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
			conn, dialErr := dialFn(child, net.JoinHostPort(ip.String(), port))
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

func raceResolvedDial(ctx context.Context, network, address, ipVersion string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) != nil {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	addrs = filterIPVersion(addrs, ipVersion)
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%s has no IPv%s address", host, ipVersion)
	}
	return raceDialAddrs(ctx, func(ctx context.Context, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}, addrs, port, host)
}

func raceSOCKSResolvedDial(ctx context.Context, socksDialer proxy.Dialer, network, address, ipVersion string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) != nil {
		if cd, ok := socksDialer.(proxy.ContextDialer); ok {
			return cd.DialContext(ctx, network, address)
		}
		return socksDialer.Dial(network, address)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	addrs = filterIPVersion(addrs, ipVersion)
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%s has no IPv%s address", host, ipVersion)
	}
	return raceDialAddrs(ctx, func(ctx context.Context, addr string) (net.Conn, error) {
		if cd, ok := socksDialer.(proxy.ContextDialer); ok {
			return cd.DialContext(ctx, network, addr)
		}
		return socksDialer.Dial(network, addr)
	}, addrs, port, host)
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
	if err = json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return protocol.InfoResponse{}, err
	}
	if out.Version != protocol.Version {
		return protocol.InfoResponse{}, fmt.Errorf("server uses unsupported protocol version %d", out.Version)
	}
	if err := protocol.ValidateRequiredCapabilities(clientCapabilities(), out.RequiredCapabilities); err != nil {
		return protocol.InfoResponse{}, fmt.Errorf("server requires an unsupported capability: %w", err)
	}
	return out, nil
}

// clientCapabilities are optional control/data-plane features this binary can
// understand. They are kept separate from what a particular connection
// requests so an InfoResponse can fail a required capability before auth.
func clientCapabilities() []string {
	return []string{protocol.CapabilityMultipathV3, protocol.CapabilityPathMTUV1}
}

func clientTransportCapabilities() []string { return clientCapabilities() }

func validateAuthResponseCapabilities(r protocol.AuthResponse) error {
	if err := protocol.ValidateRequiredCapabilities(clientTransportCapabilities(), r.RequiredTransportCapabilities); err != nil {
		return fmt.Errorf("server requires an unsupported transport capability: %w", err)
	}
	return nil
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
	clientSecret := o.OIDCClientSecret
	if clientSecret == "" {
		clientSecret = os.Getenv("NTWIRE_OIDC_CLIENT_SECRET")
	}
	tok, err := oidcclient.TokensForIssuer(context.Background(), cache, base, issuer, oidcclient.ForIssuerOptions{NoBrowser: o.NoBrowser, ClientSecret: clientSecret})
	if err != nil {
		return protocol.AuthResponse{}, fmt.Errorf("sso login: %w", err)
	}
	r := protocol.OIDCAuthRequest{
		Version: protocol.Version, IssuerName: issuer.Name, IDToken: tok.IDToken,
		WireGuardPublicKey: wgPublic, Timestamp: time.Now().UTC().Format(time.RFC3339), Info: info,
		TransportCapabilities: clientTransportCapabilities(),
		QueryOnly:             o.QueryOnly,
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
	if err = json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return protocol.AuthResponse{}, err
	}
	if err := validateAuthResponseCapabilities(out); err != nil {
		return protocol.AuthResponse{}, err
	}
	return out, nil
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
	r := protocol.AuthRequest{Version: protocol.Version, PublicKey: pub, WireGuardPublicKey: wgPublic, Timestamp: time.Now().UTC().Format(time.RFC3339), Nonce: base64.RawURLEncoding.EncodeToString(n), Info: info, TransportCapabilities: clientTransportCapabilities(), QueryOnly: o.QueryOnly}
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
	if err = json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return protocol.AuthResponse{}, err
	}
	if err := validateAuthResponseCapabilities(out); err != nil {
		return protocol.AuthResponse{}, err
	}
	return out, nil
}

// Connection is a persistent, local-listener view of one WireGuard session.
type Connection struct {
	Response       protocol.AuthResponse
	Stack          *wgnet.Stack
	tunnels        []*localTunnel
	LocalAddresses []string
	token, base    string
	mu             sync.Mutex
	closed         bool
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
	// expiresAt and reconnectState are the GUI-facing lifecycle facts which
	// cannot be reconstructed reliably from logs. They are protected by mu
	// along with Response, because renewal replaces both at the same time.
	expiresAt      time.Time
	reconnectState ReconnectState

	// historyMu guards history, a bounded ring buffer of periodic status
	// snapshots (see recordHistorySample/historyLoop) that back the local
	// status UI's charts. It is a separate lock from mu -- recording a
	// sample calls webStatus, which takes mu itself -- and is never held
	// while doing I/O.
	historyMu sync.Mutex
	history   []WebHistorySample

	// hybrid and serverTunnelIP are set only in WebSocket-fallback mode; see
	// directupgrade.go's opportunistic direct-UDP upgrade. upgradeTiming is
	// resolved once at connect time and never mutated after, so
	// directUpgradeLoop's goroutine can read it without locking.
	hybrid         *wstransport.Hybrid
	multipath      *wstransport.MultipathBind
	serverTunnelIP netip.Addr
	upgradeTiming  directUpgradeTiming
	// lastRelayUDPToken is the most recent UDP-relay allocation token seen
	// by tryUDPRelayUpgrade, used to detect a re-allocation (see
	// wstransport.MultipathBind.ResetRelayLegStats' doc comment for why
	// that must reset the leg counters). Owned exclusively by
	// directUpgradeLoop's single background goroutine, like upgradeTiming,
	// relayCandidate, and directCandidate -- never read or written under
	// c.mu.
	lastRelayUDPToken string

	// relayHopStats is the most recently received UDP-relay hop-telemetry
	// summary from the server (see postUDPRelay/protocol.UDPRelayResponse.Stats),
	// surfaced locally via State/Status so the same localized-loss picture
	// the server's dashboard shows is visible here too, not server-side
	// only. nil until the server has sent at least one.
	relayHopStats atomic.Pointer[protocol.UDPRelayHopStats]
}

// closeDisconnectTimeout bounds the best-effort remote cleanup request.
// It is a variable solely so lifecycle tests can inject a short deterministic
// timeout; production keeps the one-second default.
var closeDisconnectTimeout = time.Second

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
		return "WSS"
	case transportUDPRelay:
		return "UDP via relay"
	case transportUDPRelayReflector:
		return "UDP direct via relay reflector"
	default:
		return "unknown"
	}
}

// TransportMode is the stable, machine-readable form of the active
// data-plane route. Description in ConnectionState.Transport is intended for
// display; consumers should branch on Mode instead.
type TransportMode string

const (
	TransportUnknown           TransportMode = "unknown"
	TransportUDPDirect         TransportMode = "udp_direct"
	TransportWebSocketFallback TransportMode = "websocket_fallback"
	TransportWebSocketRelay    TransportMode = "websocket_relay"
	TransportUDPRelay          TransportMode = "udp_relay"
	TransportUDPRelayReflector TransportMode = "udp_relay_reflector"
)

func (t connectionTransport) mode() TransportMode {
	switch t {
	case transportUDPDirect:
		return TransportUDPDirect
	case transportWSSFallback:
		return TransportWebSocketFallback
	case transportWSSRelay:
		return TransportWebSocketRelay
	case transportUDPRelay:
		return TransportUDPRelay
	case transportUDPRelayReflector:
		return TransportUDPRelayReflector
	default:
		return TransportUnknown
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
// human-readable form (e.g. "UDP direct", "WSS"), including any
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
	packetConn   net.PacketConn
	protocol     string
	socks        bool
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
	// A direct UDP endpoint of the wrong family is treated as if the server
	// hadn't advertised one at all: selectTransport falls back to WebSocket
	// rather than dialing a family the caller explicitly excluded. mismatch
	// only feeds the transportReason banner below -- the actual UDP data
	// plane (direct or via the WebSocket-fallback's opportunistic upgrade
	// ladder) is restricted to options.IPVersion structurally, via
	// pkg/ipfamily, regardless of this check.
	udpEndpoint, mismatch := r.UDP, ""
	if r.UDP != "" && !matchesIPVersion(r.UDP, options.IPVersion) {
		mismatch = fmt.Sprintf("server's direct UDP endpoint (%s) is not IPv%s", r.UDP, options.IPVersion)
		udpEndpoint = ""
	}
	transport, err := normalizeTransportPreference(options.UseWebSocket, options.Transport)
	if err != nil {
		return nil, err
	}
	// v3 is the complete and sole multipath contract. A server offering only
	// retired v1/v2 identifiers is treated as a legacy single-path peer.
	multipathV3 := r.Multipath && hasTransportCapability(r.TransportCapabilities, protocol.CapabilityMultipathV3)
	pathMTU := multipathV3 && hasTransportCapability(r.TransportCapabilities, protocol.CapabilityPathMTUV1)
	useWS, err := selectTransport(options.UseWebSocket, transport, multipathV3, udpEndpoint, r.WebSocket)
	if err != nil {
		return nil, err
	}
	serverIP, err := resolveServerTunnelIP(r.ServerTunnelIP, clientIP)
	if err != nil {
		return nil, err
	}
	stackConfig := wgnet.Config{PrivateKey: key.Private, Addresses: []netip.Addr{clientIP}, DNSServers: []netip.Addr{serverIP}, IPVersion: options.IPVersion, UDPBufferLogger: options.Logger}
	// hybrid is non-nil only in WebSocket-fallback mode; it is what the
	// opportunistic direct-UDP upgrade (directupgrade.go) uses to
	// self-reflect, prime, and move the peer's endpoint between transports.
	// A direct-UDP session (useWS false) already has the best available
	// path and has nothing to upgrade to.
	var hybrid *wstransport.Hybrid
	var multipath *wstransport.MultipathBind
	if useWS {
		if multipathV3 {
			// V3 deliberately uses sticky carrier/probe health and never samples
			// a standby by mirroring ordinary tunnel payload.
			hybrid, multipath = wstransport.NewMultipathHybridClient(r.WebSocket, h, http.Header{"Authorization": {"Bearer " + r.Token}}, pathMTU, resolveMultipathOptions(options.Multipath), options.IPVersion, options.Logger)
			stackConfig.Bind = multipath
		} else {
			hybrid = wstransport.NewHybridClient(r.WebSocket, h, http.Header{"Authorization": {"Bearer " + r.Token}}, options.IPVersion, options.Logger)
			stackConfig.Bind = hybrid
		}
	}
	st, err := wgnet.New(stackConfig)
	if err != nil {
		return nil, err
	}
	endpoint := r.UDP
	if useWS {
		if multipath != nil {
			endpoint = wstransport.MultipathSentinel
		} else {
			endpoint = wstransport.WSSentinel
		}
	}
	if err = st.AddPeer(wgnet.Endpoint{PublicKey: r.ServerPublicKey, Address: allowedIPsForFamily(clientIP) + "@" + endpoint}); err != nil {
		st.Close()
		return nil, err
	}
	c := &Connection{
		Response: r, Stack: st, token: r.Token, base: url, info: info, http: h, ports: options.Ports,
		hybrid: hybrid, multipath: multipath, serverTunnelIP: serverIP, upgradeTiming: resolveDirectUpgradeTiming(options.DirectUpgradeTiming),
		stop: make(chan struct{}), statusFile: options.StatusFile, keyPath: keyPath,
		bindAddr: bindAddr, options: options, method: auth.method, issuer: auth.issuer,
		log: options.Logger,
	}
	if multipath != nil && transport != "" {
		multipath.SetForced(transport)
	}
	if r.TTLSeconds > 0 {
		c.expiresAt = time.Now().Add(time.Duration(r.TTLSeconds) * time.Second)
	}
	c.transport.Store(uint32(initialTransportState(useWS, r.UDP).connectionTransport()))
	c.latencyMillis.Store(uint64(time.Since(authStart).Milliseconds()))
	if c.log == nil {
		c.log = slog.Default()
	}
	if options.Insecure {
		c.log.Warn("TLS certificate verification is disabled", "event", "insecure_tls_enabled", "server", c.DisplayName())
	}
	dataTransport := "udp"
	if useWS {
		dataTransport = "websocket"
		// transportReason is left empty when the caller passed --websocket:
		// they already know why. It's only worth surfacing (in the connect
		// CLI's banner, and as Warn-level noise if the background
		// direct-upgrade loop then fails) for the auto-selected case, where
		// the server simply never advertised a UDP endpoint -- the
		// surprising, often-support-question-worthy one.
		if !options.UseWebSocket && udpEndpoint == "" {
			c.transportReason = "server did not advertise a direct UDP WireGuard endpoint"
			if mismatch != "" {
				c.transportReason = mismatch
			}
		}
	}
	c.log.Debug("control-plane session established", "server", c.DisplayName(), "transport", dataTransport, "reason", c.transportReason, "tunnel_ip", clientIP, "ttl_seconds", r.TTLSeconds)
	explicitBind := options.BindAddress != ""
	if bindIP, e := netip.ParseAddr(bindAddr); explicitBind && (e != nil || !bindIP.IsLoopback()) {
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
		host, softHost, rejectedServerHost := resolveTunnelHost(t.Name, t.LocalHost, options.Hosts, explicitBind, bindAddr)
		if rejectedServerHost != "" {
			// A server-supplied local_host is validated at config load
			// time, but the client re-checks: it must never trust a
			// (possibly compromised) server to move a listener beyond
			// loopback on its behalf.
			c.log.Warn("server suggested a non-loopback local_host for a tunnel; ignoring it", "tunnel", t.Name, "local_host", rejectedServerHost)
		}
		if t.Protocol == "udp" {
			pc, firstErr, e := listenLocalUDP(host, p, softHost, !explicitPort)
			if e != nil {
				c.Close()
				return nil, e
			}
			bound := pc.LocalAddr().String()
			if firstErr != nil {
				c.log.Warn("UDP tunnel listener fell back from its requested local address", "tunnel", t.Name, "requested", net.JoinHostPort(host, fmt.Sprint(p)), "bound", bound, "error", firstErr)
			}
			target := net.JoinHostPort(serverIP.String(), fmt.Sprint(t.VirtualPort))
			lt := &localTunnel{name: t.Name, virtualPort: t.VirtualPort, packetConn: pc, protocol: "udp", localAddr: bound, target: target}
			c.tunnels = append(c.tunnels, lt)
			c.LocalAddresses = append(c.LocalAddresses, bound)
			c.log.Debug("UDP tunnel listener bound", "tunnel", t.Name, "local_address", bound, "target", target)
			go c.forwardUDP(lt, pc, target, t.UDPIdleTimeout)
			continue
		}
		l, firstErr, e := listenLocal(host, p, softHost, !explicitPort, nil)
		if e != nil {
			c.Close()
			return nil, e
		}
		bound := l.Addr().String()
		requested := net.JoinHostPort(host, fmt.Sprint(p))
		if firstErr != nil {
			fields := []any{"tunnel", t.Name, "requested", requested, "bound", bound, "error", firstErr}
			if hint := loopbackAliasHint(host); hint != "" {
				fields = append(fields, "hint", hint)
			}
			c.log.Warn("tunnel listener fell back from its requested local address", fields...)
		}
		target := net.JoinHostPort(serverIP.String(), fmt.Sprint(t.VirtualPort))
		lt := &localTunnel{name: t.Name, virtualPort: t.VirtualPort, listener: l, protocol: "tcp", socks: protocol.IsBrowserSocksTarget(t.TargetHint), localAddr: bound, target: target}
		c.tunnels = append(c.tunnels, lt)
		c.LocalAddresses = append(c.LocalAddresses, bound)
		c.log.Debug("tunnel listener bound", "tunnel", t.Name, "local_address", bound, "target", target)
		go c.forward(lt, l, target)
	}
	go c.renewLoop()
	go c.historyLoop()
	// v3 bootstraps over WSS and registers direct UDP as a probe-qualified standby.
	// The scheduler retains its healthy incumbent until actual failure, so a
	// probe-only challenger cannot steal live tunnel traffic.
	if multipath != nil && shouldBootstrapDirectMultipath(multipathV3, udpEndpoint, options.UseWebSocket) {
		go c.bootstrapDirectMultipath(udpEndpoint)
	}
	if hybrid != nil && udpEndpoint == "" && !options.NoDirectUpgrade && transport != string(wstransport.PathWSS) {
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

// MultipathOptions contains the bounded v3 data-path knobs. A zero field uses
// the production default.
type MultipathOptions struct {
	// DuplicateRateBytesPerSec bounds reactive WireGuard-only duplication.
	DuplicateRateBytesPerSec int
}

func resolveMultipathOptions(o *MultipathOptions) wstransport.MultipathOptions {
	if o == nil {
		return wstransport.MultipathOptions{}
	}
	return wstransport.MultipathOptions{
		DuplicateRateBytesPerSec: o.DuplicateRateBytesPerSec,
	}
}

func hasTransportCapability(caps []string, want string) bool {
	for _, got := range caps {
		if got == want {
			return true
		}
	}
	return false
}

// selectTransport decides whether the WireGuard data plane uses the
// WebSocket fallback instead of UDP. explicit is the caller's --websocket
// flag; udp and websocket are AuthResponse.UDP/WebSocket. A relay-only
// server advertises no UDP endpoint (udp == ""), so this auto-selects
// WebSocket instead of requiring the caller to know that in advance — a
// direct server with a misconfigured empty advertised_endpoint used to
// simply error here; it now silently works over WebSocket instead, which is
// strictly better but is a deliberate behavior change (see PLAN-RELAY.md §F).
func selectTransport(explicit bool, transport string, multipath bool, udp, websocket string) (useWS bool, err error) {
	switch transport {
	case string(wstransport.PathWSS):
		if websocket == "" {
			return false, fmt.Errorf("transport wss requested but server did not advertise a WebSocket endpoint")
		}
		return true, nil
	case string(wstransport.PathDirect):
		if udp == "" {
			return false, fmt.Errorf("transport direct-udp requested but server did not advertise a WireGuard endpoint")
		}
		// An explicit direct-udp choice is a single-path request. In
		// particular, do not bootstrap over WSS and let an independent server
		// scheduler select a different return path.
		return false, nil
	case string(wstransport.PathUDPRelay):
		if websocket == "" {
			return false, fmt.Errorf("transport udp-relay requested but server did not advertise a WebSocket endpoint")
		}
		if !multipath {
			return false, fmt.Errorf("transport udp-relay requested but server did not negotiate multipath")
		}
		return true, nil
	}
	// When both legs negotiated multipath, bootstrap over WSS so it remains a
	// live candidate while direct UDP is independently reflected, registered,
	// and probed. Selecting raw UDP here would discard WSS entirely, making
	// automatic comparison and failover impossible.
	useWS = explicit || (udp == "" && websocket != "") || (transport == "" && multipath && udp != "" && websocket != "")
	if useWS && websocket == "" {
		return false, fmt.Errorf("server did not advertise a WebSocket endpoint")
	}
	if !useWS && udp == "" {
		return false, fmt.Errorf("server did not advertise a WireGuard endpoint")
	}
	return useWS, nil
}

// shouldBootstrapDirectMultipath gates automatic direct-UDP registration.
// Only the complete v3 contract can add a probe-qualified standby while keeping the
// established WSS incumbent stable.
func shouldBootstrapDirectMultipath(multipathV3 bool, udpEndpoint string, websocketForced bool) bool {
	return multipathV3 && udpEndpoint != "" && !websocketForced
}

func normalizeTransportPreference(websocket bool, transport string) (string, error) {
	normalized, err := wstransport.ValidateTransportName(transport)
	if err != nil {
		return "", err
	}
	if websocket && normalized != "" && normalized != string(wstransport.PathWSS) {
		return "", fmt.Errorf("-websocket conflicts with -transport %s", normalized)
	}
	if websocket {
		return string(wstransport.PathWSS), nil
	}
	return normalized, nil
}

// matchesIPVersion reports whether hostport's host is a literal address of
// the requested family ("4" or "6"). "" (no restriction) always matches.
func matchesIPVersion(hostport, ipVersion string) bool {
	if ipVersion == "" {
		return true
	}
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	if ipVersion == "6" {
		return addr.Unmap().Is6()
	}
	return addr.Unmap().Is4()
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

// resolveTunnelHost picks one tunnel's local listener host and whether it
// is a soft (fallback-eligible) or hard (strict) choice, per this order:
//
//  1. hosts[name]        (client --port name=host:port, or settings hosts:) -- soft
//  2. bindAddr            (explicit --bind)                                  -- strict
//  3. serverLocalHost     (server's per-tunnel suggestion)                   -- soft
//  4. bindAddr            (the resolved default, ordinarily 127.0.0.1)
//
// A non-loopback serverLocalHost is never used -- the client does not
// trust the server to move a listener beyond loopback on its behalf, even
// though the server is expected to have already rejected that value at
// config load -- and is returned as rejectedServerHost so the caller can
// log it; rejectedServerHost is empty whenever there was nothing to reject.
func resolveTunnelHost(name, serverLocalHost string, hosts map[string]string, explicitBind bool, bindAddr string) (host string, soft bool, rejectedServerHost string) {
	if h, ok := hosts[name]; ok {
		return h, true, ""
	}
	if explicitBind {
		return bindAddr, false, ""
	}
	if serverLocalHost != "" {
		if ip, err := netip.ParseAddr(serverLocalHost); err == nil && ip.IsLoopback() {
			return serverLocalHost, true, ""
		}
		return bindAddr, true, serverLocalHost
	}
	return bindAddr, true, ""
}

// listenFunc matches net.Listen's signature; it exists so tests can inject
// failures for a specific address without depending on platform-specific
// errno behavior (e.g. binding a loopback alias that only exists on Linux).
type listenFunc func(network, address string) (net.Listener, error)

// listenLocal binds a tunnel's local listener at host:port, softening the
// host and/or port when the caller did not strictly require them:
//
//  1. host:port
//  2. host:0            (only when softPort and port != 0)
//  3. 127.0.0.1:port    (only when softHost and host != "127.0.0.1")
//  4. 127.0.0.1:0       (only when softHost, softPort, port != 0, and host != "127.0.0.1")
//
// A configured local port or preferred loopback address is a convenience
// default, not a guarantee, so any bind error triggers the next step --
// this is deliberately not classified by errno, since the set that means
// "this address is unavailable" (e.g. EADDRINUSE, EADDRNOTAVAIL) is not
// portable across platforms. A hard (non-soft) host or port is a strict
// override: its failure is returned immediately with no fallback.
//
// firstErr is the error from the initial host:port attempt (nil if it
// succeeded), returned so callers can log why a tunnel did not land on its
// requested address even when a fallback then succeeded. err is non-nil
// only when no attempt bound successfully. listen defaults to net.Listen
// when nil.
func listenLocal(host string, port int, softHost, softPort bool, listen listenFunc) (l net.Listener, firstErr error, err error) {
	if listen == nil {
		listen = net.Listen
	}
	l, firstErr = listen("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if firstErr == nil {
		return l, nil, nil
	}
	if softPort && port != 0 {
		if l2, e := listen("tcp", net.JoinHostPort(host, "0")); e == nil {
			return l2, firstErr, nil
		}
	}
	if softHost && host != "127.0.0.1" {
		if l2, e := listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port))); e == nil {
			return l2, firstErr, nil
		}
		if softPort && port != 0 {
			if l2, e := listen("tcp", net.JoinHostPort("127.0.0.1", "0")); e == nil {
				return l2, firstErr, nil
			}
		}
	}
	return nil, firstErr, firstErr
}

func listenLocalUDP(host string, port int, softHost, softPort bool) (net.PacketConn, error, error) {
	listen := func(h string, p int) (net.PacketConn, error) {
		return net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(h), Port: p})
	}
	pc, firstErr := listen(host, port)
	if firstErr == nil {
		return pc, nil, nil
	}
	if softPort && port != 0 {
		if pc, e := listen(host, 0); e == nil {
			return pc, firstErr, nil
		}
	}
	if softHost && host != "127.0.0.1" {
		if pc, e := listen("127.0.0.1", port); e == nil {
			return pc, firstErr, nil
		}
		if softPort && port != 0 {
			if pc, e := listen("127.0.0.1", 0); e == nil {
				return pc, firstErr, nil
			}
		}
	}
	return nil, firstErr, firstErr
}

// loopbackAliasHint returns an actionable command for a loopback address
// that is not the universally-present 127.0.0.1, on the one platform where
// it typically needs one: macOS assigns only 127.0.0.1 to lo0 by default,
// so any other 127.0.0.0/8 address (or a non-::1 IPv6 loopback) 404s at
// bind time until an operator adds it as an alias. Linux binds all of
// 127/8 out of the box and needs no such hint.
func loopbackAliasHint(host string) string {
	if runtime.GOOS != "darwin" || host == "" || host == "127.0.0.1" || host == "::1" {
		return ""
	}
	if ip, err := netip.ParseAddr(host); err != nil || !ip.IsLoopback() {
		return ""
	}
	return fmt.Sprintf("sudo ifconfig lo0 alias %s up", host)
}

// ReplacePort switches a tunnel's local port, keeping its currently bound
// host unchanged. It is a thin wrapper over ReplaceListener for callers
// (the web UI, `ntwire port <name>=N`, the GUI) that only want to change
// the port.
func (c *Connection) ReplacePort(name string, port int) (string, error) {
	return c.ReplaceListener(name, "", port)
}

// ReplaceListener atomically switches a tunnel to a new local listener.
// An empty host keeps the tunnel's currently bound host unchanged -- it
// must not default to c.bindAddr, since that would silently relocate a
// tunnel bound to a non-default host (e.g. a server-suggested local_host)
// back to the connection's baseline on a port-only change. Existing
// connections continue on the old listener while new connections use the
// new one. Unlike the automatic per-tunnel fallback at connect time, this
// is a direct user action: it is strict, with no fallback to another
// address or port on failure.
func (c *Connection) ReplaceListener(name, host string, port int) (string, error) {
	if name == "" || port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid tunnel name or local port")
	}
	if host != "" {
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return "", fmt.Errorf("invalid local host %q: must be a numeric IP address", host)
		}
		host = ip.String()
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
	currentHost, currentPort, splitErr := net.SplitHostPort(tunnel.localAddr)
	if host == "" {
		if splitErr == nil {
			host = currentHost
		} else if host = c.bindAddr; host == "" {
			host = "127.0.0.1"
		}
	}
	if splitErr == nil && currentHost == host && currentPort == fmt.Sprint(port) {
		addr := tunnel.localAddr
		c.mu.Unlock()
		return addr, nil
	}
	c.mu.Unlock()
	if tunnel.protocol == "udp" {
		pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host), Port: port})
		if err != nil {
			return "", err
		}
		c.mu.Lock()
		if c.Stack == nil {
			c.mu.Unlock()
			_ = pc.Close()
			return "", fmt.Errorf("connection is closed")
		}
		index := -1
		for i, t := range c.tunnels {
			if t == tunnel {
				index = i
				break
			}
		}
		if index < 0 {
			c.mu.Unlock()
			_ = pc.Close()
			return "", fmt.Errorf("unknown tunnel %q", name)
		}
		old := tunnel.packetConn
		tunnel.packetConn, tunnel.localAddr = pc, pc.LocalAddr().String()
		c.LocalAddresses[index] = tunnel.localAddr
		addr := tunnel.localAddr
		c.mu.Unlock()
		if old != nil {
			_ = old.Close()
		}
		go c.forwardUDP(tunnel, pc, tunnel.target, 0)
		_ = c.writeCurrentStatus()
		return addr, nil
	}

	l, err := net.Listen("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
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
					c.preserveTransportOnReconnect()
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
	if c.closed || c.Stack == nil {
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
	if c.closed {
		c.mu.Unlock()
		return fmt.Errorf("connection is closed")
	}
	c.Response = auth.response
	c.token = auth.response.Token
	c.method, c.issuer = auth.method, auth.issuer
	if auth.response.TTLSeconds > 0 {
		c.expiresAt = time.Now().Add(time.Duration(auth.response.TTLSeconds) * time.Second)
	} else {
		c.expiresAt = time.Time{}
	}
	c.latencyMillis.Store(uint64(time.Since(started).Milliseconds()))
	c.reconnections.Store(info.Reconnections)
	c.mu.Unlock()
	if c.hybrid != nil {
		c.hybrid.WebSocket.SetHeader(http.Header{"Authorization": {"Bearer " + auth.response.Token}})
	}
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
	if c.closed {
		c.mu.Unlock()
		return fmt.Errorf("connection is closed")
	}
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
	// Transport capabilities are negotiated at authentication time and a
	// renewal commonly omits them. Keep the established values so callers of
	// State do not see their security-capability state disappear between
	// renewals merely because the compact renewal response left it out.
	if out.TransportCapabilities == nil {
		out.TransportCapabilities = append([]string(nil), c.Response.TransportCapabilities...)
	}
	if out.RequiredTransportCapabilities == nil {
		out.RequiredTransportCapabilities = append([]string(nil), c.Response.RequiredTransportCapabilities...)
	}
	c.Response = out
	c.token = out.Token
	if out.TTLSeconds > 0 {
		c.expiresAt = time.Now().Add(time.Duration(out.TTLSeconds) * time.Second)
	} else {
		c.expiresAt = time.Time{}
	}
	c.latencyMillis.Store(uint64(time.Since(started).Milliseconds()))
	c.mu.Unlock()
	// hybrid is set once at connect and never reassigned (see the doc comment
	// on the var declaration in Connect), so reading it without c.mu is safe.
	// A dropped WebSocket carrier redials with whatever header was last set
	// here; without this, a redial after any renewal presents the token the
	// server just invalidated and 401s forever (see Bind.SetHeader).
	if c.hybrid != nil {
		c.hybrid.WebSocket.SetHeader(http.Header{"Authorization": {"Bearer " + out.Token}})
	}
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
	mux.HandleFunc("/history", func(w http.ResponseWriter, r *http.Request) {
		if !allowed(r) {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(c.webHistory())
	})
	mux.HandleFunc("/instructions", func(w http.ResponseWriter, r *http.Request) {
		if !allowed(r) {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(c.webInstructions())
	})
	mux.HandleFunc("/portal", func(w http.ResponseWriter, r *http.Request) {
		if !allowed(r) {
			http.NotFound(w, r)
			return
		}
		p, err := c.Portal(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(p)
	})
	mux.HandleFunc("/portal/action", func(w http.ResponseWriter, r *http.Request) {
		if !allowed(r) {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var in struct {
			Action   string `json:"action"`
			TargetID string `json:"target_id"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&in); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		c.executePortalAction(r.Context(), w, in.Action, in.TargetID)
	})
	mux.HandleFunc("/transport", func(w http.ResponseWriter, r *http.Request) {
		if !allowed(r) {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(c.TransportInfo())
			return
		}
		if r.Method == http.MethodPut || r.Method == http.MethodPost {
			var in struct {
				Transport string `json:"transport"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&in); err != nil {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			if err := c.SetTransport(in.Transport); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(c.TransportInfo())
			return
		}
		w.Header().Set("Allow", "GET, PUT, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})
	mux.HandleFunc("/tunnels/", func(w http.ResponseWriter, r *http.Request) {
		if !allowed(r) {
			http.NotFound(w, r)
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/tunnels/")
		if name, action, ok := strings.Cut(rest, "/browser/"); ok {
			// name feeds browserProfileKey into browseropen's profile-key
			// sanitizer, so "/" and ".." are already neutralized there, but
			// reject them here too as defense in depth for anything else
			// this path segment might later be used for.
			if name == "" || strings.Contains(name, "/") || strings.Contains(name, "..") {
				http.Error(w, "invalid tunnel name", http.StatusBadRequest)
				return
			}
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", http.MethodPost)
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			switch action {
			case "open":
				c.openTunnelBrowser(w, name)
			case "reset":
				c.resetTunnelBrowserProfile(w, name)
			default:
				http.NotFound(w, r)
			}
			return
		}
		if r.Method != http.MethodPut {
			w.Header().Set("Allow", http.MethodPut)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := rest
		if name == "" || strings.Contains(name, "/") {
			http.Error(w, "invalid tunnel name", http.StatusBadRequest)
			return
		}
		var in struct {
			LocalPort int    `json:"local_port"`
			LocalHost string `json:"local_host"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&in); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		address, err := c.ReplaceListener(name, in.LocalHost, in.LocalPort)
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
	ui := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	c.mu.Lock()
	c.ui = ui
	c.UIURL = "http://" + l.Addr().String() + "/?token=" + access
	c.mu.Unlock()
	go func() { _ = ui.Serve(l) }()
}

// WebTunnel is the live status of one tunnel on a running connect process,
// as reported by its local status UI's /status endpoint.
type WebTunnel struct {
	Name         string      `json:"name"`
	VirtualPort  int         `json:"virtual_port"`
	Description  string      `json:"description"`
	LocalAddress string      `json:"local_address"`
	Stats        TunnelStats `json:"stats"`
	TargetHint   string      `json:"target_hint,omitempty"`
	PACURL       string      `json:"pac_url,omitempty"`
	PACURLiOS    string      `json:"pac_url_ios,omitempty"`
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
	// "UDP direct", "WSS", or "UDP direct via relay reflector".
	ConnectionType  string                   `json:"connection_type"`
	Tunnels         []WebTunnel              `json:"tunnels"`
	TTLSeconds      int                      `json:"ttl_seconds"`
	LatencyMillis   uint64                   `json:"latency_millis"`
	Reconnections   uint64                   `json:"reconnections"`
	Paths           []wstransport.PathStatus `json:"paths,omitempty"`
	Duplication     bool                     `json:"duplication_active,omitempty"`
	Forced          string                   `json:"forced,omitempty"`
	ForcedEffective bool                     `json:"forced_effective,omitempty"`
	// RelayUDP is the most recently received UDP-relay hop-telemetry
	// summary from the server, when this session used that tier -- see
	// Connection.relayHopStats.
	RelayUDP      *protocol.UDPRelayHopStats `json:"relay_udp,omitempty"`
	PortalEnabled bool                       `json:"portal_enabled"`
	// SettingsURL mirrors Options.SettingsURL; empty when the caller (e.g.
	// the CLI) supplied none.
	SettingsURL string `json:"settings_url,omitempty"`
}

// ConnectionState is the complete typed, race-free state of a running
// connection. It is intended for long-lived callers such as ntwire-gui;
// unlike parsing log lines, it remains stable across log formatting changes
// and reports the current listener, authentication, transport, reconnect,
// expiry, and negotiated security state together.
type ConnectionState struct {
	Connected      bool                `json:"connected"`
	Server         string              `json:"server"`
	ServerName     string              `json:"server_name"`
	Authentication AuthenticationState `json:"authentication"`
	Tunnels        []ListenerState     `json:"tunnels"`
	Transport      TransportState      `json:"transport"`
	Reconnect      ReconnectState      `json:"reconnect"`
	Expiration     ExpirationState     `json:"expiration"`
	Security       SecurityState       `json:"security"`
	LatencyMillis  uint64              `json:"latency_millis"`
	Reconnections  uint64              `json:"reconnections"`
}

// AuthenticationState identifies the successful method without exposing the
// authenticated identity, session token, or any other credential.
type AuthenticationState struct {
	Method string `json:"method,omitempty"`
	Issuer string `json:"issuer,omitempty"`
}

// ListenerState is one granted tunnel and its actual local listener.
type ListenerState struct {
	Name         string      `json:"name"`
	VirtualPort  int         `json:"virtual_port"`
	Description  string      `json:"description"`
	LocalAddress string      `json:"local_address"`
	Stats        TunnelStats `json:"stats"`
	TargetHint   string      `json:"target_hint,omitempty"`
	PACURL       string      `json:"pac_url,omitempty"`
	PACURLiOS    string      `json:"pac_url_ios,omitempty"`
}

// TransportState reports both a stable route identifier and human-readable
// display text. Paths and Duplication are populated for multipath transport.
type TransportState struct {
	Mode            TransportMode            `json:"mode"`
	Description     string                   `json:"description"`
	Reason          string                   `json:"reason,omitempty"`
	Paths           []wstransport.PathStatus `json:"paths,omitempty"`
	Duplication     bool                     `json:"duplication_active,omitempty"`
	Forced          string                   `json:"forced,omitempty"`
	ForcedEffective bool                     `json:"forced_effective,omitempty"`
	// RelayUDP mirrors WebStatus.RelayUDP -- see Connection.relayHopStats.
	RelayUDP *protocol.UDPRelayHopStats `json:"relay_udp,omitempty"`
}

// ReconnectState describes an in-progress control-plane recovery. RetryAt is
// omitted when the connection is healthy; LastError is deliberately a value,
// not a log-derived inference.
type ReconnectState struct {
	Reconnecting bool       `json:"reconnecting"`
	Attempts     uint64     `json:"attempts"`
	RetryAt      *time.Time `json:"retry_at,omitempty"`
	LastError    string     `json:"last_error,omitempty"`
}

// ExpirationState is refreshed after every successful authentication or
// renewal. ExpiresAt is omitted for legacy/test connections without a TTL.
type ExpirationState struct {
	TTLSeconds int        `json:"ttl_seconds"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// SecurityState contains only non-secret, negotiated or explicitly enabled
// client security capabilities. It never includes tokens, identities, keys,
// or TLS material.
type SecurityState struct {
	TransportCapabilities         []string `json:"transport_capabilities,omitempty"`
	RequiredTransportCapabilities []string `json:"required_transport_capabilities,omitempty"`
	InsecureTLS                   bool     `json:"insecure_tls"`
	ListenerBindAddress           string   `json:"listener_bind_address,omitempty"`
}

// State returns a complete race-free snapshot for API consumers. Callers must
// treat the returned slices as their own copy.
func (c *Connection) State() ConnectionState {
	c.mu.Lock()
	defer c.mu.Unlock()
	granted := c.grantedByName()
	tunnels := make([]ListenerState, 0, len(c.tunnels))
	for _, t := range c.tunnels {
		g := granted[t.name]
		ls := ListenerState{Name: t.name, VirtualPort: t.virtualPort, Description: g.Description, LocalAddress: t.localAddr, Stats: t.stats(), TargetHint: g.TargetHint}
		if g.TargetHint == "socks" {
			ls.PACURL = pac.URLForPlatform(c.base, t.name, false)
			ls.PACURLiOS = pac.URLForPlatform(c.base, t.name, true)
		}
		tunnels = append(tunnels, ls)
	}
	transport := connectionTransport(c.transport.Load())
	state := ConnectionState{
		Connected:      c.Stack != nil,
		Server:         c.base,
		ServerName:     c.displayName(),
		Authentication: AuthenticationState{Method: c.method, Issuer: c.issuer},
		Tunnels:        tunnels,
		Transport: TransportState{
			Mode: transport.mode(), Description: transport.String(), Reason: c.transportReason,
		},
		Reconnect:     c.reconnectState,
		Expiration:    ExpirationState{TTLSeconds: c.Response.TTLSeconds},
		Security:      SecurityState{TransportCapabilities: append([]string(nil), c.Response.TransportCapabilities...), RequiredTransportCapabilities: append([]string(nil), c.Response.RequiredTransportCapabilities...), InsecureTLS: c.options.Insecure, ListenerBindAddress: c.bindAddr},
		LatencyMillis: c.latencyMillis.Load(),
		Reconnections: c.reconnections.Load(),
	}
	if c.reconnectState.RetryAt != nil {
		t := *c.reconnectState.RetryAt
		state.Reconnect.RetryAt = &t
	}
	if !c.expiresAt.IsZero() {
		expiresAt := c.expiresAt
		state.Expiration.ExpiresAt = &expiresAt
	}
	if c.multipath != nil {
		state.Transport.Paths = append([]wstransport.PathStatus(nil), c.multipath.Paths()...)
		primary, _, dup := c.multipath.Scheduler().Select()
		if primary != "" {
			state.Transport.Description = multipathDescription(primary)
		}
		state.Transport.Duplication = dup
		state.Transport.Forced = c.multipath.Forced()
		if state.Transport.Forced != "" && primary == state.Transport.Forced {
			state.Transport.ForcedEffective = true
		}
	}
	state.Transport.RelayUDP = c.relayHopStats.Load()
	return state
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
		g := granted[t.name]
		wt := WebTunnel{Name: t.name, VirtualPort: t.virtualPort, LocalAddress: t.localAddr, Stats: t.stats(), Description: g.Description, TargetHint: g.TargetHint}
		if g.TargetHint == "socks" {
			wt.PACURL = pac.URLForPlatform(c.base, t.name, false)
			wt.PACURLiOS = pac.URLForPlatform(c.base, t.name, true)
		}
		tunnels = append(tunnels, wt)
	}
	status := WebStatus{Connected: c.Stack != nil, Server: c.base, ServerName: c.displayName(), ConnectionType: connectionTransport(c.transport.Load()).String(), Tunnels: tunnels, TTLSeconds: c.Response.TTLSeconds, LatencyMillis: c.latencyMillis.Load(), Reconnections: c.reconnections.Load(), PortalEnabled: c.Response.PortalEnabled, SettingsURL: c.options.SettingsURL}
	if c.multipath != nil {
		status.Paths = c.multipath.Paths()
		primary, _, dup := c.multipath.Scheduler().Select()
		if primary != "" {
			status.ConnectionType = multipathDescription(primary)
		}
		status.Duplication = dup
		status.Forced = c.multipath.Forced()
		if status.Forced != "" && primary == status.Forced {
			status.ForcedEffective = true
		}
	}
	status.RelayUDP = c.relayHopStats.Load()
	return status
}

func multipathDescription(primary string) string {
	switch primary {
	case string(wstransport.PathDirect):
		return "UDP direct"
	case string(wstransport.PathUDPRelay):
		return "UDP via relay"
	case string(wstransport.PathWSS):
		// A WebSocket candidate can terminate at the server itself or at a
		// relay. Path selection alone does not establish which, so keep this
		// label route-neutral.
		return "WSS"
	default:
		return "Transport unavailable"
	}
}

// SetTransport overrides the active transport selection at runtime ("auto",
// "direct-udp", "udp-relay", "wss", or aliases "udp", "relay", "websocket").
// When a forced transport is set and healthy, it is immediately selected as
// primary. If it is unavailable or becomes unhealthy, ntwire automatically falls
// back to the best available healthy transport.
func (c *Connection) SetTransport(target string) error {
	normalized, err := wstransport.ValidateTransportName(target)
	if err != nil {
		return err
	}
	c.mu.Lock()
	multipath := c.multipath
	c.mu.Unlock()
	if multipath == nil {
		return errors.New("multipath transport is not active for this connection")
	}
	multipath.SetForced(normalized)
	return nil
}

// TransportInfo describes the live transport configuration and candidate states.
type TransportInfo struct {
	Active          string                   `json:"active"`
	Forced          string                   `json:"forced,omitempty"`
	ForcedEffective bool                     `json:"forced_effective"`
	Paths           []wstransport.PathStatus `json:"paths,omitempty"`
}

func (c *Connection) TransportInfo() TransportInfo {
	c.mu.Lock()
	multipath := c.multipath
	c.mu.Unlock()
	if multipath == nil {
		return TransportInfo{Active: connectionTransport(c.transport.Load()).String()}
	}
	paths := multipath.Paths()
	primary, _, _ := multipath.Scheduler().Select()
	forced := multipath.Forced()
	effective := false
	if forced != "" && primary == forced {
		effective = true
	}
	return TransportInfo{
		Active:          primary,
		Forced:          forced,
		ForcedEffective: effective,
		Paths:           paths,
	}
}

// historySampleInterval is how often historyLoop records a sample. The
// local status UI's charts assume samples are evenly spaced at this
// interval when mapping a sample's index to elapsed time, so this is the
// one place that cadence is allowed to change.
const historySampleInterval = 5 * time.Second

// historySampleLimit bounds Connection.history to five minutes of samples
// at historySampleInterval.
const historySampleLimit = int(5 * time.Minute / historySampleInterval)

// WebHistorySample is one point-in-time snapshot in a running connect
// process's history, as reported by its local status UI's /history
// endpoint. It is recorded independently of any browser polling (see
// Connection.historyLoop), so a freshly opened status UI tab can render up
// to five minutes of history immediately instead of starting empty.
type WebHistorySample struct {
	Time time.Time `json:"time"`
	// Connected is true only when the control-plane session is both
	// established and not currently reconnecting -- see
	// Connection.recordHistorySample. Charts use it to mark periods the
	// connection was down.
	Connected      bool        `json:"connected"`
	ConnectionType string      `json:"connection_type"`
	LatencyMillis  uint64      `json:"latency_millis"`
	Tunnels        []WebTunnel `json:"tunnels"`
}

// WebHistory is the local status UI's GET /history response: the current
// contents of Connection.history, oldest first.
type WebHistory struct {
	Samples []WebHistorySample `json:"samples"`
}

// recordHistorySample appends one snapshot to the ring buffer, trimming to
// historySampleLimit. It is safe to call from any goroutine.
func (c *Connection) recordHistorySample() {
	status := c.webStatus()
	c.mu.Lock()
	reconnecting := c.reconnectState.Reconnecting
	c.mu.Unlock()
	sample := WebHistorySample{
		Time:           time.Now(),
		Connected:      status.Connected && !reconnecting,
		ConnectionType: status.ConnectionType,
		LatencyMillis:  status.LatencyMillis,
		Tunnels:        status.Tunnels,
	}
	c.historyMu.Lock()
	c.history = append(c.history, sample)
	if over := len(c.history) - historySampleLimit; over > 0 {
		c.history = c.history[over:]
	}
	c.historyMu.Unlock()
}

// webHistory returns a copy of the current history ring buffer, as served
// at GET /history.
func (c *Connection) webHistory() WebHistory {
	c.historyMu.Lock()
	defer c.historyMu.Unlock()
	return WebHistory{Samples: append([]WebHistorySample(nil), c.history...)}
}

// historyLoop records one status snapshot immediately, then again on every
// historySampleInterval tick until Close -- the same <-c.stop shutdown
// pattern renewLoop uses, so this goroutine never outlives the connection.
func (c *Connection) historyLoop() {
	c.recordHistorySample()
	t := time.NewTicker(historySampleInterval)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			c.recordHistorySample()
		}
	}
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

// socksTunnelLocalAddr returns the bound loopback address of the named
// tunnel, or an error naming why it can't back a browser proxy: unknown
// name, or a tunnel that isn't a browser-capable SOCKS proxy -- opening a plain
// port-forward tunnel as a browser's proxy would silently break it.
func (c *Connection) socksTunnelLocalAddr(name string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	granted := c.grantedByName()
	for _, t := range c.tunnels {
		if t.name != name {
			continue
		}
		if !protocol.IsBrowserSocksTarget(granted[t.name].TargetHint) {
			return "", fmt.Errorf("tunnel %q is not a SOCKS proxy", name)
		}
		return t.localAddr, nil
	}
	return "", fmt.Errorf("unknown tunnel %q", name)
}

// browserProfileKey returns the browseropen profile key used by the "Open
// in browser" / "Reset browser profile" buttons for the named SOCKS
// tunnel. When Options.Profile is set (e.g. from a GUI profile), it is
// namespaced as "<profile>-<tunnel>" matching the tray menu; otherwise it
// falls back to "client-<tunnel>".
func (c *Connection) browserProfileKey(name string) string {
	if c != nil && c.options.Profile != "" {
		return c.options.Profile + "-" + name
	}
	return "client-" + name
}

// openTunnelBrowser backs POST /tunnels/{name}/browser/open: it launches an
// isolated Chromium-family browser proxied through the named SOCKS
// tunnel's local listener.
func (c *Connection) openTunnelBrowser(w http.ResponseWriter, name string) {
	addr, err := c.socksTunnelLocalAddr(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := openSocksBrowser(c.browserProfileKey(name), addr); err != nil {
		http.Error(w, "cannot open browser: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// resetTunnelBrowserProfile backs POST /tunnels/{name}/browser/reset: it
// deletes the named SOCKS tunnel's isolated browser profile directory, so
// the next "Open in browser" starts with no cached cookies, site data, or
// saved credentials.
func (c *Connection) resetTunnelBrowserProfile(w http.ResponseWriter, name string) {
	if _, err := c.socksTunnelLocalAddr(name); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := browseropen.CleanProfile(c.browserProfileKey(name)); err != nil {
		http.Error(w, "cannot reset browser profile: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Portal fetches the rendered portal and authorized target context from the server.
func (c *Connection) Portal(ctx context.Context) (*portal.RenderedPortal, error) {
	c.mu.Lock()
	serverURL := c.base
	token := c.token
	httpClient := c.http
	c.mu.Unlock()

	if serverURL == "" || token == "" || httpClient == nil {
		return nil, fmt.Errorf("client is not connected")
	}

	reqURL := strings.TrimRight(serverURL, "/") + "/v1/portal?mode=native"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch portal: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("server returned %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}

	var res portal.RenderedPortal
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("decode portal response: %w", err)
	}
	return &res, nil
}

// portalAction resolves an action with the server, which is the authority for
// the target's authorization and configured launch URL.
func (c *Connection) portalAction(ctx context.Context, action, targetID string) (*portal.ActionResolution, error) {
	c.mu.Lock()
	serverURL := c.base
	token := c.token
	httpClient := c.http
	c.mu.Unlock()

	if serverURL == "" || token == "" || httpClient == nil {
		return nil, fmt.Errorf("client is not connected")
	}

	body, err := json.Marshal(portal.ActionRequest{Action: action, TargetID: targetID})
	if err != nil {
		return nil, fmt.Errorf("encode portal action: %w", err)
	}
	reqURL := strings.TrimRight(serverURL, "/") + "/v1/portal/action"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute portal action: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("server returned %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}

	var res portal.ActionResolution
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("decode portal action response: %w", err)
	}
	return &res, nil
}

func (c *Connection) executePortalAction(ctx context.Context, w http.ResponseWriter, action, targetID string) {
	if targetID == "" {
		http.Error(w, "target_id is required", http.StatusBadRequest)
		return
	}
	if action != portal.ActionOpen && action != portal.ActionBrowser {
		http.Error(w, "unsupported action", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	tunnels := c.tunnels
	c.mu.Unlock()

	var matchedTunnel *localTunnel
	for _, t := range tunnels {
		if strings.EqualFold(t.name, targetID) {
			matchedTunnel = t
			break
		}
	}
	if matchedTunnel == nil {
		http.Error(w, fmt.Sprintf("target %q is not authorized", targetID), http.StatusForbidden)
		return
	}
	resolution, err := c.portalAction(ctx, action, targetID)
	if err != nil {
		http.Error(w, "cannot resolve portal action: "+err.Error(), http.StatusBadGateway)
		return
	}
	if !resolution.Authorized {
		http.Error(w, fmt.Sprintf("target %q is not authorized", targetID), http.StatusForbidden)
		return
	}
	targetURL := resolution.URL

	// Determine SOCKS local proxy address
	var socksAddr string
	for _, t := range tunnels {
		if addr, err := c.socksTunnelLocalAddr(t.name); err == nil {
			socksAddr = addr
			break
		}
	}

	if socksAddr != "" {
		if err := openSocksBrowser(c.browserProfileKey(targetID), socksAddr, targetURL); err != nil {
			http.Error(w, "cannot open browser: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else if targetURL != "" {
		if err := openBrowser(targetURL); err != nil {
			http.Error(w, "cannot open URL: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "no SOCKS proxy or URL available for target", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
		data := instructions.Data{
			Name: t.name, Description: g.Description,
			LocalAddress: net.JoinHostPort(instructionHost, port), LocalHost: instructionHost, LocalPort: p,
			VirtualPort: t.virtualPort, TargetHint: g.TargetHint,
			TunnelIP: c.Response.TunnelIP, ServerTunnelIP: c.Response.ServerTunnelIP,
			Server: c.base,
			Client: portal.NormalizeClient(portal.ClientContext{OS: runtime.GOOS, Arch: runtime.GOARCH, Type: "ntwire", Version: buildinfo.String(), Capabilities: portal.ClientCapabilities{LaunchBrowserWithSocks: true}}, "native"),
		}
		if g.TargetHint == "socks" {
			data.PACURL = pac.URLForPlatform(c.base, t.name, false)
			data.PACURLiOS = pac.URLForPlatform(c.base, t.name, true)
		}
		wi.Blocks = instructions.Render(g.Instructions, data)
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
			if tunnel.socks {
				c.forwardSocksUDPAssociate(tunnel, in, target)
				return
			}
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

// forwardUDP mirrors forward for a datagram tunnel. A connected netstack UDP
// socket per local source tuple preserves reply isolation and lets applications
// use independent ephemeral UDP ports concurrently.
func (c *Connection) forwardUDP(tunnel *localTunnel, pc net.PacketConn, target string, idle time.Duration) {
	if idle <= 0 {
		idle = 2 * time.Minute
	}
	type flow struct{ conn net.Conn }
	flows := map[string]flow{}
	var mu sync.Mutex
	defer func() {
		mu.Lock()
		for _, f := range flows {
			_ = f.conn.Close()
		}
		mu.Unlock()
	}()
	for {
		buf := make([]byte, 65535)
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		key := src.String()
		mu.Lock()
		f, ok := flows[key]
		mu.Unlock()
		if !ok {
			c.mu.Lock()
			stack := c.Stack
			c.mu.Unlock()
			if stack == nil {
				continue
			}
			out, e := stack.DialContext(context.Background(), "udp", target)
			if e != nil {
				continue
			}
			f = flow{conn: out}
			mu.Lock()
			flows[key] = f
			mu.Unlock()
			tunnel.connections.Add(1)
			tunnel.active.Add(1)
			go func(key string, src net.Addr, out net.Conn) {
				defer tunnel.active.Add(-1)
				defer out.Close()
				defer func() { mu.Lock(); delete(flows, key); mu.Unlock() }()
				b := make([]byte, 65535)
				for {
					_ = out.SetReadDeadline(time.Now().Add(idle))
					n, e := out.Read(b)
					if e != nil {
						return
					}
					if _, e = pc.WriteTo(b[:n], src); e != nil {
						return
					}
					tunnel.fromTunnel.Add(uint64(n))
				}
			}(key, src, out)
		}
		if n, e := f.conn.Write(buf[:n]); e == nil {
			tunnel.toTunnel.Add(uint64(n))
		}
	}
}

// forwardSocksUDPAssociate passes normal SOCKS sessions through unchanged,
// but rewrites a UDP ASSOCIATE reply to a loopback relay owned by this client.
// Applications must never be told the server's virtual-only UDP address.
func (c *Connection) forwardSocksUDPAssociate(tunnel *localTunnel, in net.Conn, target string) {
	c.mu.Lock()
	stack := c.Stack
	c.mu.Unlock()
	if stack == nil {
		return
	}
	out, err := stack.DialContext(context.Background(), "tcp", target)
	if err != nil {
		return
	}
	defer out.Close()
	tunnel.connections.Add(1)
	tunnel.active.Add(1)
	defer tunnel.active.Add(-1)
	br := bufio.NewReader(in)
	first, err := br.ReadByte()
	if err != nil {
		return
	}
	if first != 5 {
		_, _ = out.Write([]byte{first})
		go io.Copy(countingWriter{w: out, counter: &tunnel.toTunnel}, br)
		io.Copy(countingWriter{w: in, counter: &tunnel.fromTunnel}, out)
		return
	}
	n, err := br.ReadByte()
	if err != nil {
		return
	}
	methods := make([]byte, n)
	if _, err = io.ReadFull(br, methods); err != nil {
		return
	}
	greeting := append([]byte{5, n}, methods...)
	if _, err = out.Write(greeting); err != nil {
		return
	}
	reply := make([]byte, 2)
	if _, err = io.ReadFull(out, reply); err != nil {
		return
	}
	if _, err = in.Write(reply); err != nil || reply[1] != 0 {
		return
	}
	h := make([]byte, 4)
	if _, err = io.ReadFull(br, h); err != nil {
		return
	}
	req := append([]byte(nil), h...)
	addrLen := 0
	switch h[3] {
	case 1:
		addrLen = 4
	case 4:
		addrLen = 16
	case 3:
		l, e := br.ReadByte()
		if e != nil {
			return
		}
		req = append(req, l)
		addrLen = int(l)
	default:
		return
	}
	rest := make([]byte, addrLen+2)
	if _, err = io.ReadFull(br, rest); err != nil {
		return
	}
	req = append(req, rest...)
	if _, err = out.Write(req); err != nil {
		return
	}
	// Replies are 10 bytes for IPv4 or 22 bytes for IPv6. The association
	// handler always returns a numeric virtual address.
	rh := make([]byte, 4)
	if _, err = io.ReadFull(out, rh); err != nil {
		return
	}
	rl := 4
	if rh[3] == 4 {
		rl = 16
	}
	rr := make([]byte, rl+2)
	if _, err = io.ReadFull(out, rr); err != nil {
		return
	}
	serverReply := append(rh, rr...)
	if h[1] != 3 || rh[1] != 0 {
		_, _ = in.Write(serverReply)
		go io.Copy(countingWriter{w: out, counter: &tunnel.toTunnel}, br)
		io.Copy(countingWriter{w: in, counter: &tunnel.fromTunnel}, out)
		return
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return
	}
	defer pc.Close()
	// The remote endpoint is the address supplied by the server reply.
	remote, ok := socksReplyAddr(serverReply)
	if !ok {
		return
	}
	uc, err := stack.DialContext(context.Background(), "udp", remote)
	if err != nil {
		return
	}
	defer uc.Close()
	local := pc.LocalAddr().(*net.UDPAddr)
	a := local.AddrPort()
	outReply := socksUDPReply(a)
	if _, err = in.Write(outReply); err != nil {
		return
	}
	var sourceMu sync.RWMutex
	var source net.Addr
	go func() {
		b := make([]byte, 65535)
		for {
			n, src, e := pc.ReadFrom(b)
			if e != nil {
				return
			}
			if _, e = uc.Write(b[:n]); e != nil {
				return
			}
			tunnel.toTunnel.Add(uint64(n))
			sourceMu.Lock()
			source = src
			sourceMu.Unlock()
		}
	}()
	go func() {
		b := make([]byte, 65535)
		for {
			n, e := uc.Read(b)
			if e != nil {
				return
			}
			sourceMu.RLock()
			dst := source
			sourceMu.RUnlock()
			if dst != nil {
				if _, e := pc.WriteTo(b[:n], dst); e == nil {
					tunnel.fromTunnel.Add(uint64(n))
				}
			}
		}
	}()
	_, _ = io.Copy(io.Discard, br)
}

func socksReplyAddr(b []byte) (string, bool) {
	if len(b) < 10 {
		return "", false
	}
	if b[3] == 1 {
		return net.JoinHostPort(net.IP(b[4:8]).String(), fmt.Sprint(uint16(b[8])<<8|uint16(b[9]))), true
	}
	if b[3] == 4 && len(b) >= 22 {
		return net.JoinHostPort(net.IP(b[4:20]).String(), fmt.Sprint(uint16(b[20])<<8|uint16(b[21]))), true
	}
	return "", false
}
func socksUDPReply(ap netip.AddrPort) []byte {
	ip := ap.Addr().Unmap()
	a := ip.As4()
	return []byte{5, 0, 0, 1, a[0], a[1], a[2], a[3], byte(ap.Port() >> 8), byte(ap.Port())}
}
func (c *Connection) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	h, token, base := c.http, c.token, c.base
	tunnels, ui, stack := c.tunnels, c.ui, c.Stack
	c.tunnels, c.ui, c.Stack = nil, nil, nil
	statusFile := c.statusFile
	if statusFile == "" {
		statusFile = DefaultStatusFile()
	}
	if c.stop != nil {
		select {
		case <-c.stop:
		default:
			close(c.stop)
		}
	}
	c.mu.Unlock()
	c.transitionTransport(nextTransportState(transportStateStopped, transportShutdown, false), "connection closed")

	// Best effort: expiry remains the server-side safety net if this cannot be
	// delivered (for example after a network outage). Never hold c.mu while
	// doing I/O: renewal/reconnect and status readers must be able to observe
	// shutdown immediately. Bound the request so Close cannot hang forever on
	// a vanished server.
	if h != nil && token != "" {
		ctx, cancel := context.WithTimeout(context.Background(), closeDisconnectTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/disconnect", nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := h.Do(req)
			if err == nil && resp != nil {
				_ = resp.Body.Close()
			}
		}
	}
	for _, t := range tunnels {
		if t.listener != nil {
			_ = t.listener.Close()
		}
		if t.packetConn != nil {
			_ = t.packetConn.Close()
		}
	}
	if ui != nil {
		_ = ui.Close()
	}
	if statusFile != "" {
		_ = os.Remove(statusFile)
	}
	if stack != nil {
		_ = stack.Close()
	}
}
