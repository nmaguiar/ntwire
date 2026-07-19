// Package client implements the HTTPS authentication side of nwire.
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
	"fmt"
	"github.com/nmaguiar/nwire/pkg/client/webui"
	"github.com/nmaguiar/nwire/pkg/protocol"
	"github.com/nmaguiar/nwire/pkg/sshkey"
	"github.com/nmaguiar/nwire/pkg/wgnet"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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
	return protocol.ClientInfo{OS: runtime.GOOS, Arch: runtime.GOARCH, Hostname: h, Username: u, ClientVersion: "dev", Extra: map[string]string{}}
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
}

// UnknownCertificateError is returned for a server that has not yet been
// pinned in known_servers. Call TrustServer and retry after user confirmation.
type UnknownCertificateError struct{ Host, Fingerprint string }

func (e *UnknownCertificateError) Error() string {
	return fmt.Sprintf("unknown server certificate for %s (%s)", e.Host, e.Fingerprint)
}

func defaultKnownServersFile() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(h, ".nwire", "known_servers")
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
		return http.DefaultClient, nil
	}
	if o.Insecure {
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}}}, nil
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
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}}, nil
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
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, VerifyConnection: func(cs tls.ConnectionState) error { // #nosec G402 -- verification is the pin below
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("server supplied no certificate")
		}
		s := sha256.Sum256(cs.PeerCertificates[0].Raw)
		fp := "SHA256:" + base64.RawStdEncoding.EncodeToString(s[:])
		if v.Servers[host] != fp {
			return &UnknownCertificateError{Host: host, Fingerprint: fp}
		}
		return nil
	}}}}, nil
}

func AuthenticateWithOptions(url, keyPath string, info protocol.ClientInfo, options Options) (protocol.AuthResponse, error) {
	k, err := wgnet.GenerateKey()
	if err != nil {
		return protocol.AuthResponse{}, err
	}
	h, err := httpClient(url, options)
	if err != nil {
		return protocol.AuthResponse{}, err
	}
	return authenticate(h, url, keyPath, info, k.Public)
}
func authenticate(h *http.Client, url, keyPath string, info protocol.ClientInfo, wgPublic string) (protocol.AuthResponse, error) {
	pub, err := sshkey.PublicFromPrivate(keyPath)
	if err != nil {
		return protocol.AuthResponse{}, err
	}
	n := make([]byte, 32)
	if _, err = rand.Read(n); err != nil {
		return protocol.AuthResponse{}, err
	}
	r := protocol.AuthRequest{Version: protocol.Version, PublicKey: pub, WireGuardPublicKey: wgPublic, Timestamp: time.Now().UTC().Format(time.RFC3339), Nonce: base64.RawURLEncoding.EncodeToString(n), Info: info}
	p, err := protocol.SigningPayload(r)
	if err != nil {
		return protocol.AuthResponse{}, err
	}
	r.Signature, err = sshkey.SignFile(keyPath, p)
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
		return protocol.AuthResponse{}, fmt.Errorf("authentication failed: %s", resp.Status)
	}
	var out protocol.AuthResponse
	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}

// Connection is a persistent, local-listener view of one WireGuard session.
type Connection struct {
	Response       protocol.AuthResponse
	Stack          *wgnet.Stack
	listeners      []net.Listener
	LocalAddresses []string
	token, base    string
	mu             sync.Mutex
	info           protocol.ClientInfo
	http           *http.Client
	ports          map[string]int
	stop           chan struct{}
	ui             *http.Server
	UIURL          string
}

func Connect(url, keyPath string, info protocol.ClientInfo, ports map[string]int) (*Connection, error) {
	return ConnectWithOptions(url, keyPath, info, Options{Ports: ports})
}

func ConnectWithOptions(url, keyPath string, info protocol.ClientInfo, options Options) (*Connection, error) {
	key, err := wgnet.GenerateKey()
	if err != nil {
		return nil, err
	}
	h, err := httpClient(url, options)
	if err != nil {
		return nil, err
	}
	r, err := authenticate(h, url, keyPath, info, key.Public)
	if err != nil {
		return nil, err
	}
	clientIP, err := netip.ParseAddr(r.TunnelIP)
	if err != nil {
		return nil, fmt.Errorf("server did not return a tunnel IP: %w", err)
	}
	st, err := wgnet.New(wgnet.Config{PrivateKey: key.Private, Addresses: []netip.Addr{clientIP}})
	if err != nil {
		return nil, err
	}
	endpoint := r.UDP
	if endpoint == "" {
		st.Close()
		return nil, fmt.Errorf("server did not advertise a WireGuard endpoint")
	}
	serverIP := clientIP
	a := serverIP.As4()
	a[3] = 1
	serverIP = netip.AddrFrom4(a)
	if err = st.AddPeer(wgnet.Endpoint{PublicKey: r.ServerPublicKey, Address: "0.0.0.0/0@" + endpoint}); err != nil {
		st.Close()
		return nil, err
	}
	c := &Connection{Response: r, Stack: st, token: r.Token, base: strings.TrimRight(url, "/"), info: info, http: h, ports: options.Ports, stop: make(chan struct{})}
	for _, t := range r.Tunnels {
		p := options.Ports[t.Name]
		addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(p))
		l, e := net.Listen("tcp", addr)
		if e != nil {
			c.Close()
			return nil, e
		}
		c.listeners = append(c.listeners, l)
		c.LocalAddresses = append(c.LocalAddresses, l.Addr().String())
		go c.forward(l, net.JoinHostPort(serverIP.String(), fmt.Sprint(t.VirtualPort)))
	}
	go c.renewLoop()
	c.startWebUI()
	if !options.NoWebUI && c.UIURL != "" {
		openBrowser(c.UIURL)
	}
	return c, nil
}

func (c *Connection) renewLoop() {
	for {
		c.mu.Lock()
		ttl := c.Response.TTLSeconds
		c.mu.Unlock()
		if ttl <= 0 {
			ttl = 60
		}
		d := time.Duration(ttl) * time.Second * 2 / 3
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
			if err := c.renew(); err == nil {
				break
			}
			select {
			case <-c.stop:
				return
			case <-time.After(delay):
			}
		}
	}
}

func (c *Connection) renew() error {
	b, _ := json.Marshal(protocol.RenewRequest{Info: c.info})
	c.mu.Lock()
	token := c.token
	c.mu.Unlock()
	req, err := http.NewRequest(http.MethodPost, c.base+"/v1/renew", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
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
	c.Response = out
	c.token = out.Token
	c.mu.Unlock()
	return nil
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
		c.mu.Lock()
		defer c.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"connected": c.Stack != nil, "tunnels": c.Response.Tunnels, "local_addresses": c.LocalAddresses, "ttl_seconds": c.Response.TTLSeconds})
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

func openBrowser(url string) {
	var command string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		command, args = "open", []string{url}
	case "windows":
		command, args = "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default:
		command, args = "xdg-open", []string{url}
	}
	if err := exec.Command(command, args...).Start(); err != nil {
		return
	}
}
func (c *Connection) forward(l net.Listener, target string) {
	for {
		in, e := l.Accept()
		if e != nil {
			return
		}
		go func() {
			defer in.Close()
			out, e := c.Stack.DialContext(context.Background(), "tcp", target)
			if e != nil {
				return
			}
			defer out.Close()
			go io.Copy(out, in)
			io.Copy(in, out)
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
	for _, l := range c.listeners {
		_ = l.Close()
	}
	c.listeners = nil
	select {
	case <-c.stop:
	default:
		close(c.stop)
	}
	if c.ui != nil {
		_ = c.ui.Close()
	}
	if c.Stack != nil {
		_ = c.Stack.Close()
		c.Stack = nil
	}
}
