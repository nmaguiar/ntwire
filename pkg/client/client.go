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
	"fmt"
	"github.com/nmaguiar/ntwire/pkg/client/webui"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
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
	"sync/atomic"
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
	StatusFile       string
	UseWebSocket     bool
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
	name        string
	virtualPort int
	listener    net.Listener
	localAddr   string
	target      string
	toTunnel    atomic.Uint64
	fromTunnel  atomic.Uint64
	connections atomic.Uint64
	active      atomic.Int64
}

func (t *localTunnel) stats() TunnelStats {
	return TunnelStats{BytesToTunnel: t.toTunnel.Load(), BytesFromTunnel: t.fromTunnel.Load(), Connections: t.connections.Load(), Active: t.active.Load()}
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
	stackConfig := wgnet.Config{PrivateKey: key.Private, Addresses: []netip.Addr{clientIP}}
	if options.UseWebSocket {
		if r.WebSocket == "" {
			return nil, fmt.Errorf("server did not advertise a WebSocket endpoint")
		}
		stackConfig.Bind = wstransport.NewClient(r.WebSocket, h, http.Header{"Authorization": {"Bearer " + r.Token}})
	}
	st, err := wgnet.New(stackConfig)
	if err != nil {
		return nil, err
	}
	endpoint := r.UDP
	if options.UseWebSocket {
		endpoint = "0.0.0.0:0"
	}
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
	c := &Connection{Response: r, Stack: st, token: r.Token, base: strings.TrimRight(url, "/"), info: info, http: h, ports: options.Ports, stop: make(chan struct{}), statusFile: options.StatusFile, keyPath: keyPath}
	for _, t := range r.Tunnels {
		p := options.Ports[t.Name]
		if p < 0 || p > 65535 {
			c.Close()
			return nil, fmt.Errorf("invalid local port for tunnel %q", t.Name)
		}
		addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(p))
		l, e := net.Listen("tcp", addr)
		if e != nil {
			c.Close()
			return nil, e
		}
		target := net.JoinHostPort(serverIP.String(), fmt.Sprint(t.VirtualPort))
		lt := &localTunnel{name: t.Name, virtualPort: t.VirtualPort, listener: l, localAddr: l.Addr().String(), target: target}
		c.tunnels = append(c.tunnels, lt)
		c.LocalAddresses = append(c.LocalAddresses, l.Addr().String())
		go c.forward(lt, l, target)
	}
	go c.renewLoop()
	c.startWebUI()
	if !options.NoWebUI && c.UIURL != "" {
		openBrowser(c.UIURL)
	}
	if err := c.writeCurrentStatus(); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// ReplacePort atomically switches a tunnel to a new loopback listener. Existing
// connections continue on the old listener while new connections use the port.
func (c *Connection) ReplacePort(name string, port int) (string, error) {
	if name == "" || port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid tunnel name or local port")
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

	l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
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
	s := Status{PID: os.Getpid(), Server: c.base, UIURL: c.UIURL, LocalAddresses: append([]string(nil), c.LocalAddresses...)}
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
			if err := c.renew(); err == nil || c.reconnect() == nil {
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
	c.mu.Unlock()
	r, err := authenticate(c.http, c.base, c.keyPath, c.info, public)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.Response = r
	c.token = r.Token
	c.mu.Unlock()
	return nil
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
		_ = json.NewEncoder(w).Encode(c.webStatus())
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

type webTunnel struct {
	Name         string      `json:"name"`
	VirtualPort  int         `json:"virtual_port"`
	Description  string      `json:"description"`
	LocalAddress string      `json:"local_address"`
	Stats        TunnelStats `json:"stats"`
}

func (c *Connection) webStatus() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	tunnels := make([]webTunnel, 0, len(c.tunnels))
	for i, t := range c.tunnels {
		wt := webTunnel{Name: t.name, VirtualPort: t.virtualPort, LocalAddress: t.localAddr, Stats: t.stats()}
		if i < len(c.Response.Tunnels) {
			wt.Description = c.Response.Tunnels[i].Description
		}
		tunnels = append(tunnels, wt)
	}
	return map[string]any{"connected": c.Stack != nil, "tunnels": tunnels, "ttl_seconds": c.Response.TTLSeconds}
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
func (c *Connection) forward(tunnel *localTunnel, listener net.Listener, target string) {
	for {
		in, e := listener.Accept()
		if e != nil {
			return
		}
		go func() {
			defer in.Close()
			tunnel.connections.Add(1)
			tunnel.active.Add(1)
			defer tunnel.active.Add(-1)
			c.mu.Lock()
			stack := c.Stack
			c.mu.Unlock()
			if stack == nil {
				return
			}
			out, e := stack.DialContext(context.Background(), "tcp", target)
			if e != nil {
				return
			}
			defer out.Close()
			go func() { n, _ := io.Copy(out, in); tunnel.toTunnel.Add(uint64(n)) }()
			n, _ := io.Copy(in, out)
			tunnel.fromTunnel.Add(uint64(n))
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
