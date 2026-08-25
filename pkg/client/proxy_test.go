package client

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	urlpkg "net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"golang.zx2c4.com/wireguard/conn"
)

type socks5Request struct {
	Atyp     byte
	Host     string
	IP       net.IP
	Port     int
	AuthUser string
	AuthPass string
}

type testSOCKS5Server struct {
	listener net.Listener
	mu       sync.Mutex
	requests []socks5Request
	conns    []net.Conn
	user     string
	pass     string
	closed   bool
	done     chan struct{}
}

func startTestSOCKS5Server(t *testing.T, user, pass string) *testSOCKS5Server {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for test SOCKS5 server: %v", err)
	}
	s := &testSOCKS5Server{
		listener: l,
		user:     user,
		pass:     pass,
		done:     make(chan struct{}),
	}
	go s.serve()
	return s
}

func (s *testSOCKS5Server) Addr() string {
	return s.listener.Addr().String()
}

func (s *testSOCKS5Server) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.listener.Close()
	for _, c := range s.conns {
		c.Close()
	}
	s.conns = nil
	s.mu.Unlock()
	close(s.done)
}

func (s *testSOCKS5Server) DropConnections() {
	s.mu.Lock()
	for _, c := range s.conns {
		c.Close()
	}
	s.conns = nil
	s.mu.Unlock()
}

func (s *testSOCKS5Server) Requests() []socks5Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]socks5Request, len(s.requests))
	copy(out, s.requests)
	return out
}

func (s *testSOCKS5Server) RequestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

func (s *testSOCKS5Server) serve() {
	for {
		c, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			c.Close()
			return
		}
		s.conns = append(s.conns, c)
		s.mu.Unlock()
		go s.handleConn(c)
	}
}

func (s *testSOCKS5Server) handleConn(c net.Conn) {
	defer c.Close()
	var buf [258]byte
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	nmethods := int(buf[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}

	var authUser, authPass string
	if s.user != "" || s.pass != "" {
		hasAuth := false
		for _, m := range methods {
			if m == 0x02 {
				hasAuth = true
				break
			}
		}
		if !hasAuth {
			c.Write([]byte{0x05, 0xFF})
			return
		}
		if _, err := c.Write([]byte{0x05, 0x02}); err != nil {
			return
		}
		if _, err := io.ReadFull(c, buf[:2]); err != nil {
			return
		}
		if buf[0] != 0x01 {
			return
		}
		ulen := int(buf[1])
		unameBuf := make([]byte, ulen)
		if _, err := io.ReadFull(c, unameBuf); err != nil {
			return
		}
		authUser = string(unameBuf)
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return
		}
		plen := int(buf[0])
		passBuf := make([]byte, plen)
		if _, err := io.ReadFull(c, passBuf); err != nil {
			return
		}
		authPass = string(passBuf)
		if authUser != s.user || authPass != s.pass {
			c.Write([]byte{0x01, 0x01})
			return
		}
		if _, err := c.Write([]byte{0x01, 0x00}); err != nil {
			return
		}
	} else {
		if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
			return
		}
	}

	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return
	}
	if buf[0] != 0x05 || buf[1] != 0x01 {
		return
	}
	atyp := buf[3]
	var targetHost string
	var targetIP net.IP
	var port int

	switch atyp {
	case 0x01: // IPv4
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(c, ipBuf); err != nil {
			return
		}
		targetIP = net.IP(ipBuf)
		var portBuf [2]byte
		if _, err := io.ReadFull(c, portBuf[:]); err != nil {
			return
		}
		port = int(binary.BigEndian.Uint16(portBuf[:]))
		targetHost = targetIP.String()
	case 0x03: // Domain name
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return
		}
		dlen := int(buf[0])
		domainBuf := make([]byte, dlen)
		if _, err := io.ReadFull(c, domainBuf); err != nil {
			return
		}
		targetHost = string(domainBuf)
		var portBuf [2]byte
		if _, err := io.ReadFull(c, portBuf[:]); err != nil {
			return
		}
		port = int(binary.BigEndian.Uint16(portBuf[:]))
	case 0x04: // IPv6
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(c, ipBuf); err != nil {
			return
		}
		targetIP = net.IP(ipBuf)
		var portBuf [2]byte
		if _, err := io.ReadFull(c, portBuf[:]); err != nil {
			return
		}
		port = int(binary.BigEndian.Uint16(portBuf[:]))
		targetHost = targetIP.String()
	default:
		c.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	req := socks5Request{
		Atyp:     atyp,
		Host:     targetHost,
		IP:       targetIP,
		Port:     port,
		AuthUser: authUser,
		AuthPass: authPass,
	}
	s.mu.Lock()
	s.requests = append(s.requests, req)
	s.mu.Unlock()

	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(port))
	targetConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		c.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer targetConn.Close()

	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}

	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(targetConn, c)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(c, targetConn)
		errCh <- err
	}()
	<-errCh
}

type testHTTPProxyServer struct {
	server   *httptest.Server
	mu       sync.Mutex
	requests []string
}

func startTestHTTPProxyServer(t *testing.T) *testHTTPProxyServer {
	p := &testHTTPProxyServer{}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.requests = append(p.requests, r.Method+" "+r.RequestURI)
		p.mu.Unlock()

		if r.Method == http.MethodConnect {
			destConn, err := net.DialTimeout("tcp", r.Host, 5*time.Second)
			if err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				destConn.Close()
				http.Error(w, "hijacking not supported", http.StatusInternalServerError)
				return
			}
			clientConn, _, err := hijacker.Hijack()
			if err != nil {
				destConn.Close()
				return
			}
			go func() {
				defer destConn.Close()
				defer clientConn.Close()
				errCh := make(chan error, 2)
				go func() { _, e := io.Copy(destConn, clientConn); errCh <- e }()
				go func() { _, e := io.Copy(clientConn, destConn); errCh <- e }()
				<-errCh
			}()
			return
		}

		req, err := http.NewRequest(r.Method, r.RequestURI, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for k, v := range r.Header {
			req.Header[k] = v
		}
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))
	return p
}

func (p *testHTTPProxyServer) Close() {
	p.server.Close()
}

func (p *testHTTPProxyServer) URL() string {
	return p.server.URL
}

func (p *testHTTPProxyServer) Requests() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, len(p.requests))
	copy(out, p.requests)
	return out
}

// 1. Existing HTTP proxy functionality remains operational.
func TestProxy_HTTP_ControlPlane(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/info" {
			json.NewEncoder(w).Encode(protocol.InfoResponse{Version: 1})
			return
		}
		http.NotFound(w, r)
	}))
	defer targetServer.Close()

	httpProxy := startTestHTTPProxyServer(t)
	defer httpProxy.Close()

	client, err := httpClient(targetServer.URL, Options{
		HTTPSProxy: httpProxy.URL(),
	})
	if err != nil {
		t.Fatalf("httpClient error = %v", err)
	}

	resp, err := client.Get(targetServer.URL + "/v1/info")
	if err != nil {
		t.Fatalf("GET /v1/info through HTTP proxy error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: %d", resp.StatusCode)
	}
	if len(httpProxy.Requests()) == 0 {
		t.Fatal("HTTP proxy did not record any requests")
	}
}

// 2. Existing HTTPS proxy functionality remains operational where already tested/supported.
func TestProxy_HTTPS_ProxyURL(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://server.example/v1/info", nil)
	if err != nil {
		t.Fatal(err)
	}
	pFunc, _, err := configureProxy(Options{HTTPSProxy: "https://proxy.example:8443"})
	if err != nil {
		t.Fatalf("configureProxy() error = %v", err)
	}
	u, err := pFunc(req)
	if err != nil || u.String() != "https://proxy.example:8443" {
		t.Fatalf("expected https://proxy.example:8443, got %v (%v)", u, err)
	}
}

// 3. SOCKS5 connection succeeds.
func TestProxy_SOCKS5_Success(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello from target"))
	}))
	defer targetServer.Close()

	socksServer := startTestSOCKS5Server(t, "", "")
	defer socksServer.Close()

	client, err := httpClient(targetServer.URL, Options{
		HTTPSProxy: "socks5://" + socksServer.Addr(),
	})
	if err != nil {
		t.Fatalf("httpClient error = %v", err)
	}

	resp, err := client.Get(targetServer.URL + "/test")
	if err != nil {
		t.Fatalf("request through SOCKS5 failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello from target" {
		t.Fatalf("unexpected body: %q", string(body))
	}
	if socksServer.RequestCount() != 1 {
		t.Fatalf("expected 1 SOCKS request, got %d", socksServer.RequestCount())
	}
}

// 4. SOCKS5 username/password authentication succeeds.
func TestProxy_SOCKS5_Auth_Success(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer targetServer.Close()

	socksServer := startTestSOCKS5Server(t, "alice", "supersecret")
	defer socksServer.Close()

	client, err := httpClient(targetServer.URL, Options{
		HTTPSProxy: fmt.Sprintf("socks5://alice:supersecret@%s", socksServer.Addr()),
	})
	if err != nil {
		t.Fatalf("httpClient error = %v", err)
	}

	resp, err := client.Get(targetServer.URL + "/test")
	if err != nil {
		t.Fatalf("authenticated SOCKS request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	reqs := socksServer.Requests()
	if len(reqs) != 1 || reqs[0].AuthUser != "alice" || reqs[0].AuthPass != "supersecret" {
		t.Fatalf("unexpected SOCKS auth received: %+v", reqs)
	}
}

// 5. Invalid SOCKS credentials fail cleanly.
func TestProxy_SOCKS5_Auth_Failure(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer targetServer.Close()

	socksServer := startTestSOCKS5Server(t, "alice", "correctsecret")
	defer socksServer.Close()

	client, err := httpClient(targetServer.URL, Options{
		HTTPSProxy: fmt.Sprintf("socks5://alice:wrongpassword@%s", socksServer.Addr()),
	})
	if err != nil {
		t.Fatalf("httpClient error = %v", err)
	}

	_, err = client.Get(targetServer.URL + "/test")
	if err == nil {
		t.Fatal("expected request with invalid SOCKS credentials to fail, but succeeded")
	}
}

// 6. socks5:// performs destination DNS locally.
func TestProxy_SOCKS5_LocalDNS(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer targetServer.Close()

	socksServer := startTestSOCKS5Server(t, "", "")
	defer socksServer.Close()

	client, err := httpClient(targetServer.URL, Options{
		HTTPSProxy: "socks5://" + socksServer.Addr(),
	})
	if err != nil {
		t.Fatalf("httpClient error = %v", err)
	}

	_, portStr, _ := net.SplitHostPort(targetServer.Listener.Addr().String())
	localhostURL := fmt.Sprintf("http://localhost:%s/test", portStr)

	resp, err := client.Get(localhostURL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	reqs := socksServer.Requests()
	if len(reqs) < 1 {
		t.Fatal("expected at least 1 SOCKS request")
	}
	for _, req := range reqs {
		// For socks5://, destination hostname "localhost" must be resolved locally to an IP (0x01 or 0x04)
		if req.Atyp != 0x01 && req.Atyp != 0x04 {
			t.Fatalf("socks5:// sent ATYP 0x%02x, want 0x01 (IPv4) or 0x04 (IPv6)", req.Atyp)
		}
		if req.IP == nil {
			t.Fatalf("socks5:// did not provide IP address in SOCKS request: %+v", req)
		}
	}
}

// 7. socks5h:// passes the hostname to the SOCKS server for remote resolution.
func TestProxy_SOCKS5h_RemoteDNS(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer targetServer.Close()

	socksServer := startTestSOCKS5Server(t, "", "")
	defer socksServer.Close()

	client, err := httpClient(targetServer.URL, Options{
		HTTPSProxy: "socks5h://" + socksServer.Addr(),
	})
	if err != nil {
		t.Fatalf("httpClient error = %v", err)
	}

	_, portStr, _ := net.SplitHostPort(targetServer.Listener.Addr().String())
	localhostURL := fmt.Sprintf("http://localhost:%s/test", portStr)

	resp, err := client.Get(localhostURL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	reqs := socksServer.Requests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 SOCKS request, got %d", len(reqs))
	}
	// For socks5h://, destination hostname "localhost" must be passed as FQDN (0x03)
	if reqs[0].Atyp != 0x03 {
		t.Fatalf("socks5h:// sent ATYP 0x%02x, want 0x03 (FQDN)", reqs[0].Atyp)
	}
	if reqs[0].Host != "localhost" {
		t.Fatalf("socks5h:// sent host %q, want %q", reqs[0].Host, "localhost")
	}
}

// 8. HTTPS control-plane traffic works through SOCKS5.
func TestProxy_SOCKS5_HTTPSControlPlane(t *testing.T) {
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "id_ed25519")
	_, err := sshkey.GenerateIdentityFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	targetServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/info":
			json.NewEncoder(w).Encode(protocol.InfoResponse{
				Version:      1,
				Capabilities: []string{"ssh-auth"},
			})
		case "/v1/auth":
			json.NewEncoder(w).Encode(protocol.AuthResponse{
				Token:          "test-token",
				TunnelIP:       "100.64.0.2",
				ServerTunnelIP: "100.64.0.1",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer targetServer.Close()

	socksServer := startTestSOCKS5Server(t, "", "")
	defer socksServer.Close()

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: targetServer.Certificate().Raw,
	})
	caFile := filepath.Join(tempDir, "ca.pem")
	os.WriteFile(caFile, certPEM, 0644)

	resp, err := AuthenticateWithOptions(targetServer.URL, keyPath, protocol.ClientInfo{}, Options{
		CAFile:     caFile,
		HTTPSProxy: "socks5://" + socksServer.Addr(),
		QueryOnly:  true,
	})
	if err != nil {
		t.Fatalf("AuthenticateWithOptions through SOCKS5 failed: %v", err)
	}
	if resp.Token != "test-token" {
		t.Fatalf("unexpected token: %q", resp.Token)
	}
	if socksServer.RequestCount() < 1 {
		t.Fatalf("expected at least 1 SOCKS request, got %d", socksServer.RequestCount())
	}
}

// 9. WSS traffic works through SOCKS5.
func TestProxy_SOCKS5_WSSTraffic(t *testing.T) {
	serverBind := wstransport.NewServer()
	serverFns, _, err := serverBind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer serverBind.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := serverBind.ServeHTTP(w, r, "session-1"); err != nil {
			t.Errorf("serverBind.ServeHTTP error: %v", err)
		}
	})

	targetServer := httptest.NewServer(handler)
	defer targetServer.Close()

	socksServer := startTestSOCKS5Server(t, "", "")
	defer socksServer.Close()

	clientHTTP, err := httpClient(targetServer.URL, Options{
		HTTPSProxy: "socks5://" + socksServer.Addr(),
	})
	if err != nil {
		t.Fatal(err)
	}

	wsURL := "ws" + targetServer.URL[len("http"):]
	clientBind := wstransport.NewClient(wsURL, clientHTTP, nil)
	_, _, err = clientBind.Open(0)
	if err != nil {
		t.Fatalf("clientBind.Open error = %v", err)
	}
	defer clientBind.Close()

	ep, err := clientBind.ParseEndpoint("127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}

	testPayload := []byte("packet-via-socks5")
	if err := clientBind.Send([][]byte{testPayload}, ep); err != nil {
		t.Fatalf("clientBind.Send error: %v", err)
	}

	bufs := [][]byte{make([]byte, 1024)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)

	n, err := serverFns[0](bufs, sizes, eps)
	if err != nil || n != 1 {
		t.Fatalf("server receive failed: n=%d, err=%v", n, err)
	}
	if string(bufs[0][:sizes[0]]) != string(testPayload) {
		t.Fatalf("received payload mismatch: got %q, want %q", bufs[0][:sizes[0]], testPayload)
	}
	if socksServer.RequestCount() < 1 {
		t.Fatal("SOCKS server recorded 0 requests for WSS traffic")
	}
}

// 10. WSS traffic works through SOCKS5h.
func TestProxy_SOCKS5h_WSSTraffic(t *testing.T) {
	serverBind := wstransport.NewServer()
	serverFns, _, err := serverBind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer serverBind.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := serverBind.ServeHTTP(w, r, "session-1"); err != nil {
			t.Errorf("serverBind.ServeHTTP error: %v", err)
		}
	})

	targetServer := httptest.NewServer(handler)
	defer targetServer.Close()

	socksServer := startTestSOCKS5Server(t, "", "")
	defer socksServer.Close()

	clientHTTP, err := httpClient(targetServer.URL, Options{
		HTTPSProxy: "socks5h://" + socksServer.Addr(),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, portStr, _ := net.SplitHostPort(targetServer.Listener.Addr().String())
	wsURL := fmt.Sprintf("ws://localhost:%s", portStr)

	clientBind := wstransport.NewClient(wsURL, clientHTTP, nil)
	_, _, err = clientBind.Open(0)
	if err != nil {
		t.Fatalf("clientBind.Open error = %v", err)
	}
	defer clientBind.Close()

	ep, err := clientBind.ParseEndpoint("127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}

	testPayload := []byte("packet-via-socks5h")
	if err := clientBind.Send([][]byte{testPayload}, ep); err != nil {
		t.Fatalf("clientBind.Send error: %v", err)
	}

	bufs := [][]byte{make([]byte, 1024)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)

	n, err := serverFns[0](bufs, sizes, eps)
	if err != nil || n != 1 {
		t.Fatalf("server receive failed: n=%d, err=%v", n, err)
	}
	if string(bufs[0][:sizes[0]]) != string(testPayload) {
		t.Fatalf("received payload mismatch: got %q, want %q", bufs[0][:sizes[0]], testPayload)
	}

	reqs := socksServer.Requests()
	if len(reqs) < 1 {
		t.Fatal("SOCKS server recorded 0 requests for WSS traffic")
	}
	if reqs[0].Atyp != 0x03 {
		t.Fatalf("socks5h:// sent ATYP 0x%02x, want 0x03 (FQDN)", reqs[0].Atyp)
	}
}

// 11. WSS reconnect/redial continues through SOCKS.
func TestProxy_SOCKS5_WSSRedial(t *testing.T) {
	serverBind := wstransport.NewServer()
	_, _, err := serverBind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer serverBind.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = serverBind.ServeHTTP(w, r, "session-1")
	})

	targetServer := httptest.NewServer(handler)
	defer targetServer.Close()

	socksServer := startTestSOCKS5Server(t, "", "")
	defer socksServer.Close()

	clientHTTP, err := httpClient(targetServer.URL, Options{
		HTTPSProxy: "socks5://" + socksServer.Addr(),
	})
	if err != nil {
		t.Fatal(err)
	}

	serverConnected := make(chan struct{}, 10)
	serverBind.OnPeerConnected = func(id string, ep conn.Endpoint) {
		serverConnected <- struct{}{}
	}

	wsURL := "ws" + targetServer.URL[len("http"):]
	clientBind := wstransport.NewClient(wsURL, clientHTTP, nil)
	clientBind.SetRedialBackoff(5*time.Millisecond, 20*time.Millisecond, time.Second)
	reconnected := make(chan struct{}, 10)
	clientBind.OnPeerConnected = func(id string, ep conn.Endpoint) {
		reconnected <- struct{}{}
	}

	_, _, err = clientBind.Open(0)
	if err != nil {
		t.Fatalf("clientBind.Open error = %v", err)
	}
	defer clientBind.Close()

	// Initial connection established
	select {
	case <-reconnected:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for initial connection")
	}
	select {
	case <-serverConnected:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for initial server peer")
	}

	if socksServer.RequestCount() != 1 {
		t.Fatalf("expected 1 initial SOCKS request, got %d", socksServer.RequestCount())
	}

	// Terminate the active session from the server side to trigger client redial
	serverBind.CloseSession("session-1")

	// Wait for automatic redial through SOCKS
	select {
	case <-reconnected:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for automatic redial")
	}

	// SOCKS proxy must have recorded at least 2 connections (initial + redial)
	if socksServer.RequestCount() < 2 {
		t.Fatalf("expected at least 2 SOCKS requests after redial, got %d", socksServer.RequestCount())
	}
}

// 12. TLS certificate validation still validates the ntwire destination.
func TestProxy_SOCKS5_TLSValidation(t *testing.T) {
	targetServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer targetServer.Close()

	socksServer := startTestSOCKS5Server(t, "", "")
	defer socksServer.Close()

	// 12a. Request without CA or insecure should fail certificate validation
	untrustedClient, err := httpClient(targetServer.URL, Options{
		HTTPSProxy: "socks5://" + socksServer.Addr(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = untrustedClient.Get(targetServer.URL + "/test")
	if err == nil {
		t.Fatal("expected TLS verification to fail without CA or pin")
	}

	// 12b. Request with Insecure: true should succeed
	insecureClient, err := httpClient(targetServer.URL, Options{
		HTTPSProxy: "socks5://" + socksServer.Addr(),
		Insecure:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := insecureClient.Get(targetServer.URL + "/test")
	if err != nil {
		t.Fatalf("insecure request over SOCKS5 failed: %v", err)
	}
	resp.Body.Close()

	// 12c. Request with CAFile should succeed
	tempDir := t.TempDir()
	caFile := filepath.Join(tempDir, "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: targetServer.Certificate().Raw,
	})
	os.WriteFile(caFile, certPEM, 0644)

	caClient, err := httpClient(targetServer.URL, Options{
		HTTPSProxy: "socks5://" + socksServer.Addr(),
		CAFile:     caFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err = caClient.Get(targetServer.URL + "/test")
	if err != nil {
		t.Fatalf("CA-validated request over SOCKS5 failed: %v", err)
	}
	resp.Body.Close()
}

// 13. Certificate pinning continues to work.
func TestProxy_SOCKS5_CertificatePinning(t *testing.T) {
	targetServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer targetServer.Close()

	socksServer := startTestSOCKS5Server(t, "", "")
	defer socksServer.Close()

	s := sha256.Sum256(targetServer.Certificate().Raw)
	fp := "SHA256:" + base64.RawStdEncoding.EncodeToString(s[:])

	tempDir := t.TempDir()
	knownFile := filepath.Join(tempDir, "known_servers")

	u, _ := urlpkg.Parse(targetServer.URL)
	host := u.Host

	// Pin valid fingerprint
	TrustServer(knownFile, host, fp)

	pinnedClient, err := httpClient(targetServer.URL, Options{
		HTTPSProxy:       "socks5://" + socksServer.Addr(),
		KnownServersFile: knownFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := pinnedClient.Get(targetServer.URL + "/test")
	if err != nil {
		t.Fatalf("pinned request failed: %v", err)
	}
	resp.Body.Close()

	// Mismatched fingerprint
	TrustServer(knownFile, host, "SHA256:mismatchedfingerprint")
	mismatchedClient, err := httpClient(targetServer.URL, Options{
		HTTPSProxy:       "socks5://" + socksServer.Addr(),
		KnownServersFile: knownFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = mismatchedClient.Get(targetServer.URL + "/test")
	var unknownCertErr *UnknownCertificateError
	if !errors.As(err, &unknownCertErr) {
		t.Fatalf("expected UnknownCertificateError for mismatched fingerprint, got: %v", err)
	}
}

// 14. --ip-version 4 behaves correctly with SOCKS5/local DNS.
func TestProxy_SOCKS5_IPVersion4(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer targetServer.Close()

	socksServer := startTestSOCKS5Server(t, "", "")
	defer socksServer.Close()

	client, err := httpClient(targetServer.URL, Options{
		HTTPSProxy: "socks5://" + socksServer.Addr(),
		IPVersion:  "4",
	})
	if err != nil {
		t.Fatalf("httpClient error = %v", err)
	}

	_, portStr, _ := net.SplitHostPort(targetServer.Listener.Addr().String())
	localhostURL := fmt.Sprintf("http://localhost:%s/test", portStr)

	resp, err := client.Get(localhostURL)
	if err != nil {
		t.Fatalf("request with IPVersion 4 failed: %v", err)
	}
	defer resp.Body.Close()

	reqs := socksServer.Requests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	if reqs[0].Atyp != 0x01 {
		t.Fatalf("expected IPv4 (0x01), got 0x%02x", reqs[0].Atyp)
	}
	if reqs[0].IP.To4() == nil {
		t.Fatalf("expected IPv4 address, got %v", reqs[0].IP)
	}
}

// 15. --ip-version 6 behaves correctly with SOCKS5/local DNS.
func TestProxy_SOCKS5_IPVersion6(t *testing.T) {
	socksServer := startTestSOCKS5Server(t, "", "")
	defer socksServer.Close()

	client, err := httpClient("http://127.0.0.1:8080", Options{
		HTTPSProxy: "socks5://" + socksServer.Addr(),
		IPVersion:  "6",
	})
	if err != nil {
		t.Fatal(err)
	}

	// 127.0.0.1 is an IPv4 literal, so IPVersion 6 must reject it or fail to connect
	_, err = client.Get("http://127.0.0.1:8080/test")
	if err == nil {
		t.Fatal("expected request to IPv4 target with IPVersion 6 to fail")
	}
}

// 16. NoSystemProxy behaviour is unchanged.
func TestProxy_NoSystemProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://unreachable.proxy.invalid:8080")
	t.Setenv("HTTP_PROXY", "http://unreachable.proxy.invalid:8080")

	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer targetServer.Close()

	client, err := httpClient(targetServer.URL, Options{
		NoSystemProxy: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Get(targetServer.URL + "/test")
	if err != nil {
		t.Fatalf("NoSystemProxy should connect directly and ignore environment proxy, but failed: %v", err)
	}
	resp.Body.Close()
}

// 17. Explicit proxy configuration overrides environment proxy configuration.
func TestProxy_ExplicitOverridesEnv(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://unreachable.env.proxy.invalid:8080")
	t.Setenv("HTTP_PROXY", "http://unreachable.env.proxy.invalid:8080")

	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer targetServer.Close()

	socksServer := startTestSOCKS5Server(t, "", "")
	defer socksServer.Close()

	client, err := httpClient(targetServer.URL, Options{
		HTTPSProxy: "socks5://" + socksServer.Addr(),
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Get(targetServer.URL + "/test")
	if err != nil {
		t.Fatalf("explicit SOCKS proxy should override environment proxy, but failed: %v", err)
	}
	defer resp.Body.Close()
	if socksServer.RequestCount() != 1 {
		t.Fatalf("expected 1 SOCKS request, got %d", socksServer.RequestCount())
	}
}

// 18. Unsupported schemes produce a clear error.
func TestProxy_UnsupportedSchemes(t *testing.T) {
	unsupported := []string{
		"socks4://127.0.0.1:1080",
		"ftp://127.0.0.1:21",
		"gopher://127.0.0.1:70",
		"socks5+unix:///var/run/socks.sock",
		"unknown://127.0.0.1:1080",
	}
	for _, proxyURL := range unsupported {
		_, err := httpClient("https://server.example:8443", Options{
			HTTPSProxy: proxyURL,
		})
		if err == nil {
			t.Errorf("expected error for unsupported proxy URL %q, got nil", proxyURL)
		} else if !strings.Contains(err.Error(), "must be an http://, https://, socks5://, or socks5h:// URL") {
			t.Errorf("unexpected error message for %q: %v", proxyURL, err)
		}
	}
}

// 19. Malformed proxy URLs produce a clear error.
func TestProxy_MalformedURLs(t *testing.T) {
	malformed := []string{
		"://invalid",
		"https:///missing-host",
		"socks5://",
		"socks5h:///missing-host",
		"proxy.example.com:1080",
	}
	for _, proxyURL := range malformed {
		_, err := httpClient("https://server.example:8443", Options{
			HTTPSProxy: proxyURL,
		})
		if err == nil {
			t.Errorf("expected error for malformed proxy URL %q, got nil", proxyURL)
		}
	}
}

// 20. Passwords are never exposed in errors/log output.
func TestProxy_PasswordRedaction(t *testing.T) {
	secretPass := "SuperSecretPassword123!"

	cases := []struct {
		input string
		want  string
	}{
		{"socks5://alice:SuperSecretPassword123!@127.0.0.1:1080", "socks5://alice:xxxxx@127.0.0.1:1080"},
		{"socks5h://alice:SuperSecretPassword123!@proxy.example:1080", "socks5h://alice:xxxxx@proxy.example:1080"},
		{"http://alice:SuperSecretPassword123!@proxy.example:8080", "http://alice:xxxxx@proxy.example:8080"},
		{"socks5://alice@proxy.example:1080", "socks5://alice@proxy.example:1080"},
		{"socks5://proxy.example:1080", "socks5://proxy.example:1080"},
	}
	for _, tc := range cases {
		got := RedactProxyURL(tc.input)
		if got != tc.want {
			t.Errorf("RedactProxyURL(%q) = %q, want %q", tc.input, got, tc.want)
		}
		if strings.Contains(got, secretPass) {
			t.Errorf("RedactProxyURL leaked secret password: %q", got)
		}
	}

	// Error when proxy validation fails
	invalidURL := fmt.Sprintf("socks4://alice:%s@127.0.0.1:1080", secretPass)
	_, err := httpClient("https://server.example:8443", Options{
		HTTPSProxy: invalidURL,
	})
	if err == nil {
		t.Fatal("expected error for unsupported socks4 scheme")
	}
	if strings.Contains(err.Error(), secretPass) {
		t.Fatalf("error message contains secret password: %v", err)
	}

	// Error when connection to unreachable proxy fails
	unreachableURL := fmt.Sprintf("socks5://alice:%s@127.0.0.1:1", secretPass)
	client, err := httpClient("http://server.example:8443", Options{
		HTTPSProxy: unreachableURL,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Get("http://server.example:8443/test")
	if err == nil {
		t.Fatal("expected connection to port 1 to fail")
	}
	if strings.Contains(err.Error(), secretPass) {
		t.Fatalf("dial error message contains secret password: %v", err)
	}
}
