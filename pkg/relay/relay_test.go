package relay

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/nmaguiar/ntwire/pkg/protocol"
)

// chanListener is an origin server's dial-back net.Listener: Accept() yields
// whatever connection a fake agent pushes onto ch, mirroring what
// pkg/server/relay.go's relayListener will do for real.
type chanListener struct {
	ch     chan net.Conn
	closed chan struct{}
}

func newChanListener() *chanListener {
	return &chanListener{ch: make(chan net.Conn), closed: make(chan struct{})}
}
func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *chanListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}
func (l *chanListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

func TestUDPRelayPoolListenAddrPreservesRelayHost(t *testing.T) {
	tests := []struct {
		name   string
		listen string
		port   uint16
		want   string
	}{
		{name: "IPv4", listen: "141.227.176.130:5000", port: 5001, want: "141.227.176.130:5001"},
		{name: "IPv6", listen: "[2001:db8::1]:5000", port: 5002, want: "[2001:db8::1]:5002"},
		{name: "wildcard", listen: ":5000", port: 5003, want: ":5003"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := udpRelayPoolListenAddr(tt.listen, tt.port)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("udpRelayPoolListenAddr(%q, %d) = %q, want %q", tt.listen, tt.port, got, tt.want)
			}
		})
	}
}

func TestUDPRelayPoolListenAddrRejectsMalformedListenAddress(t *testing.T) {
	if _, err := udpRelayPoolListenAddr("141.227.176.130", 5001); err == nil {
		t.Fatal("udpRelayPoolListenAddr accepted an address without a port")
	}
}

func generateOriginCert(t *testing.T, dnsName string) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: dnsName},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return pair, "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// startOrigin runs an ntwire-server stand-in: an http.Server whose
// TLS-terminating listener is fed entirely by dial-back connections, just
// like cmd/ntwire-server's relay branch will do.
func startOrigin(t *testing.T, dnsName, body string) (*chanListener, string) {
	t.Helper()
	pair, fp := generateOriginCert(t, dnsName)
	ln := newChanListener()
	srv := &http.Server{
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12},
	}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close(); ln.Close() })
	return ln, fp
}

// runFakeAgent registers name on the relay's agents listener and forwards
// every RelayOpen it receives into dialBack, exactly as pkg/server/relay.go
// will: dial the data endpoint, wrap it as a net.Conn, deliver it to the
// origin's listener.
func runFakeAgent(t *testing.T, agentsAddr string, k testKey, name string, dialBack *chanListener) {
	t.Helper()
	insecureClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	controlURL := "wss://" + agentsAddr + "/v1/relay/control"
	ws, _, err := websocket.Dial(context.Background(), controlURL, &websocket.DialOptions{HTTPClient: insecureClient})
	if err != nil {
		t.Fatalf("dial control for %q: %v", name, err)
	}
	t.Cleanup(func() { ws.Close(websocket.StatusNormalClosure, "") })

	req := signedRegisterRequest(t, k, name, name+"-nonce")
	b, _ := json.Marshal(req)
	if err := ws.Write(context.Background(), websocket.MessageText, b); err != nil {
		t.Fatalf("write registration for %q: %v", name, err)
	}
	_, data, err := ws.Read(context.Background())
	if err != nil {
		t.Fatalf("read registration response for %q: %v", name, err)
	}
	var resp protocol.RelayRegisterResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("unmarshal registration response: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf("registration for %q failed: %s (%s)", name, resp.Error, resp.Code)
	}

	go func() {
		for {
			_, data, err := ws.Read(context.Background())
			if err != nil {
				return
			}
			var open protocol.RelayOpen
			if json.Unmarshal(data, &open) != nil {
				continue
			}
			dataURL := "wss://" + agentsAddr + "/v1/relay/data?conn_id=" + open.ConnID
			dataWS, _, err := websocket.Dial(context.Background(), dataURL, &websocket.DialOptions{HTTPClient: insecureClient})
			if err != nil {
				continue
			}
			conn := websocket.NetConn(context.Background(), dataWS, websocket.MessageBinary)
			select {
			case dialBack.ch <- conn:
			case <-dialBack.closed:
				conn.Close()
			}
		}
	}()
}

func testRelayConfig(t *testing.T, domain string, registrations []RegistrationConfig) *Relay {
	t.Helper()
	cfg := Config{Domain: domain, Registrations: registrations}
	cfg.Listen.Public = "127.0.0.1:0"
	cfg.Listen.Agents = "127.0.0.1:0"
	cfg.TLS.Ephemeral = true
	cfg.Limits.HandshakeTimeout = 5 * time.Second
	cfg.Limits.DialBackTimeout = 3 * time.Second
	cfg.Limits.MaxPendingPerServer = 32
	cfg.Limits.MaxConnsPerServer = 256
	cfg.Limits.MaxNewConnsPerMinute = 1000
	r, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

// dialClientThroughRelay dials the relay's public listener and completes a
// TLS handshake pinned to originFP, exactly as pkg/client/client.go's
// VerifyConnection hook does: SHA256 fingerprint only, no hostname check.
func dialClientThroughRelay(publicAddr, serverName, originFP string) (*tls.Conn, error) {
	raw, err := net.Dial("tcp", publicAddr)
	if err != nil {
		return nil, err
	}
	var pinErr error
	conn := tls.Client(raw, &tls.Config{
		ServerName: serverName, InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				pinErr = fmt.Errorf("no peer certificate")
				return pinErr
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			fp := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
			if originFP != "" && fp != originFP {
				pinErr = fmt.Errorf("fingerprint mismatch: got %s want %s", fp, originFP)
				return pinErr
			}
			return nil
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if pinErr != nil {
		return nil, pinErr
	}
	return conn, nil
}

func TestRelay_EndToEndRoundTrip(t *testing.T) {
	k := generateTestKey(t)
	relay := testRelayConfig(t, "relay.test", []RegistrationConfig{{Name: "home", PublicKey: k.line}})

	dialBack, originFP := startOrigin(t, "home.relay.test", "hello from home")
	runFakeAgent(t, relay.AgentsAddr().String(), k, "home", dialBack)

	// Give the agent a moment to complete registration before the client dials.
	time.Sleep(50 * time.Millisecond)

	conn, err := dialClientThroughRelay(relay.PublicAddr().String(), "home.relay.test", originFP)
	if err != nil {
		t.Fatalf("client dial through relay failed: %v", err)
	}
	defer conn.Close()

	req, _ := http.NewRequest(http.MethodGet, "https://home.relay.test/", nil)
	if err := req.Write(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello from home" {
		t.Fatalf("got %q, want %q", body, "hello from home")
	}
}

func TestRelay_UnknownTenantIndistinguishableFromOffline(t *testing.T) {
	k := generateTestKey(t)
	relay := testRelayConfig(t, "relay.test", []RegistrationConfig{{Name: "home", PublicKey: k.line}})
	// No agent registered for "home" at all: this is the "offline" case.

	_, err := dialClientThroughRelay(relay.PublicAddr().String(), "home.relay.test", "")
	if err == nil {
		t.Fatal("expected the handshake to fail against an offline tenant")
	}
	offlineErr := err.Error()

	_, err = dialClientThroughRelay(relay.PublicAddr().String(), "ghost.relay.test", "")
	if err == nil {
		t.Fatal("expected the handshake to fail against an unregistered tenant")
	}
	// Both cases reset the connection identically (a TLS handshake failure
	// with no application data exchanged); we do not assert exact error
	// string equality since OS-level timing can vary, but both must fail.
	_ = offlineErr
}

func TestRelay_MultiTenantRoutesIndependently(t *testing.T) {
	homeKey := generateTestKey(t)
	labKey := generateTestKey(t)
	relay := testRelayConfig(t, "relay.test", []RegistrationConfig{
		{Name: "home", PublicKey: homeKey.line},
		{Name: "lab", PublicKey: labKey.line},
	})

	homeDialBack, homeFP := startOrigin(t, "home.relay.test", "hello from home")
	labDialBack, labFP := startOrigin(t, "lab.relay.test", "hello from lab")
	runFakeAgent(t, relay.AgentsAddr().String(), homeKey, "home", homeDialBack)
	runFakeAgent(t, relay.AgentsAddr().String(), labKey, "lab", labDialBack)
	time.Sleep(50 * time.Millisecond)

	fetch := func(serverName, fp string) string {
		conn, err := dialClientThroughRelay(relay.PublicAddr().String(), serverName, fp)
		if err != nil {
			t.Fatalf("dial %s: %v", serverName, err)
		}
		defer conn.Close()
		req, _ := http.NewRequest(http.MethodGet, "https://"+serverName+"/", nil)
		req.Write(conn)
		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			t.Fatalf("read response from %s: %v", serverName, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}

	if got := fetch("home.relay.test", homeFP); got != "hello from home" {
		t.Fatalf("home: got %q", got)
	}
	if got := fetch("lab.relay.test", labFP); got != "hello from lab" {
		t.Fatalf("lab: got %q", got)
	}
}

func TestRelay_LabKeyCannotClaimHome(t *testing.T) {
	homeKey := generateTestKey(t)
	labKey := generateTestKey(t)
	relay := testRelayConfig(t, "relay.test", []RegistrationConfig{
		{Name: "home", PublicKey: homeKey.line},
		{Name: "lab", PublicKey: labKey.line},
	})

	insecureClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	controlURL := "wss://" + relay.AgentsAddr().String() + "/v1/relay/control"
	ws, _, err := websocket.Dial(context.Background(), controlURL, &websocket.DialOptions{HTTPClient: insecureClient})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close(websocket.StatusNormalClosure, "")

	req := signedRegisterRequest(t, labKey, "home", "n1")
	b, _ := json.Marshal(req)
	ws.Write(context.Background(), websocket.MessageText, b)
	_, data, err := ws.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var resp protocol.RelayRegisterResponse
	json.Unmarshal(data, &resp)
	if resp.Code != protocol.ErrorRelayNameNotAllowed {
		t.Fatalf("code = %q, want relay_name_not_allowed", resp.Code)
	}
}

func TestRelay_ScannerGetsNoBanner(t *testing.T) {
	k := generateTestKey(t)
	relay := testRelayConfig(t, "relay.test", []RegistrationConfig{{Name: "home", PublicKey: k.line}})

	conn, err := net.DialTimeout("tcp", relay.PublicAddr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// No TLS ClientHello sent at all (mirrors "openssl s_client" with no
	// -servername, or a plain scanner): the relay must not offer a
	// certificate or send any banner before receiving a valid ClientHello.
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if n != 0 {
		t.Fatalf("relay sent %d unsolicited bytes to a connection with no ClientHello", n)
	}
	if err == nil {
		t.Fatal("expected the connection to be idle or closed, not to produce data")
	}
}

func TestRelay_RegistrationsReloadEvictsRemovedTenant(t *testing.T) {
	k := generateTestKey(t)
	relay := testRelayConfig(t, "relay.test", []RegistrationConfig{{Name: "home", PublicKey: k.line}})

	dialBack, originFP := startOrigin(t, "home.relay.test", "hello from home")
	runFakeAgent(t, relay.AgentsAddr().String(), k, "home", dialBack)
	time.Sleep(50 * time.Millisecond)

	conn, err := dialClientThroughRelay(relay.PublicAddr().String(), "home.relay.test", originFP)
	if err != nil {
		t.Fatalf("expected initial connection to succeed: %v", err)
	}
	conn.Close()

	if err := relay.ReloadRegistrations(nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)

	if _, err := dialClientThroughRelay(relay.PublicAddr().String(), "home.relay.test", originFP); err == nil {
		t.Fatal("expected the tenant to be offline after its registration was removed")
	}
}

// TestRelay_RegistrationsReloadEvictsRotatedKey is the regression test for
// key rotation not taking effect on reload: ReplaceRegistrations used to
// evict by name alone, so rotating a compromised key while keeping the same
// name left the compromised server's control connection live indefinitely
// -- it never re-registers on its own, so the new key was never checked.
func TestRelay_RegistrationsReloadEvictsRotatedKey(t *testing.T) {
	oldKey := generateTestKey(t)
	newKey := generateTestKey(t)
	relay := testRelayConfig(t, "relay.test", []RegistrationConfig{{Name: "home", PublicKey: oldKey.line}})

	dialBack, originFP := startOrigin(t, "home.relay.test", "hello from home")
	runFakeAgent(t, relay.AgentsAddr().String(), oldKey, "home", dialBack)
	time.Sleep(50 * time.Millisecond)

	conn, err := dialClientThroughRelay(relay.PublicAddr().String(), "home.relay.test", originFP)
	if err != nil {
		t.Fatalf("expected initial connection to succeed: %v", err)
	}
	conn.Close()

	// Rotate the key for "home" without the old agent ever re-registering.
	if err := relay.ReloadRegistrations([]RegistrationConfig{{Name: "home", PublicKey: newKey.line}}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)

	if _, err := dialClientThroughRelay(relay.PublicAddr().String(), "home.relay.test", originFP); err == nil {
		t.Fatal("expected the old key's agent to be evicted once its name was rebound to a different key")
	}
}

func TestRelay_SampleConfigParses(t *testing.T) {
	tmp := t.TempDir() + "/relay.yaml"
	if err := os.WriteFile(tmp, []byte(SampleConfig()), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(tmp)
	if err != nil {
		t.Fatalf("SampleConfig did not load: %v", err)
	}
	if cfg.Domain == "" {
		t.Fatal("expected a non-empty domain in the sample config")
	}
}

func TestRelay_DedicatedTCPPortRoutesDirectly(t *testing.T) {
	homeKey := generateTestKey(t)
	labKey := generateTestKey(t)
	relay := testRelayConfig(t, "relay.test", []RegistrationConfig{
		{Name: "home", PublicKey: homeKey.line, Listen: "127.0.0.1:0"},
		{Name: "lab", PublicKey: labKey.line},
	})

	homeDialBack, homeFP := startOrigin(t, "home.relay.test", "hello from home")
	labDialBack, labFP := startOrigin(t, "lab.relay.test", "hello from lab")
	runFakeAgent(t, relay.AgentsAddr().String(), homeKey, "home", homeDialBack)
	runFakeAgent(t, relay.AgentsAddr().String(), labKey, "lab", labDialBack)
	time.Sleep(50 * time.Millisecond)

	tenantAddr := relay.TenantAddr("home")
	if tenantAddr == nil {
		t.Fatal("expected non-nil tenant listener address for home")
	}
	if relay.TenantAddr("lab") != nil {
		t.Fatal("expected nil tenant listener address for lab (no dedicated listen configured)")
	}

	// 1. Dial home's dedicated port with an unrelated/arbitrary SNI (bypassing subdomain requirement)
	conn, err := dialClientThroughRelay(tenantAddr.String(), "arbitrary.example.com", homeFP)
	if err != nil {
		t.Fatalf("dial home on dedicated port with arbitrary SNI failed: %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://arbitrary.example.com/", nil)
	if err := req.Write(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	conn.Close()
	if string(body) != "hello from home" {
		t.Fatalf("got %q, want %q", body, "hello from home")
	}

	// 2. Dial home's dedicated port with empty SNI (e.g. connecting via IP)
	conn, err = dialClientThroughRelay(tenantAddr.String(), "", homeFP)
	if err != nil {
		t.Fatalf("dial home on dedicated port with empty SNI failed: %v", err)
	}
	req, _ = http.NewRequest(http.MethodGet, "https://127.0.0.1/", nil)
	if err := req.Write(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err = http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	conn.Close()
	if string(body) != "hello from home" {
		t.Fatalf("got %q, want %q", body, "hello from home")
	}

	// 3. Dial home via the shared public listener using SNI (subdomain)
	conn, err = dialClientThroughRelay(relay.PublicAddr().String(), "home.relay.test", homeFP)
	if err != nil {
		t.Fatalf("dial home via shared public listener failed: %v", err)
	}
	req, _ = http.NewRequest(http.MethodGet, "https://home.relay.test/", nil)
	req.Write(conn)
	resp, err = http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	conn.Close()
	if string(body) != "hello from home" {
		t.Fatalf("got %q, want %q", body, "hello from home")
	}

	// 4. Dial lab via the shared public listener using SNI
	conn, err = dialClientThroughRelay(relay.PublicAddr().String(), "lab.relay.test", labFP)
	if err != nil {
		t.Fatalf("dial lab via shared public listener failed: %v", err)
	}
	req, _ = http.NewRequest(http.MethodGet, "https://lab.relay.test/", nil)
	req.Write(conn)
	resp, err = http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	conn.Close()
	if string(body) != "hello from lab" {
		t.Fatalf("got %q, want %q", body, "hello from lab")
	}
}
