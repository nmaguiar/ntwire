package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/relay"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
	"golang.org/x/crypto/ssh"
)

type fakeNetConn struct {
	net.Conn
	closed        bool
	readDeadlines []time.Time
}

func (f *fakeNetConn) Close() error { f.closed = true; return nil }
func (f *fakeNetConn) SetReadDeadline(t time.Time) error {
	f.readDeadlines = append(f.readDeadlines, t)
	return nil
}

func TestRelayListener_AcceptYieldsPushedConnWithRelayReportedAddress(t *testing.T) {
	l := newRelayListener()
	defer l.Close()
	want := &relayConn{Conn: &fakeNetConn{}, remoteAddr: stringAddr("203.0.113.7:5555")}
	go l.push(want)

	got, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if got.RemoteAddr().String() != "203.0.113.7:5555" {
		t.Fatalf("RemoteAddr = %q, want %q", got.RemoteAddr().String(), "203.0.113.7:5555")
	}
}

func TestRelayListener_PushAfterCloseClosesConn(t *testing.T) {
	l := newRelayListener()
	l.Close()
	c := &fakeNetConn{}
	l.push(c)
	if !c.closed {
		t.Fatal("push after Close should close the connection instead of blocking forever")
	}
}

func TestRelayConn_DoesNotForwardHTTPHijackDeadline(t *testing.T) {
	underlying := &fakeNetConn{}
	c := &relayConn{Conn: underlying}
	if err := c.SetReadDeadline(time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if len(underlying.readDeadlines) != 0 {
		t.Fatalf("hijack deadline was forwarded: %v", underlying.readDeadlines)
	}

	want := time.Now().Add(time.Minute).Round(0)
	if err := c.SetReadDeadline(want); err != nil {
		t.Fatal(err)
	}
	if len(underlying.readDeadlines) != 1 || !underlying.readDeadlines[0].Equal(want) {
		t.Fatalf("forwarded deadlines = %v, want [%v]", underlying.readDeadlines, want)
	}
}

// TestRelayConn_ServeTLSSeesRelayReportedRemoteAddr drives a real
// http.Server.ServeTLS over a relayListener fed by two net.Pipe-backed
// relayConns with distinct synthetic addresses, and asserts the handler's
// r.RemoteAddr reflects each one distinctly. This is the regression test for
// the plan's "single most important implementation detail": without the
// RemoteAddr override, every relayed client would appear to share one
// address.
func TestRelayConn_ServeTLSSeesRelayReportedRemoteAddr(t *testing.T) {
	pair, err := generateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	l := newRelayListener()
	defer l.Close()

	seen := make(chan string, 2)
	srv := &http.Server{
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen <- r.RemoteAddr }),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12},
	}
	go srv.ServeTLS(l, "", "")
	defer srv.Close()

	dial := func(clientAddr string) {
		serverSide, clientSide := net.Pipe()
		l.push(&relayConn{Conn: serverSide, remoteAddr: stringAddr(clientAddr)})
		tlsConn := tls.Client(clientSide, &tls.Config{InsecureSkipVerify: true})
		defer tlsConn.Close()
		req, _ := http.NewRequest(http.MethodGet, "https://ignored/", nil)
		if err := req.Write(tlsConn); err != nil {
			t.Errorf("write request: %v", err)
			return
		}
		buf := make([]byte, 4096)
		_, _ = tlsConn.Read(buf) // drain enough of the response to let the handler run
	}

	go dial("203.0.113.9:1111")
	go dial("203.0.113.9:2222")

	got := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case addr := <-seen:
			got[addr] = true
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for both requests to reach the handler")
		}
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 distinct RemoteAddr values, got %v", got)
	}
	if !got["203.0.113.9:1111"] || !got["203.0.113.9:2222"] {
		t.Fatalf("RemoteAddr values did not match what was pushed: %v", got)
	}
}

func TestReload_FreezesRelayBlock(t *testing.T) {
	s, _, _ := newTestServer(t, []TunnelConfig{{Name: "reports", Target: "x:1", VirtualPort: 1, Allow: []string{"*"}}})
	s.Config.Relay = RelayConfig{Enabled: true, URL: "wss://relay.example.com:8444", Name: "home", IdentityFile: "/tmp/id", ReconnectMin: time.Second, ReconnectMax: time.Minute}

	changed := s.Config
	changed.Relay = RelayConfig{Enabled: true, URL: "wss://different.example.com:8444", Name: "lab", IdentityFile: "/tmp/other-id"}
	s.Reload(changed)

	if s.Config.Relay.Name != "home" || s.Config.Relay.URL != "wss://relay.example.com:8444" {
		t.Fatalf("relay block was not frozen across Reload: %+v", s.Config.Relay)
	}
}

func TestLoadConfig_RelayRequiresFields(t *testing.T) {
	dir := t.TempDir()
	keysDir := dir + "/keys"
	os.MkdirAll(keysDir, 0700)
	path := dir + "/ntwire.yaml"
	yaml := fmt.Sprintf(`
auth:
  authorized_keys_dir: %s
relay:
  enabled: true
`, keysDir)
	os.WriteFile(path, []byte(yaml), 0600)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected an error when relay.enabled is set without url/name/identity_file")
	}
}

func TestLoadConfig_RelayRejectsAdvertisedEndpoint(t *testing.T) {
	dir := t.TempDir()
	keysDir := dir + "/keys"
	os.MkdirAll(keysDir, 0700)
	path := dir + "/ntwire.yaml"
	yaml := fmt.Sprintf(`
auth:
  authorized_keys_dir: %s
network:
  advertised_endpoint: "1.2.3.4:51820"
relay:
  enabled: true
  url: wss://relay.example.com:8444
  name: home
  identity_file: /tmp/id
`, keysDir)
	os.WriteFile(path, []byte(yaml), 0600)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected an error combining relay.enabled with a non-empty advertised_endpoint")
	}
}

func TestLoadConfig_RelayDefaultsReconnect(t *testing.T) {
	dir := t.TempDir()
	keysDir := dir + "/keys"
	os.MkdirAll(keysDir, 0700)
	path := dir + "/ntwire.yaml"
	yaml := fmt.Sprintf(`
auth:
  authorized_keys_dir: %s
relay:
  enabled: true
  url: wss://relay.example.com:8444
  name: home
  identity_file: /tmp/id
`, keysDir)
	os.WriteFile(path, []byte(yaml), 0600)
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Relay.ReconnectMin != time.Second || c.Relay.ReconnectMax != time.Minute {
		t.Fatalf("unexpected reconnect defaults: %+v", c.Relay)
	}
}

func TestRelayHTTPClient_FingerprintPin(t *testing.T) {
	pair, err := generateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(pair.Certificate[0])
	fp := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])

	srv := &http.Server{
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.ServeTLS(ln, "", "")
	defer srv.Close()

	client, err := relayHTTPClient(RelayConfig{Fingerprint: fp})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get("https://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatalf("request with correct pin failed: %v", err)
	}
	resp.Body.Close()

	badClient, err := relayHTTPClient(RelayConfig{Fingerprint: "SHA256:not-the-right-one"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := badClient.Get("https://" + ln.Addr().String() + "/"); err == nil {
		t.Fatal("expected the mismatched fingerprint pin to reject the connection")
	}
}

// TestRelayAgent_EndToEndWithRealRelay drives a real pkg/relay.Relay as the
// fake relay and a real RelayAgent/relayListener as the ntwire-server side,
// confirming registration, RelayOpen push, data-conn dial-back, and that two
// concurrent clients arrive with two distinct RemoteAddr values end to end.
func TestRelayAgent_EndToEndWithRealRelay(t *testing.T) {
	signer, _, err := sshkey.GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	idPath := t.TempDir() + "/id"
	if err := os.WriteFile(idPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	pubLine := string(ssh.MarshalAuthorizedKey(pub))

	relayCfg := relay.Config{Domain: "relay.test", Registrations: []relay.RegistrationConfig{{Name: "home", PublicKey: pubLine}}}
	relayCfg.Listen.Public = "127.0.0.1:0"
	relayCfg.Listen.Agents = "127.0.0.1:0"
	relayCfg.TLS.Ephemeral = true
	relayCfg.Limits.HandshakeTimeout = 5 * time.Second
	relayCfg.Limits.DialBackTimeout = 3 * time.Second
	relayCfg.Limits.MaxPendingPerServer = 32
	relayCfg.Limits.MaxConnsPerServer = 256
	relayCfg.Limits.MaxNewConnsPerMinute = 1000
	rl, err := relay.New(relayCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rl.Start(); err != nil {
		t.Fatal(err)
	}
	defer rl.Close()

	pair, err := generateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	originFP := "SHA256:" + base64.RawStdEncoding.EncodeToString(sha256Sum(pair.Certificate[0]))

	seen := make(chan string, 4)
	origin := &http.Server{
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen <- r.RemoteAddr }),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12},
	}

	agentCfg := RelayConfig{Enabled: true, URL: "wss://" + rl.AgentsAddr().String(), Name: "home", IdentityFile: idPath, Fingerprint: rl.Fingerprint()}
	agent, err := NewRelayAgent(agentCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go agent.Run(ctx)
	go origin.ServeTLS(agent.Listener(), "", "")
	defer origin.Close()
	defer agent.Close()

	time.Sleep(100 * time.Millisecond) // allow registration to complete

	dial := func(clientPortHint string) {
		raw, err := net.Dial("tcp", rl.PublicAddr().String())
		if err != nil {
			t.Errorf("dial relay public: %v", err)
			return
		}
		var pinErr error
		tlsConn := tls.Client(raw, &tls.Config{
			ServerName: "home.relay.test", InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					pinErr = fmt.Errorf("no cert")
					return pinErr
				}
				sum := sha256Sum(cs.PeerCertificates[0].Raw)
				fp := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum)
				if fp != originFP {
					pinErr = fmt.Errorf("mismatch")
					return pinErr
				}
				return nil
			},
		})
		defer tlsConn.Close()
		hctx, hcancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer hcancel()
		if err := tlsConn.HandshakeContext(hctx); err != nil {
			t.Errorf("handshake failed: %v (pinErr=%v)", err, pinErr)
			return
		}
		req, _ := http.NewRequest(http.MethodGet, "https://home.relay.test/", nil)
		req.Write(tlsConn)
		buf := make([]byte, 4096)
		tlsConn.Read(buf)
	}

	go dial("a")
	go dial("b")

	addrs := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case a := <-seen:
			addrs[a] = true
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for both relayed requests")
		}
	}
	if len(addrs) != 2 {
		t.Fatalf("expected 2 distinct relay-reported RemoteAddr values, got %v", addrs)
	}
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// TestRelayAgent_ReconnectsWhenRelayStopsRespondingToPings is the regression
// test for runOnce having no keepalive of its own on the control connection:
// without it, a relay that accepts registration and then hangs -- stops
// responding to everything, including pings, without ever closing the
// connection -- was only ever caught by whatever the OS's default TCP
// keepalive happens to notice, not the prompt detection relay mode depends
// on for NAT rebinding. This drives a hand-rolled control endpoint (not a
// real pkg/relay.Relay, which always answers pings) that registers once and
// then never reads or writes again.
//
// This necessarily waits through the real, hardcoded 30s ping interval and
// 5s ping timeout mirrored from pkg/relay/agent.go -- there is no other
// externally observable signal that would prove the ping fired, and no
// existing test in this codebase exercises that interval via real timing
// either (agent.go's own keepalive is equally untested that way).
func TestRelayAgent_ReconnectsWhenRelayStopsRespondingToPings(t *testing.T) {
	if testing.Short() {
		t.Skip("waits through the real 30s ping interval; skipped in -short")
	}
	signer, _, err := sshkey.GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	idPath := t.TempDir() + "/id"
	if err := os.WriteFile(idPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}

	pair, err := generateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	fp := "SHA256:" + base64.RawStdEncoding.EncodeToString(sha256Sum(pair.Certificate[0]))

	connectAttempts := make(chan struct{}, 8)
	// Keep every accepted *websocket.Conn referenced for the test's
	// lifetime: coder/websocket finalizes (closes) a Conn that becomes
	// unreachable to GC, which would otherwise close the "hung" connection
	// out from under this test and mask the very condition it simulates.
	heldConns := make(chan *websocket.Conn, 8)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/relay/control", func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		heldConns <- ws
		connectAttempts <- struct{}{}
		if _, _, err := ws.Read(r.Context()); err != nil {
			return
		}
		resp := protocol.RelayRegisterResponse{Version: protocol.Version, Name: "home", Domain: "relay.test"}
		b, _ := json.Marshal(resp)
		_ = ws.Write(r.Context(), websocket.MessageText, b)
		// Deliberately never read or write again: registered, then hung.
	})
	srv := &http.Server{Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.ServeTLS(ln, "", "")
	defer srv.Close()

	agentCfg := RelayConfig{
		Enabled: true, URL: "wss://" + ln.Addr().String(), Name: "home",
		IdentityFile: idPath, Fingerprint: fp,
		ReconnectMin: 10 * time.Millisecond, ReconnectMax: 100 * time.Millisecond,
	}
	agent, err := NewRelayAgent(agentCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go agent.Run(ctx)
	defer agent.Close()

	select {
	case <-connectAttempts:
	case <-time.After(5 * time.Second):
		t.Fatal("initial control connection was never established")
	}

	select {
	case <-connectAttempts:
	case <-time.After(45 * time.Second):
		t.Fatal("agent never reconnected after the relay stopped responding to pings")
	}
}
