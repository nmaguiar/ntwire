package wstransport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.zx2c4.com/wireguard/conn"
)

func TestWebSocketBindRoundTrip(t *testing.T) {
	server := NewServer()
	serverFns, _, err := server.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := server.ServeHTTP(w, r, "session"); err != nil {
			t.Error(err)
		}
	})
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listeners unavailable: %v", err)
	}
	h := &httptest.Server{Listener: l, Config: &http.Server{Handler: handler}}
	h.Start()
	defer h.Close()
	client := NewClient("ws"+h.URL[len("http"):], h.Client(), nil)
	clientFns, _, err := client.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ep, err := client.ParseEndpoint("127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Send([][]byte{make([]byte, 16)}, ep); err != nil {
		t.Fatal(err)
	}
	serverBuf, serverSizes, serverEP := [][]byte{make([]byte, 64)}, make([]int, 1), make([]conn.Endpoint, 1)
	if n, err := serverFns[0](serverBuf, serverSizes, serverEP); err != nil || n != 1 || serverSizes[0] != 16 {
		t.Fatalf("server receive: n=%d err=%v size=%d", n, err, serverSizes[0])
	}
	if err = server.Send([][]byte{serverBuf[0][:serverSizes[0]]}, serverEP[0]); err != nil {
		t.Fatal(err)
	}
	clientBuf, clientSizes, clientEP := [][]byte{make([]byte, 64)}, make([]int, 1), make([]conn.Endpoint, 1)
	if n, err := clientFns[0](clientBuf, clientSizes, clientEP); err != nil || n != 1 || clientSizes[0] != 16 {
		t.Fatalf("client receive: n=%d err=%v size=%d", n, err, clientSizes[0])
	}
}

// TestHybridClientRoutesBySentinelEndpoint is the load-bearing assertion
// behind the opportunistic direct-UDP upgrade's revert path: a client-side
// Hybrid must route a WSSentinel-seeded peer over WebSocket, and a real
// host:port-seeded peer over raw UDP instead -- using the exact same
// AddPeer/UpdateEndpoint call wgnet.Stack exposes, not any Hybrid-specific
// API, since pkg/client never touches Hybrid directly once it is built.
func TestHybridClientRoutesBySentinelEndpoint(t *testing.T) {
	server := NewServer()
	serverFns, _, err := server.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := server.ServeHTTP(w, r, "session"); err != nil {
			t.Error(err)
		}
	})
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listeners unavailable: %v", err)
	}
	h := &httptest.Server{Listener: l, Config: &http.Server{Handler: handler}}
	h.Start()
	defer h.Close()

	client := NewHybridClient("ws"+h.URL[len("http"):], h.Client(), nil, "")
	if _, _, err := client.Open(0); err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	wsEP, err := client.ParseEndpoint(WSSentinel)
	if err != nil {
		t.Fatalf("ParseEndpoint(WSSentinel) = %v", err)
	}
	if _, ok := wsEP.(endpoint); !ok {
		t.Fatalf("ParseEndpoint(WSSentinel) returned %T, want the WebSocket endpoint type", wsEP)
	}
	udpEP, err := client.ParseEndpoint("127.0.0.1:1")
	if err != nil {
		t.Fatalf("ParseEndpoint(host:port) = %v", err)
	}
	if _, ok := udpEP.(endpoint); ok {
		t.Fatal("ParseEndpoint(host:port) returned the WebSocket endpoint type, want a UDP one")
	}

	if err := client.Send([][]byte{make([]byte, 16)}, wsEP); err != nil {
		t.Fatalf("Send via WSSentinel endpoint = %v", err)
	}
	serverBuf, serverSizes, serverEP := [][]byte{make([]byte, 64)}, make([]int, 1), make([]conn.Endpoint, 1)
	if n, err := serverFns[0](serverBuf, serverSizes, serverEP); err != nil || n != 1 || serverSizes[0] != 16 {
		t.Fatalf("server never received the WSSentinel-routed send: n=%d err=%v size=%d", n, err, serverSizes[0])
	}
}

// TestMultipathHybridClientRegistersWSSAfterOpen protects the relay-only
// startup order: before Open, the client Bind has no WebSocket peer and
// ParseEndpoint rejects WSSentinel. The multipath wrapper must therefore add
// its WSS path only after opening the underlying Hybrid, or all WireGuard
// packets fail with no healthy multipath candidate.
func TestMultipathHybridClientRegistersWSSAfterOpen(t *testing.T) {
	server := NewServer()
	serverFns, _, err := server.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := server.ServeHTTP(w, r, "session"); err != nil {
			t.Error(err)
		}
	})
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listeners unavailable: %v", err)
	}
	h := &httptest.Server{Listener: l, Config: &http.Server{Handler: handler}}
	h.Start()
	defer h.Close()

	_, client := NewMultipathHybridClient("ws"+h.URL[len("http"):], h.Client(), nil, false, false, V2Options{}, "")
	clientFns, _, err := client.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// Hybrid.Open appends the UDP carrier's receive funcs (StdNetBind may
	// return more than one, e.g. one per address family) before the single
	// WebSocket one, so the WS func -- where the ack actually arrives -- is
	// always the last element, never assumable as index 0.
	clientWSFn := clientFns[len(clientFns)-1]

	// RegisterPath (from the client's onOpen) fires an immediate probe but
	// does not wait for the reply; this test's server is a bare Server, not
	// wrapped in ServerMultipathBind, so nothing answers it automatically --
	// read the probe and echo the ack by hand, exactly as
	// ServerMultipathBind.dispatchControl would.
	serverBuf, serverSizes, serverEP := [][]byte{make([]byte, 64)}, make([]int, 1), make([]conn.Endpoint, 1)
	n, err := serverFns[0](serverBuf, serverSizes, serverEP)
	if err != nil || n != 1 {
		t.Fatalf("server receive of probe: n=%d err=%v", n, err)
	}
	typ, payload, ok := DecodeControlFrame(serverBuf[0][:serverSizes[0]])
	if !ok || typ != FramePathProbe {
		t.Fatalf("expected a path probe, got typ=%d ok=%v", typ, ok)
	}
	if err := server.Send([][]byte{EncodeControlFrame(FramePathAck, payload)}, serverEP[0]); err != nil {
		t.Fatalf("server ack send: %v", err)
	}

	// The client must actually pump its receive func for wrapReceive to
	// intercept the ack and call handlePathControl; a control-frame-only
	// batch never returns to the caller (see wrapReceive), so this blocks
	// until client.Close() tears down the connection -- run it in the
	// background and poll Select for the result instead of waiting on it
	// directly.
	go func() {
		buf, sizes, eps := [][]byte{make([]byte, 64)}, make([]int, 1), make([]conn.Endpoint, 1)
		_, _ = clientWSFn(buf, sizes, eps)
	}()
	deadline := time.Now().Add(2 * time.Second)
	var primary string
	for time.Now().Before(deadline) {
		if primary, _, _ = client.Scheduler().Select(); primary == "wss" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if primary != "wss" {
		t.Fatalf("primary path after ack = %q, want wss", primary)
	}

	ep, err := client.ParseEndpoint(MultipathSentinel)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Send([][]byte{make([]byte, 16)}, ep); err != nil {
		t.Fatalf("Send via multipath WSS = %v", err)
	}
	serverBuf, serverSizes, serverEP = [][]byte{make([]byte, 64)}, make([]int, 1), make([]conn.Endpoint, 1)
	if n, err := serverFns[0](serverBuf, serverSizes, serverEP); err != nil || n != 1 || serverSizes[0] != 16 {
		t.Fatalf("server receive: n=%d err=%v size=%d", n, err, serverSizes[0])
	}
}

// TestClientBindSendsSNIThroughPinningTransport answers a question raised by
// the ntwire relay design (PLAN-RELAY.md §I): the /v1/wg data-plane dial
// goes through coder/websocket driven by the same fingerprint-pinning
// http.Client as pkg/client's control plane (InsecureSkipVerify, no explicit
// ServerName). That is a different code path than a plain http.Transport
// request, so this asserts empirically that it still puts SNI on the wire
// for a named host — if it silently didn't, the control plane would work
// fine over a relay while the data plane dead-ended at the relay's SNI
// router.
func TestClientBindSendsSNIThroughPinningTransport(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "origin"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer rawLn.Close()

	sniCh := make(chan string, 1)
	tlsLn := tls.NewListener(rawLn, &tls.Config{
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			select {
			case sniCh <- chi.ServerName:
			default:
			}
			return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
		},
	})
	defer tlsLn.Close()

	server := NewServer()
	if _, _, err := server.Open(0); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_ = server.ServeHTTP(w, r, "session")
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(tlsLn)
	defer srv.Close()

	// Mirrors pkg/client's httpClient(): InsecureSkipVerify with no explicit
	// ServerName, plus a DialContext that redirects the named host to the
	// loopback listener above (there is no real DNS entry for it).
	pinningClient := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial("tcp", rawLn.Addr().String())
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}

	client := NewClient("wss://home.relay.test:1234/", pinningClient, nil)
	if _, _, err := client.Open(0); err != nil {
		t.Fatalf("client dial through pinning transport failed: %v", err)
	}
	defer client.Close()

	select {
	case sni := <-sniCh:
		if sni != "home.relay.test" {
			t.Fatalf("SNI = %q, want %q", sni, "home.relay.test")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the ClientHello")
	}
}

// TestClientBindRedialsAfterDrop protects the fix for the gap where, once
// the client-side "remote" peer's WebSocket connection dropped (an interface
// change, a NAT rebind, a proxy hiccup), Send failed forever: nothing ever
// redialed. It simulates the drop from the server side -- closing the
// server's copy of the socket produces the same read error on the client
// that a broken network path would -- and asserts Send against the same
// endpoint value eventually works again with no caller-visible change.
func TestClientBindRedialsAfterDrop(t *testing.T) {
	server := NewServer()
	serverFns, _, err := server.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := server.ServeHTTP(w, r, "session"); err != nil {
			t.Error(err)
		}
	})
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listeners unavailable: %v", err)
	}
	h := &httptest.Server{Listener: l, Config: &http.Server{Handler: handler}}
	h.Start()
	defer h.Close()

	client := NewClient("ws"+h.URL[len("http"):], h.Client(), nil)
	client.SetRedialBackoff(5*time.Millisecond, 20*time.Millisecond, time.Second)
	events := make(chan string, 4)
	client.OnPeerConnected = func(string, conn.Endpoint) { events <- "connected" }
	client.OnPeerDisconnected = func(string, conn.Endpoint) { events <- "disconnected" }
	if _, _, err := client.Open(0); err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if event := <-events; event != "connected" {
		t.Fatalf("initial lifecycle event = %q", event)
	}

	ep, err := client.ParseEndpoint("127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}

	if err := client.Send([][]byte{make([]byte, 16)}, ep); err != nil {
		t.Fatalf("initial send: %v", err)
	}
	serverBuf, serverSizes, serverEP := [][]byte{make([]byte, 64)}, make([]int, 1), make([]conn.Endpoint, 1)
	if n, err := serverFns[0](serverBuf, serverSizes, serverEP); err != nil || n != 1 {
		t.Fatalf("server receive before drop: n=%d err=%v", n, err)
	}

	server.mu.Lock()
	var serverPeer *peer
	for _, p := range server.peers {
		serverPeer = p
	}
	server.mu.Unlock()
	if serverPeer == nil {
		t.Fatal("server never saw the client's peer")
	}
	_ = serverPeer.ws.Close(websocket.StatusNormalClosure, "simulated drop")
	select {
	case event := <-events:
		if event != "disconnected" {
			t.Fatalf("drop lifecycle event = %q", event)
		}
	case <-time.After(time.Second):
		t.Fatal("client never emitted disconnect lifecycle event")
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		if err := client.Send([][]byte{make([]byte, 16)}, ep); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("client never redialed: Send kept failing")
		}
		time.Sleep(5 * time.Millisecond)
	}

	serverBuf, serverSizes, serverEP = [][]byte{make([]byte, 64)}, make([]int, 1), make([]conn.Endpoint, 1)
	if n, err := serverFns[0](serverBuf, serverSizes, serverEP); err != nil || n != 1 || serverSizes[0] != 16 {
		t.Fatalf("server receive after redial: n=%d err=%v size=%d", n, err, serverSizes[0])
	}
	select {
	case event := <-events:
		if event != "connected" {
			t.Fatalf("redial lifecycle event = %q", event)
		}
	case <-time.After(time.Second):
		t.Fatal("client never emitted reconnect lifecycle event")
	}
}

// TestClientBindRedialUsesUpdatedHeader protects SetHeader: pkg/client's
// Connection.renew/reconnect call it on every control-plane token rotation
// specifically so a later redial presents a live token rather than the one
// Open originally dialed with, which the server's session store deletes on
// renewal (see pkg/server's renew handler). The test server enforces that
// itself -- only "new-token" is accepted -- so if SetHeader's value were
// ignored by redial, every attempt would 401 and Send would never recover.
func TestClientBindRedialUsesUpdatedHeader(t *testing.T) {
	server := NewServer()
	// OnPeerConnected fires (see ServeHTTP) only after the peer is inserted
	// into server.peers under the lock, so waiting on it below is a correct
	// happens-after signal -- unlike checking server.peers right after
	// client.Open returns, which races the server-side handler goroutine
	// that hasn't necessarily reached that insertion yet.
	peerConnected := make(chan struct{}, 1)
	server.OnPeerConnected = func(string, conn.Endpoint) {
		select {
		case peerConnected <- struct{}{}:
		default:
		}
	}
	if _, _, err := server.Open(0); err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	var expected atomic.Value
	expected.Store("old-token")
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token != expected.Load().(string) {
			http.Error(w, "invalid session", http.StatusUnauthorized)
			return
		}
		if err := server.ServeHTTP(w, r, "session"); err != nil {
			t.Error(err)
		}
	})
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listeners unavailable: %v", err)
	}
	h := &httptest.Server{Listener: l, Config: &http.Server{Handler: handler}}
	h.Start()
	defer h.Close()

	client := NewClient("ws"+h.URL[len("http"):], h.Client(), http.Header{"Authorization": {"Bearer old-token"}})
	client.SetRedialBackoff(5*time.Millisecond, 15*time.Millisecond, 500*time.Millisecond)
	if _, _, err := client.Open(0); err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ep, err := client.ParseEndpoint("127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-peerConnected:
	case <-time.After(3 * time.Second):
		t.Fatal("server never saw the client's peer")
	}

	server.mu.Lock()
	var serverPeer *peer
	for _, p := range server.peers {
		serverPeer = p
	}
	server.mu.Unlock()
	if serverPeer == nil {
		t.Fatal("server never saw the client's peer")
	}

	// Rotate the token before dropping the connection, mirroring a renewal
	// that happens independently of any network interruption.
	expected.Store("new-token")
	client.SetHeader(http.Header{"Authorization": {"Bearer new-token"}})
	_ = serverPeer.ws.Close(websocket.StatusNormalClosure, "simulated drop")

	deadline := time.Now().Add(3 * time.Second)
	for {
		if err := client.Send([][]byte{make([]byte, 16)}, ep); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("client never redialed successfully with the updated header")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestServerReplacesStaleClientPeerOnRedial covers a case a graceful close
// (as in TestClientBindRedialsAfterDrop) never exercises: an interface that
// vanishes without ever notifying the peer -- no FIN, no WebSocket close
// frame reaches the server, so its "session" peer entry is still live when
// the client's redial reaches it again. That is exactly what ServeHTTP's
// replace branch (old := b.peers[id]; old.ws.Close(); b.peers[id] = p) exists
// for, and what remove's b.peers[p.id] == p guard protects: the old peer's
// own read() goroutine, unwinding concurrently from that same Close, must
// not delete the just-installed new entry out from under it. The orphaned
// old peer is left untouched here (never closed by the test) to stand in for
// the vanished interface, and redial is called directly -- read()'s defer
// calls it the same way after a real read error, which
// TestClientBindRedialsAfterDrop already covers.
func TestServerReplacesStaleClientPeerOnRedial(t *testing.T) {
	server := NewServer()
	serverFns, _, err := server.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	// Unlike the other tests' handlers, this one must not call any t method:
	// the orphaned old peer's own read() goroutine (left running by design,
	// see below) spawns its own redial once the server later closes it as
	// part of the replace this test provokes, and that redial's dial can
	// legitimately land after this test function has returned -- t.Error
	// from a goroutine at that point panics the whole test binary. The
	// test's real assertions run synchronously below and don't depend on
	// this handler ever reporting anything.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = server.ServeHTTP(w, r, "session")
	})
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listeners unavailable: %v", err)
	}
	h := &httptest.Server{Listener: l, Config: &http.Server{Handler: handler}}
	h.Start()
	defer h.Close()

	client := NewClient("ws"+h.URL[len("http"):], h.Client(), nil)
	clientFns, _, err := client.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// Replacing the deliberately orphaned connection below closes it on the
	// server. Its read goroutine would then start an unrelated automatic
	// redial, racing the explicit redial this test is exercising.
	client.DisableRedial()

	ep, err := client.ParseEndpoint("127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Send([][]byte{make([]byte, 16)}, ep); err != nil {
		t.Fatalf("initial send: %v", err)
	}
	serverBuf, serverSizes, serverEP := [][]byte{make([]byte, 64)}, make([]int, 1), make([]conn.Endpoint, 1)
	if n, err := serverFns[0](serverBuf, serverSizes, serverEP); err != nil || n != 1 {
		t.Fatalf("server receive before drop: n=%d err=%v", n, err)
	}

	// Abandon the client's peer -- no Close on either side -- and redial
	// directly, standing in for read()'s defer after the interface vanished.
	client.mu.Lock()
	delete(client.peers, "remote")
	client.mu.Unlock()
	client.redial()

	client.mu.Lock()
	_, reconnected := client.peers["remote"]
	client.mu.Unlock()
	if !reconnected {
		t.Fatal("redial did not install a new client-side peer")
	}

	if err := client.Send([][]byte{make([]byte, 16)}, ep); err != nil {
		t.Fatalf("send over the redialed connection: %v", err)
	}
	serverBuf, serverSizes, serverEP = [][]byte{make([]byte, 64)}, make([]int, 1), make([]conn.Endpoint, 1)
	if n, err := serverFns[0](serverBuf, serverSizes, serverEP); err != nil || n != 1 || serverSizes[0] != 16 {
		t.Fatalf("server receive after redial: n=%d err=%v size=%d", n, err, serverSizes[0])
	}

	// The server must still be able to push data back over the new
	// connection: if remove() had incorrectly deleted the new entry (racing
	// against ServeHTTP's replace of the stale one), this would fail with
	// "WebSocket peer is not connected".
	if err := server.Send([][]byte{make([]byte, 16)}, serverEP[0]); err != nil {
		t.Fatalf("server send back over the redialed connection: %v", err)
	}
	result := make(chan error, 1)
	go func() {
		buf, sizes, eps := [][]byte{make([]byte, 64)}, make([]int, 1), make([]conn.Endpoint, 1)
		n, err := clientFns[0](buf, sizes, eps)
		if err == nil && (n != 1 || sizes[0] != 16) {
			err = fmt.Errorf("n=%d size=%d", n, sizes[0])
		}
		result <- err
	}()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("client never received the server's reply: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the client to receive the server's reply")
	}
}
