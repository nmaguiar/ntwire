package wstransport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

	client := NewHybridClient("ws"+h.URL[len("http"):], h.Client(), nil)
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

	_, client := NewMultipathHybridClient("ws"+h.URL[len("http"):], h.Client(), nil)
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
