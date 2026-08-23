package client

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"golang.zx2c4.com/wireguard/conn"
)

// freeUDPPortForTest finds a currently-unused UDP port by briefly binding to
// 127.0.0.1:0 and releasing it, mirroring pkg/wgnet's test helper of the
// same shape (unexported there, so duplicated here rather than exported
// purely for tests).
func freeUDPPortForTest(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Skipf("loopback UDP unavailable: %v", err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// pumpReceive drains a conn.ReceiveFunc forever, discarding whatever it
// returns. FilterBind only intercepts control frames as a side effect of its
// wrapped receive func actually being called -- exactly as wireguard-go's
// own receive loop would call it in production -- so tests exercising
// Control() need something playing that role.
func pumpReceive(batchSize int, fn conn.ReceiveFunc) {
	bufs, sizes, eps := receiveBatch(batchSize)
	for {
		if _, err := fn(bufs, sizes, eps); err != nil {
			return
		}
	}
}

func TestSelfReflectReturnsObservedAddress(t *testing.T) {
	serverBind := wstransport.NewFilterBind(conn.NewStdNetBind())
	fns, serverPort, err := serverBind.Open(0)
	if err != nil {
		t.Skipf("loopback UDP unavailable: %v", err)
	}
	defer serverBind.Close()
	for _, fn := range fns {
		go pumpReceive(serverBind.BatchSize(), fn)
	}
	go func() {
		for cp := range serverBind.Control() {
			if cp.Type == wstransport.FrameReflectRequest {
				_ = serverBind.SendControl(wstransport.FrameReflectResponse, []byte(cp.From.String()), cp.From.String())
			}
		}
	}()

	clientBind := wstransport.NewFilterBind(conn.NewStdNetBind())
	clientFns, _, err := clientBind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer clientBind.Close()
	// selfReflect's reply arrives on the client's own receive func, which in
	// production a real wireguard-go device pumps continuously once the
	// Stack is up. Nothing else in this narrow test does that, so it has to
	// be pumped explicitly here for the reply to ever reach Control().
	for _, fn := range clientFns {
		go pumpReceive(clientBind.BatchSize(), fn)
	}

	addr, err := selfReflect(clientBind, "127.0.0.1:"+strconv.Itoa(int(serverPort)), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if addr == "" {
		t.Fatal("selfReflect() returned an empty address")
	}
}

func TestSelfReflectTimesOutWithNoResponder(t *testing.T) {
	clientBind := wstransport.NewFilterBind(conn.NewStdNetBind())
	if _, _, err := clientBind.Open(0); err != nil {
		t.Fatal(err)
	}
	defer clientBind.Close()

	unusedPort := freeUDPPortForTest(t)
	if _, err := selfReflect(clientBind, "127.0.0.1:"+strconv.Itoa(unusedPort), 300*time.Millisecond); err == nil {
		t.Fatal("selfReflect() succeeded with no responder, want a timeout error")
	}
}

func TestPrimeAddrSendsBurst(t *testing.T) {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback UDP unavailable: %v", err)
	}
	defer listener.Close()

	clientBind := wstransport.NewFilterBind(conn.NewStdNetBind())
	if _, _, err := clientBind.Open(0); err != nil {
		t.Fatal(err)
	}
	defer clientBind.Close()

	primeAddr(clientBind, listener.LocalAddr().String())

	_ = listener.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	got := 0
	for got < wstransport.PrimeBurst {
		n, _, err := listener.ReadFrom(buf)
		if err != nil {
			t.Fatalf("received %d prime frames before a read error (%v), want %d", got, err, wstransport.PrimeBurst)
		}
		if typ, _, ok := wstransport.DecodeControlFrame(buf[:n]); ok && typ == wstransport.FramePrime {
			got++
		}
	}
}

func TestPostPunchParsesSuccessResponse(t *testing.T) {
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_ = json.NewEncoder(w).Encode(protocol.PunchResponse{ServerAddr: "1.2.3.4:5", RelayReflectAddr: "5.6.7.8:9"})
	}))
	defer srv.Close()

	c := &Connection{http: srv.Client(), base: srv.URL, token: "tok"}
	resp, err := c.postPunch("9.9.9.9:1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.ServerAddr != "1.2.3.4:5" || resp.RelayReflectAddr != "5.6.7.8:9" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer tok")
	}
	if !strings.Contains(gotBody, "9.9.9.9:1") {
		t.Errorf("request body = %q, want it to contain the client address", gotBody)
	}
}

// TestPostPunch404ReturnsZeroValueNotError guards the steady state a server
// without relay.advertise_direct enabled (or an old server predating this
// feature) puts every client in: postPunch must treat that as "nothing to
// do" rather than an error the retry loop would log noisily forever.
func TestPostPunch404ReturnsZeroValueNotError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := &Connection{http: srv.Client(), base: srv.URL, token: "tok"}
	resp, err := c.postPunch("")
	if err != nil {
		t.Fatalf("postPunch() error = %v, want nil for a 404", err)
	}
	if resp.ServerAddr != "" || resp.RelayReflectAddr != "" || len(resp.Candidates) != 0 {
		t.Fatalf("postPunch() = %+v, want the zero value", resp)
	}
}

func TestDirectCandidateForReflectorPrefersMatchingPoolPair(t *testing.T) {
	resp := protocol.PunchResponse{
		ServerAddr: "legacy:1", RelayReflectAddr: "legacy:2",
		Candidates: []protocol.DirectCandidate{
			{RelayReflectAddr: "relay-a:1", ServerAddr: "server-a:1"},
			{RelayReflectAddr: "relay-b:1", ServerAddr: "server-b:1"},
		},
	}
	reflector, server := directCandidateForReflector(resp, "relay-b:1")
	if reflector != "relay-b:1" || server != "server-b:1" {
		t.Fatalf("pair = (%q, %q), want relay-b/server-b", reflector, server)
	}
}

func TestPostUDPRelayParsesSuccessResponse(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(protocol.UDPRelayResponse{RelayAddr: "1.2.3.4:5", Token: "tok-1"})
	}))
	defer srv.Close()

	c := &Connection{http: srv.Client(), base: srv.URL, token: "tok"}
	resp, err := c.postUDPRelay()
	if err != nil {
		t.Fatal(err)
	}
	if resp.RelayAddr != "1.2.3.4:5" || resp.Token != "tok-1" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer tok")
	}
}

// TestPostUDPRelay404ReturnsZeroValueNotError guards the steady state a
// server whose relay offers no UDP-relay tier (or an old server predating
// this feature) puts every client in: postUDPRelay must treat that as
// "nothing to do" rather than an error the retry loop would log noisily
// forever, exactly like postPunch's identical treatment of its own 404.
func TestPostUDPRelay404ReturnsZeroValueNotError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := &Connection{http: srv.Client(), base: srv.URL, token: "tok"}
	resp, err := c.postUDPRelay()
	if err != nil {
		t.Fatalf("postUDPRelay() error = %v, want nil for a 404", err)
	}
	if resp != (protocol.UDPRelayResponse{}) {
		t.Fatalf("postUDPRelay() = %+v, want the zero value", resp)
	}
}

// TestTryUDPRelayUpgradeReportsUnavailableReason guards
// directUpgradeLoop's same-tick fallthrough rule: a server with no
// UDP-relay tier available must produce exactly udpRelayUnavailableReason,
// not some other failure string, since that specific value is what licenses
// falling through to the full-escape attempt on the same tick.
func TestTryUDPRelayUpgradeReportsUnavailableReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	clientBind := wstransport.NewFilterBind(conn.NewStdNetBind())
	if _, _, err := clientBind.Open(0); err != nil {
		t.Skipf("loopback UDP unavailable: %v", err)
	}
	defer clientBind.Close()

	c := &Connection{http: srv.Client(), base: srv.URL, token: "tok", upgradeTiming: defaultDirectUpgradeTiming(), log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	candidate, token, reason := c.tryUDPRelayUpgrade(clientBind)
	if candidate != "" || token != "" {
		t.Fatalf("tryUDPRelayUpgrade() = (%q, %q, %q), want empty candidate/token", candidate, token, reason)
	}
	if reason != udpRelayUnavailableReason {
		t.Fatalf("tryUDPRelayUpgrade() reason = %q, want %q", reason, udpRelayUnavailableReason)
	}
}

// peeredClientServerStacks builds two real wgnet Stacks over loopback UDP,
// peered exactly the way pkg/server and pkg/client do in production (see
// wgnet_test.go's TestStackRoundTripsTCPThroughWireGuardPeers), so
// probeDirectPath's assumption about gVisor's netstack -- that a SYN to an
// unbound port gets a prompt refusal rather than silence -- is verified
// against the real thing rather than asserted in a comment.
func peeredClientServerStacks(t *testing.T) (serverStack, clientStack *wgnet.Stack, serverIP netip.Addr) {
	t.Helper()
	serverPort := freeUDPPortForTest(t)
	serverIP = netip.MustParseAddr("100.65.9.1")
	clientIP := netip.MustParseAddr("100.65.9.2")

	var err error
	serverStack, err = wgnet.New(wgnet.Config{Addresses: []netip.Addr{serverIP}, ListenPort: serverPort})
	if err != nil {
		t.Fatalf("server wgnet.New() = %v", err)
	}
	t.Cleanup(func() { _ = serverStack.Close() })
	clientStack, err = wgnet.New(wgnet.Config{Addresses: []netip.Addr{clientIP}})
	if err != nil {
		t.Fatalf("client wgnet.New() = %v", err)
	}
	t.Cleanup(func() { _ = clientStack.Close() })

	if err := serverStack.AddPeer(wgnet.Endpoint{PublicKey: clientStack.PublicKey(), Address: clientIP.String() + "/32"}); err != nil {
		t.Fatalf("server.AddPeer() = %v", err)
	}
	if err := clientStack.AddPeer(wgnet.Endpoint{PublicKey: serverStack.PublicKey(), Address: "0.0.0.0/0@127.0.0.1:" + strconv.Itoa(serverPort)}); err != nil {
		t.Fatalf("client.AddPeer() = %v", err)
	}
	return serverStack, clientStack, serverIP
}

func TestProbeDirectPathSucceedsWhenServerReachable(t *testing.T) {
	_, clientStack, serverIP := peeredClientServerStacks(t)
	c := &Connection{Stack: clientStack, serverTunnelIP: serverIP, upgradeTiming: defaultDirectUpgradeTiming()}
	if !c.probeDirectPath() {
		t.Fatal("probeDirectPath() = false, want true: an unbound port should still refuse promptly, proving round-trip connectivity over the direct path")
	}
}

func TestProbeDirectPathFailsWhenNoServerListening(t *testing.T) {
	unusedPort := freeUDPPortForTest(t)
	serverIP := netip.MustParseAddr("100.65.10.1")
	clientIP := netip.MustParseAddr("100.65.10.2")
	peerKey, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	clientStack, err := wgnet.New(wgnet.Config{Addresses: []netip.Addr{clientIP}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientStack.Close() })
	if err := clientStack.AddPeer(wgnet.Endpoint{PublicKey: peerKey.Public, Address: "0.0.0.0/0@127.0.0.1:" + strconv.Itoa(unusedPort)}); err != nil {
		t.Fatal(err)
	}

	timing := defaultDirectUpgradeTiming()
	c := &Connection{Stack: clientStack, serverTunnelIP: serverIP, upgradeTiming: timing}
	start := time.Now()
	if c.probeDirectPath() {
		t.Fatal("probeDirectPath() = true, want false: no server is listening at all")
	}
	if elapsed := time.Since(start); elapsed < timing.probeTimeout-500*time.Millisecond {
		t.Errorf("probeDirectPath() returned after %v, suspiciously fast for a full probe timeout of %v", elapsed, timing.probeTimeout)
	}
}

func TestProbeDirectPathFailsWithoutServerTunnelIP(t *testing.T) {
	_, clientStack, _ := peeredClientServerStacks(t)
	c := &Connection{Stack: clientStack, upgradeTiming: defaultDirectUpgradeTiming()}
	if c.probeDirectPath() {
		t.Fatal("probeDirectPath() = true with no serverTunnelIP set, want false")
	}
}

// TestMultipathUDPRelayHealthRequiresUDPRelayProbe protects active flows
// during a carrier migration. A TCP probe through the stable logical endpoint
// can succeed over WSS while a newly added UDP relay candidate is still dead;
// that must not be treated as a UDP upgrade.
func TestMultipathUDPRelayHealthRequiresUDPRelayProbe(t *testing.T) {
	multipath := wstransport.NewMultipathBind(conn.NewStdNetBind(), "server", false, wstransport.V2Options{})
	defer multipath.Close()

	now := time.Now()
	multipath.Scheduler().Register("wss", wstransport.PathWSS)
	multipath.Scheduler().ProbeResult("wss", time.Millisecond, true, now)
	multipath.Scheduler().Register("udp-relay", wstransport.PathUDPRelay)
	c := &Connection{multipath: multipath, upgradeTiming: defaultDirectUpgradeTiming()}
	if healthy, _ := c.pathHealthy("198.51.100.10:5000"); healthy {
		t.Fatal("pathHealthy() = true with only WSS healthy, want false for an unprobed UDP relay candidate")
	}

	multipath.Scheduler().ProbeResult("udp-relay", time.Millisecond, true, now)
	if healthy, reason := c.pathHealthy("198.51.100.10:5000"); !healthy {
		t.Fatalf("pathHealthy() = false (%s) after UDP relay probe acknowledgement, want true", reason)
	}
}

// TestSetEndpointReturnsErrorWhenWebSocketDisconnected reproduces the
// failure mode directUpgradeLoop's revert-retry logic exists for: reverting
// is itself an UpdateEndpoint call, which fails if the WebSocket fallback
// isn't currently connected (Bind.ParseEndpoint errors in that case -- see
// wstransport/bind.go). Before that retry logic existed, this failure was
// only logged at Debug and silently accepted, stranding the data plane
// pointed at a confirmed-dead direct address with nothing left to move it.
func TestSetEndpointReturnsErrorWhenWebSocketDisconnected(t *testing.T) {
	server := wstransport.NewServer()
	connected := make(chan struct{})
	server.OnPeerConnected = func(id string, _ conn.Endpoint) {
		if id == "session" {
			select {
			case <-connected:
			default:
				close(connected)
			}
		}
	}
	serverFns, _, err := server.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go pumpReceive(server.BatchSize(), serverFns[0])
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

	hybrid := wstransport.NewHybridClient("ws"+h.URL[len("http"):], h.Client(), nil, "")
	defer hybrid.Close()
	// This test wants the disconnect below to stay observably disconnected,
	// not race the client's automatic reconnect (see Bind.redial). redial's
	// first attempt fires with no backoff, so a well-timed one can win even
	// against a test that closes the peer's listener first: a connection
	// already past the OS's TCP handshake at the instant the listener closes
	// can still land, even though every later dial attempt is correctly
	// refused. Disabling it outright removes the race rather than trying to
	// out-time it.
	hybrid.WebSocket.DisableRedial()

	// wgnet.New brings the WireGuard device up itself (device.Up calls
	// BindUpdate, which closes and reopens whatever Bind it was given) --
	// so this used to also call hybrid.Open(0) here first. That created a
	// throwaway connection BindUpdate would immediately close and replace,
	// and the resulting close/reopen churn raced this test's own
	// CloseSession call below: if the throwaway connection's server-side
	// removal (from Bind.read's defer) landed in the gap before the real
	// connection's server-side registration, CloseSession's b.peers["session"]
	// lookup found nothing and silently no-opped, leaving the client's
	// WebSocket peer connected for the rest of the test -- observed as
	// ParseEndpoint never returning an error below. Letting wgnet.New make
	// the only connection avoids the churn, and the race, entirely.
	clientStack, err := wgnet.New(wgnet.Config{Addresses: []netip.Addr{netip.MustParseAddr("100.65.30.2")}, Bind: hybrid})
	if err != nil {
		t.Fatal(err)
	}
	defer clientStack.Close()
	peer, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := clientStack.AddPeer(wgnet.Endpoint{PublicKey: peer.Public, Address: "0.0.0.0/0@" + wstransport.WSSentinel}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-connected:
	case <-time.After(2 * time.Second):
		t.Fatal("WebSocket peer never became connected on the server")
	}

	// Kill the WebSocket connection from the server side, forcing the
	// client's own read loop to notice and remove it from its peer map --
	// exactly what a relay/server restart or network blip would also cause.
	server.CloseSession("session")
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := hybrid.ParseEndpoint(wstransport.WSSentinel); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("WebSocket peer never became disconnected")
		}
		time.Sleep(20 * time.Millisecond)
	}

	c := &Connection{Stack: clientStack, Response: protocol.AuthResponse{ServerPublicKey: peer.Public}}
	if err := c.setEndpoint(wstransport.WSSentinel); err == nil {
		t.Fatal("setEndpoint() succeeded despite a disconnected WebSocket peer, want an error so the caller retries instead of accepting it silently")
	}
}

func receiveBatch(batchSize int) ([][]byte, []int, []conn.Endpoint) {
	bufs := make([][]byte, batchSize)
	for i := range bufs {
		bufs[i] = make([]byte, 1500)
	}
	return bufs, make([]int, batchSize), make([]conn.Endpoint, batchSize)
}
