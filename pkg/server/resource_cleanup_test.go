package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

type blockingUDPAllocator struct {
	mu       sync.Mutex
	calls    int
	entered  chan struct{}
	proceed  chan struct{}
	released []string
}

func (a *blockingUDPAllocator) AllocateUDPSession(ctx context.Context) (string, string, error) {
	a.mu.Lock()
	a.calls++
	n := a.calls
	a.mu.Unlock()
	a.entered <- struct{}{}
	// Deliberately return a late token even after cancellation: the server must
	// release a reply that raced with release/stopAll, not publish it.
	<-a.proceed
	return fmt.Sprint("token-", n), "127.0.0.1:19000", nil
}
func (a *blockingUDPAllocator) ReleaseUDPSession(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.released = append(a.released, token)
}
func newBlockingUDPAllocator() *blockingUDPAllocator {
	return &blockingUDPAllocator{entered: make(chan struct{}, 64), proceed: make(chan struct{})}
}
func receiveUDPResponse(t *testing.T, ch <-chan protocol.UDPRelayResponse) protocol.UDPRelayResponse {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("allocation did not finish")
		return protocol.UDPRelayResponse{}
	}
}
func TestUDPRelayConcurrentAllocationSingleOwner(t *testing.T) {
	u := newTestUDPRelay(t, &fakeUDPAllocator{})
	a := newBlockingUDPAllocator()
	u.agent = a
	k, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan protocol.UDPRelayResponse, 32)
	for range 32 {
		go func() { out <- u.sessionFor(context.Background(), k.Public, false, false, nil) }()
	}
	<-a.entered
	// Also exercise cancellation of an independent waiter while allocation is pending.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := u.sessionFor(ctx, k.Public, false, false, nil); got.Token != "" {
		t.Fatal("canceled waiter got a token")
	}
	close(a.proceed)
	for range 32 {
		if got := receiveUDPResponse(t, out); got.Token != "token-1" {
			t.Fatalf("got %q", got.Token)
		}
	}
	u.mu.Lock()
	st := u.sessions[k.Public]
	u.mu.Unlock()
	u.release(k.Public)
	select {
	case <-st.stop:
	default:
		t.Fatal("keepalive not stopped")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.calls != 1 || len(a.released) != 1 {
		t.Fatalf("allocations=%d releases=%v", a.calls, a.released)
	}
}
func TestUDPRelayAllocationCanceledByCleanup(t *testing.T) {
	for _, stopAll := range []bool{false, true} {
		t.Run(fmt.Sprint("stopAll=", stopAll), func(t *testing.T) {
			u := newTestUDPRelay(t, &fakeUDPAllocator{})
			a := newBlockingUDPAllocator()
			u.agent = a
			k, err := wgnet.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}
			out := make(chan protocol.UDPRelayResponse, 1)
			go func() { out <- u.sessionFor(context.Background(), k.Public, false, false, nil) }()
			<-a.entered
			if stopAll {
				u.stopAll()
			} else {
				u.release(k.Public)
			}
			close(a.proceed)
			if got := receiveUDPResponse(t, out); got.Token != "" {
				t.Fatalf("resurrected allocation: %+v", got)
			}
			u.mu.Lock()
			n, pending := len(u.sessions), len(u.pending)
			u.mu.Unlock()
			if n != 0 || pending != 0 {
				t.Fatalf("sessions=%d pending=%d", n, pending)
			}
			a.mu.Lock()
			defer a.mu.Unlock()
			if len(a.released) != 1 {
				t.Fatalf("late token releases=%v", a.released)
			}
			if stopAll {
				if got := u.sessionFor(context.Background(), k.Public, false, false, nil); got.Token != "" {
					t.Fatal("stopped relay allocated")
				}
			}
		})
	}
}
func TestDropSessionRemovesMultipathPeer(t *testing.T) {
	s, _, _ := newTestServer(t, nil)
	startTestDataPlane(t, s)
	k, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ep, err := s.data.ws.UDP.ParseEndpoint("127.0.0.1:19000")
	if err != nil {
		t.Fatal(err)
	}
	s.data.multipath.RegisterPath(k.Public, "wss", wstransport.PathWSS, ep, false)
	s.dropSession(Session{WireGuardPublicKey: k.Public})
	if _, err := s.data.multipath.ParseEndpoint(k.Public); err == nil {
		t.Fatal("multipath peer survived session cleanup")
	}
}
func TestServerCloseStopsRelayBackgroundLoops(t *testing.T) {
	s, _, _ := newTestServer(t, nil)
	startTestDataPlane(t, s)
	u := newTestUDPRelay(t, &fakeUDPAllocator{token: "test", serverAddr: "127.0.0.1:19000"})
	k, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	u.sessionFor(context.Background(), k.Public, false, false, nil)
	u.mu.Lock()
	st := u.sessions[k.Public]
	u.mu.Unlock()
	s.udpr.Store(u)
	d := &directUDP{stop: make(chan struct{})}
	s.direct = d
	s.Close()
	select {
	case <-st.stop:
	default:
		t.Fatal("relay keepalive remains live")
	}
	select {
	case <-d.stop:
	default:
		t.Fatal("direct reflection remains live")
	}
	if s.udpr.Load() != nil || s.direct != nil {
		t.Fatal("shutdown retained background state")
	}
}

type recoveringDNSConn struct {
	net.PacketConn
	reads  int
	writes chan struct{}
	query  []byte
}

func (c *recoveringDNSConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.reads++
	if c.reads == 1 {
		return 0, nil, fmt.Errorf("transient read failure")
	}
	if c.reads == 2 {
		return copy(b, c.query), &net.UDPAddr{IP: net.ParseIP("100.64.0.8"), Port: 1234}, nil
	}
	return 0, nil, net.ErrClosed
}
func (c *recoveringDNSConn) WriteTo(b []byte, a net.Addr) (int, error) {
	c.writes <- struct{}{}
	return len(b), nil
}
func TestDNSLoopRecoversAfterReadError(t *testing.T) {
	s := newTestServerForDNS()
	// A well-formed empty query still receives REFUSED for an unknown source.
	c := &recoveringDNSConn{query: make([]byte, 12), writes: make(chan struct{}, 1)}
	s.dnsLoop(&dataPlane{dnsConn: c, stop: make(chan struct{})})
	select {
	case <-c.writes:
	case <-time.After(time.Second):
		t.Fatal("DNS never processed the next packet")
	}
	if c.reads != 3 {
		t.Fatalf("reads=%d", c.reads)
	}
}
func TestDNSLoopStopsDuringRetry(t *testing.T) {
	s := newTestServerForDNS()
	stop := make(chan struct{})
	close(stop)
	c := &recoveringDNSConn{}
	s.dnsLoop(&dataPlane{dnsConn: c, stop: stop})
	if c.reads != 1 {
		t.Fatalf("reads after shutdown=%d", c.reads)
	}
}

func TestRelayDataDialHonorsCancellation(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-release }))
	defer srv.Close()
	defer close(release)
	a, err := NewRelayAgent(RelayConfig{URL: srv.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { a.handleOpen(ctx, protocol.RelayOpen{ConnID: "test"}); close(done) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("dial not started")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled data dial still blocked")
	}
}
func TestRelayDataConnectionSurvivesDialContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer ws.CloseNow()
		for {
			typ, b, err := ws.Read(r.Context())
			if err != nil {
				return
			}
			if ws.Write(r.Context(), typ, b) != nil {
				return
			}
		}
	}))
	defer srv.Close()
	a, err := NewRelayAgent(RelayConfig{URL: srv.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	done := make(chan struct{})
	go func() { a.handleOpen(context.Background(), protocol.RelayOpen{ConnID: "test"}); close(done) }()
	c, err := a.Listener().Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	<-done // handleOpen's deferred dial cancellation has now run.
	c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 5)
	n, err := c.Read(b)
	if err != nil || string(b[:n]) != "hello" {
		t.Fatalf("echo=%q err=%v", b[:n], err)
	}
}

func TestRelayReplacementAndShutdownConcurrent(t *testing.T) {
	s, _, _ := newTestServer(t, nil)
	startTestDataPlane(t, s)
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			for range 10 {
				s.EnableDirectUpgrade("127.0.0.1:19001")
				s.EnableUDPRelay(nil, "127.0.0.1:19002")
				s.EnableNativeWireGuardRelay("", "")
			}
		})
	}
	wg.Go(s.Close)
	wg.Wait()
	s.Close()
	if s.data != nil || s.udpr.Load() != nil || s.direct != nil {
		t.Fatal("relay state recreated after shutdown")
	}
}
