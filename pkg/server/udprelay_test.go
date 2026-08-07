package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"golang.zx2c4.com/wireguard/conn"
)

// fakeUDPAllocator stands in for *RelayAgent in tests, via the
// udpSessionAllocator interface, so sessionFor's idempotency and error
// handling can be exercised without a live relay control connection.
type fakeUDPAllocator struct {
	mu         sync.Mutex
	allocateN  int
	token      string
	serverAddr string
	err        error
	released   []string
}

func (f *fakeUDPAllocator) AllocateUDPSession(context.Context) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allocateN++
	return f.token, f.serverAddr, f.err
}

func (f *fakeUDPAllocator) ReleaseUDPSession(token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.released = append(f.released, token)
}

func (f *fakeUDPAllocator) allocations() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.allocateN
}

// newTestUDPRelay builds a udpRelay wired to a fake allocator and a real,
// throwaway wgnet.Stack/FilterBind pair -- UpdateEndpoint and SendControl
// both need something real underneath, but neither needs a live relay.
func newTestUDPRelay(t *testing.T, fa *fakeUDPAllocator) *udpRelay {
	t.Helper()
	stack, err := wgnet.New(wgnet.Config{Addresses: []netip.Addr{netip.MustParseAddr("100.70.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })

	bind := wstransport.NewFilterBind(conn.NewStdNetBind())
	if _, _, err := bind.Open(0); err != nil {
		t.Skipf("loopback UDP unavailable: %v", err)
	}
	t.Cleanup(func() { _ = bind.Close() })

	return &udpRelay{bind: bind, stack: stack, agent: fa, relayAddr: "127.0.0.1:1", log: slog.Default(), sessions: map[string]*udpRelaySessionState{}}
}

func TestUDPRelaySessionForIsIdempotent(t *testing.T) {
	fa := &fakeUDPAllocator{token: "tok-1", serverAddr: "127.0.0.1:9999"}
	u := newTestUDPRelay(t, fa)
	peer, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	resp1 := u.sessionFor(context.Background(), peer.Public, false, false)
	if resp1.Token != "tok-1" || resp1.RelayAddr != "127.0.0.1:1" {
		t.Fatalf("sessionFor() first call = %+v, want token/relay_addr populated", resp1)
	}
	resp2 := u.sessionFor(context.Background(), peer.Public, false, false)
	if resp2 != resp1 {
		t.Fatalf("sessionFor() second call = %+v, want identical to first %+v", resp2, resp1)
	}
	if got := fa.allocations(); got != 1 {
		t.Fatalf("AllocateUDPSession called %d times, want exactly 1 (idempotent)", got)
	}
}

func TestUDPRelaySessionForReturnsEmptyWhenAllocationUnavailable(t *testing.T) {
	fa := &fakeUDPAllocator{} // zero-value token/serverAddr: mirrors "no live control connection"
	u := newTestUDPRelay(t, fa)
	peer, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	resp := u.sessionFor(context.Background(), peer.Public, false, false)
	if resp != (protocol.UDPRelayResponse{}) {
		t.Fatalf("sessionFor() = %+v, want the zero value when allocation is unavailable", resp)
	}
}

func TestUDPRelayReleaseStopsSessionAndReleasesOnAgent(t *testing.T) {
	fa := &fakeUDPAllocator{token: "tok-1", serverAddr: "127.0.0.1:9999"}
	u := newTestUDPRelay(t, fa)
	peer, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	resp := u.sessionFor(context.Background(), peer.Public, false, false)
	u.release(peer.Public)

	fa.mu.Lock()
	released := append([]string(nil), fa.released...)
	fa.mu.Unlock()
	if len(released) != 1 || released[0] != resp.Token {
		t.Fatalf("released tokens = %v, want [%q]", released, resp.Token)
	}

	// A fresh sessionFor call after release must allocate again, not reuse
	// stale state.
	fa.token = "tok-2"
	resp2 := u.sessionFor(context.Background(), peer.Public, false, false)
	if resp2.Token != "tok-2" {
		t.Fatalf("sessionFor() after release = %+v, want a fresh allocation", resp2)
	}
	if got := fa.allocations(); got != 2 {
		t.Fatalf("AllocateUDPSession called %d times after release+re-request, want 2", got)
	}
}

func TestUDPRelayHandlerRequiresValidSession(t *testing.T) {
	s, _, _ := newTestServer(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/udp-relay", bytes.NewReader([]byte(`{}`)))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestUDPRelayHandlerReturns404WhenTierDisabled(t *testing.T) {
	s, _, _ := newTestServer(t, nil)
	sess := s.sessions.Create(CreateParams{WireGuardPublicKey: "peer-key", TTL: time.Minute})
	req := httptest.NewRequest(http.MethodPost, "/v1/udp-relay", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer "+sess.Token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d (udp relay tier never enabled)", w.Code, http.StatusNotFound)
	}
}

func TestUDPRelayHandlerReturns200WithSessionWhenEnabled(t *testing.T) {
	s, _, _ := newTestServer(t, nil)
	peer, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sess := s.sessions.Create(CreateParams{WireGuardPublicKey: peer.Public, TTL: time.Minute})

	fa := &fakeUDPAllocator{token: "tok-1", serverAddr: "127.0.0.1:9999"}
	s.udpr.Store(newTestUDPRelay(t, fa))

	req := httptest.NewRequest(http.MethodPost, "/v1/udp-relay", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer "+sess.Token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp protocol.UDPRelayResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Token != "tok-1" || resp.RelayAddr != "127.0.0.1:1" {
		t.Fatalf("response = %+v, want token/relay_addr populated", resp)
	}
}
