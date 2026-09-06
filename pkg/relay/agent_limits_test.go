package relay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// newTLSAgentServer starts a TLS test server for a fresh agentServer built from
// reg and limits; newTLSAgentServerFrom does the same for a caller that needs to
// keep the agentServer to inspect it.
func newTLSAgentServer(t *testing.T, reg *Registry, limits Limits) *httptest.Server {
	t.Helper()
	return newTLSAgentServerFrom(t, newAgentServer(reg, "relay.example.com", limits, nil))
}

func newTLSAgentServerFrom(t *testing.T, a *agentServer) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(a.Handler())
}

// TestAgentServer_SilentRegistrationTimesOut is the regression test for the
// unauthenticated resource-exhaustion finding: listen.agents is internet-facing
// by necessity, and net/http's ReadHeaderTimeout stops applying once the
// connection is hijacked, so a client that upgrades and then says nothing must
// be dropped rather than holding a goroutine and an fd indefinitely.
func TestAgentServer_SilentRegistrationTimesOut(t *testing.T) {
	k := generateTestKey(t)
	limits := testLimits()
	limits.HandshakeTimeout = 150 * time.Millisecond
	reg := NewRegistry([]Registration{{Name: "home", PublicKey: k.pub}}, limits)
	srv := newTLSAgentServer(t, reg, limits)
	defer srv.Close()

	ws := dialControl(t, srv)
	defer ws.Close(websocket.StatusInternalError, "")

	// Send nothing. The server must close the connection on its own.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := ws.Read(ctx); err == nil {
		t.Fatal("a control connection that never registers should be closed by the server")
	} else if ctx.Err() != nil {
		t.Fatal("the server held a silent control connection past the handshake timeout")
	}
}

// TestAgentServer_RegistrationRateLimited covers the per-source cap on
// registration attempts. listen.public has had one all along; listen.agents had
// none, so an anonymous caller could open control connections as fast as it
// liked.
func TestAgentServer_RegistrationRateLimited(t *testing.T) {
	k := generateTestKey(t)
	limits := testLimits()
	limits.MaxRegistrationsPerMinute = 2
	reg := NewRegistry([]Registration{{Name: "home", PublicKey: k.pub}}, limits)
	srv := newTLSAgentServer(t, reg, limits)
	defer srv.Close()

	url := "wss" + strings.TrimPrefix(srv.URL, "https") + "/v1/relay/control"
	var lastStatus int
	for i := 0; i < limits.MaxRegistrationsPerMinute+1; i++ {
		ws, resp, err := websocket.Dial(context.Background(), url, &websocket.DialOptions{HTTPClient: srv.Client()})
		if err == nil {
			defer ws.Close(websocket.StatusInternalError, "")
		}
		if resp != nil {
			lastStatus = resp.StatusCode
		}
	}
	if lastStatus != http.StatusTooManyRequests {
		t.Fatalf("attempt over the per-source limit: status = %d, want %d", lastStatus, http.StatusTooManyRequests)
	}
}

// TestAgentServer_PendingRegistrationsCapped covers the concurrent half-open
// cap: the rate limit alone bounds attempts per minute, not how many
// connections one caller can hold open at once.
func TestAgentServer_PendingRegistrationsCapped(t *testing.T) {
	k := generateTestKey(t)
	limits := testLimits()
	limits.HandshakeTimeout = 10 * time.Second // long, so slots stay occupied
	limits.MaxPendingRegistrations = 2
	reg := NewRegistry([]Registration{{Name: "home", PublicKey: k.pub}}, limits)
	srv := newTLSAgentServer(t, reg, limits)
	defer srv.Close()

	url := "wss" + strings.TrimPrefix(srv.URL, "https") + "/v1/relay/control"
	var lastStatus int
	for i := 0; i < limits.MaxPendingRegistrations+1; i++ {
		ws, resp, err := websocket.Dial(context.Background(), url, &websocket.DialOptions{HTTPClient: srv.Client()})
		if err == nil {
			defer ws.Close(websocket.StatusInternalError, "")
		}
		if resp != nil {
			lastStatus = resp.StatusCode
		}
	}
	if lastStatus != http.StatusServiceUnavailable {
		t.Fatalf("connection over the pending cap: status = %d, want %d", lastStatus, http.StatusServiceUnavailable)
	}
}

// TestAgentServer_RegisteredAgentFreesPendingSlot checks that a completed
// registration releases its half-open slot, so the cap bounds unauthenticated
// connections rather than the number of tenants that can stay connected.
func TestAgentServer_RegisteredAgentFreesPendingSlot(t *testing.T) {
	k := generateTestKey(t)
	limits := testLimits()
	limits.MaxPendingRegistrations = 1
	reg := NewRegistry([]Registration{{Name: "home", PublicKey: k.pub}}, limits)
	agents := newAgentServer(reg, "relay.example.com", limits, nil)
	srv := newTLSAgentServerFrom(t, agents)
	defer srv.Close()

	ws := dialControl(t, srv)
	defer ws.Close(websocket.StatusNormalClosure, "")
	if resp := registerOverControl(t, ws, signedRegisterRequest(t, k, "home", "n1")); resp.Error != "" {
		t.Fatalf("registration failed: %s", resp.Error)
	}

	deadline := time.Now().Add(2 * time.Second)
	for agents.pending.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := agents.pending.Load(); got != 0 {
		t.Fatalf("a registered agent still occupies %d pending slot(s)", got)
	}
}
