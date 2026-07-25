package relay

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
	"golang.org/x/crypto/ssh"
)

type testKey struct {
	path string
	pub  ssh.PublicKey
	line string
}

func generateTestKey(t *testing.T) testKey {
	t.Helper()
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
	path := t.TempDir() + "/id"
	if err = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return testKey{path: path, pub: pub, line: string(ssh.MarshalAuthorizedKey(pub))}
}

func signedRegisterRequest(t *testing.T, k testKey, name, nonce string) protocol.RelayRegisterRequest {
	t.Helper()
	req := protocol.RelayRegisterRequest{
		Version: protocol.Version, PublicKey: k.line, Name: name,
		Timestamp: time.Now().UTC().Format(time.RFC3339), Nonce: nonce,
	}
	p, err := protocol.RelayRegisterPayload(req)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sshkey.SignFile(k.path, p)
	if err != nil {
		t.Fatal(err)
	}
	req.Signature = sig
	return req
}

func testLimits() Limits {
	return Limits{DialBackTimeout: 200 * time.Millisecond, MaxPendingPerServer: 2, MaxConnsPerServer: 2}
}

func TestRegistry_RegisterSuccess(t *testing.T) {
	k := generateTestKey(t)
	reg := NewRegistry([]Registration{{Name: "home", PublicKey: k.pub}}, testLimits())
	req := signedRegisterRequest(t, k, "home", "nonce-1")
	name, _, err := reg.Register(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "home" {
		t.Fatalf("name = %q, want home", name)
	}
}

func TestRegistry_RegisterUnknownKey(t *testing.T) {
	k := generateTestKey(t)
	other := generateTestKey(t)
	reg := NewRegistry([]Registration{{Name: "home", PublicKey: k.pub}}, testLimits())
	req := signedRegisterRequest(t, other, "home", "nonce-1")
	_, _, err := reg.Register(req)
	if err == nil || err.Code != protocol.ErrorUnknownKey {
		t.Fatalf("err = %v, want unknown_key", err)
	}
}

func TestRegistry_RegisterBadSignature(t *testing.T) {
	k := generateTestKey(t)
	reg := NewRegistry([]Registration{{Name: "home", PublicKey: k.pub}}, testLimits())
	req := signedRegisterRequest(t, k, "home", "nonce-1")
	req.Signature = req.Signature[:len(req.Signature)-4] + "abcd"
	_, _, err := reg.Register(req)
	if err == nil || err.Code != protocol.ErrorBadSignature {
		t.Fatalf("err = %v, want bad_signature", err)
	}
}

func TestRegistry_RegisterNameMismatch(t *testing.T) {
	k := generateTestKey(t)
	reg := NewRegistry([]Registration{{Name: "home", PublicKey: k.pub}}, testLimits())
	req := signedRegisterRequest(t, k, "not-home", "nonce-1")
	_, _, err := reg.Register(req)
	if err == nil || err.Code != protocol.ErrorRelayNameNotAllowed {
		t.Fatalf("err = %v, want relay_name_not_allowed", err)
	}
}

func TestRegistry_RegisterReplayedNonce(t *testing.T) {
	k := generateTestKey(t)
	reg := NewRegistry([]Registration{{Name: "home", PublicKey: k.pub}}, testLimits())
	req := signedRegisterRequest(t, k, "home", "reused-nonce")
	if _, _, err := reg.Register(req); err != nil {
		t.Fatalf("first registration failed: %v", err)
	}
	req2 := signedRegisterRequest(t, k, "home", "reused-nonce")
	req2.Timestamp = req.Timestamp
	req2.Signature = req.Signature
	if _, _, err := reg.Register(req2); err == nil || err.Code != protocol.ErrorReplayedNonce {
		t.Fatalf("err = %v, want replayed_nonce", err)
	}
}

func TestRegistry_RegisterClockSkew(t *testing.T) {
	k := generateTestKey(t)
	reg := NewRegistry([]Registration{{Name: "home", PublicKey: k.pub}}, testLimits())
	req := protocol.RelayRegisterRequest{
		Version: protocol.Version, PublicKey: k.line, Name: "home",
		Timestamp: time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339), Nonce: "n",
	}
	p, _ := protocol.RelayRegisterPayload(req)
	req.Signature, _ = sshkey.SignFile(k.path, p)
	_, _, err := reg.Register(req)
	if err == nil || err.Code != protocol.ErrorClockSkew {
		t.Fatalf("err = %v, want clock_skew", err)
	}
}

type fakeConn struct {
	net.Conn
	closed bool
}

func (f *fakeConn) Close() error { f.closed = true; return nil }

func TestRegistry_RegisterAgentEvictsPrior(t *testing.T) {
	reg := NewRegistry(nil, testLimits())
	var oldClosed bool
	old := &Agent{Name: "home", Push: func(protocol.RelayOpen) error { return nil }, Close: func() { oldClosed = true }}
	reg.RegisterAgent("home", old)

	var newClosed bool
	next := &Agent{Name: "home", Push: func(protocol.RelayOpen) error { return nil }, Close: func() { newClosed = true }}
	reg.RegisterAgent("home", next)

	if !oldClosed {
		t.Fatal("prior agent was not evicted/closed on re-registration")
	}
	if newClosed {
		t.Fatal("new agent should not be closed")
	}
}

func TestRegistry_OpenRedeemHappyPath(t *testing.T) {
	reg := NewRegistry(nil, testLimits())
	pushedCh := make(chan protocol.RelayOpen, 1)
	agent := &Agent{Name: "home", Push: func(o protocol.RelayOpen) error { pushedCh <- o; return nil }, Close: func() {}}
	reg.RegisterAgent("home", agent)

	resultCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := reg.Open(context.Background(), "home", "203.0.113.5:1234", "home.relay.test")
		resultCh <- c
		errCh <- err
	}()

	var pushed protocol.RelayOpen
	select {
	case pushed = <-pushedCh:
	case <-time.After(time.Second):
		t.Fatal("RelayOpen was never pushed")
	}
	if pushed.ClientAddr != "203.0.113.5:1234" || pushed.SNI != "home.relay.test" {
		t.Fatalf("unexpected RelayOpen: %+v", pushed)
	}

	handoff, ok := reg.Redeem(pushed.ConnID)
	if !ok {
		t.Fatal("Redeem failed on a fresh conn_id")
	}
	want := &fakeConn{}
	handoff.Deliver <- want

	if err := <-errCh; err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if got := <-resultCh; got != want {
		t.Fatal("Open did not return the delivered connection")
	}

	// Single-use: redeeming again must fail.
	if _, ok := reg.Redeem(pushed.ConnID); ok {
		t.Fatal("conn_id was redeemable a second time")
	}
}

// TestRegistry_HandoffAbandonedByTimeoutIsNotDeliverable is the regression
// test for the handleData handoff leak: Redeem can win the race against
// Open's own dial-back timeout, handing agent.go's handleData a live
// Handoff for a conn_id whose Open has already given up. Before Handoff.Done
// existed, handleData would still send into Deliver's one-slot buffer with
// nobody ever left to read or close it -- a permanent fd leak, once per lost
// race.
//
// This drives Registry directly rather than through a real HTTP/WebSocket
// round trip: in production the window between Redeem succeeding and
// handleData attempting delivery is only the time to complete a WS
// handshake, far faster than any DialBackTimeout, so forcing that exact
// interleaving deterministically over real sockets would itself be racy.
// Redeeming immediately after the push and only then waiting for Open to
// time out reproduces the same ordering without the flakiness.
func TestRegistry_HandoffAbandonedByTimeoutIsNotDeliverable(t *testing.T) {
	limits := Limits{DialBackTimeout: 30 * time.Millisecond, MaxPendingPerServer: 2, MaxConnsPerServer: 2}
	reg := NewRegistry(nil, limits)
	pushedCh := make(chan protocol.RelayOpen, 1)
	agent := &Agent{Name: "home", Push: func(o protocol.RelayOpen) error { pushedCh <- o; return nil }, Close: func() {}}
	reg.RegisterAgent("home", agent)

	errCh := make(chan error, 1)
	go func() {
		_, err := reg.Open(context.Background(), "home", "203.0.113.5:1234", "home.relay.test")
		errCh <- err
	}()

	var pushed protocol.RelayOpen
	select {
	case pushed = <-pushedCh:
	case <-time.After(time.Second):
		t.Fatal("RelayOpen never pushed")
	}

	handoff, ok := reg.Redeem(pushed.ConnID)
	if !ok {
		t.Fatal("Redeem failed on a fresh conn_id")
	}

	if err := <-errCh; err == nil {
		t.Fatal("expected Open to time out")
	}

	// The fix: handleData's actual delivery logic (agent.go), reproduced
	// verbatim. With Open already abandoned, the priority check must take
	// the Done branch and never reach the send at all.
	conn := &fakeConn{}
	delivered := false
	select {
	case <-handoff.Done:
		conn.Close()
	default:
		select {
		case handoff.Deliver <- conn:
			delivered = true
		case <-handoff.Done:
			conn.Close()
		}
	}
	if delivered {
		t.Fatal("delivered into a channel nobody will ever read: this is the fd leak Done exists to prevent")
	}
	if !conn.closed {
		t.Fatal("abandoned connection was not closed")
	}

	// Counterfactual: the pre-fix behavior was an unconditional send with no
	// Done check at all. Confirm that naive send still succeeds into the
	// buffer in this exact scenario -- proving the check above is load
	// bearing, not incidentally passing because the buffer would have
	// rejected it anyway.
	naiveConn := &fakeConn{}
	select {
	case handoff.Deliver <- naiveConn:
	default:
		t.Fatal("expected the one-slot buffer to still accept an unconditional send (demonstrating why Done is required)")
	}
}

func TestRegistry_OpenTimesOutWithoutRedeem(t *testing.T) {
	reg := NewRegistry(nil, testLimits())
	agent := &Agent{Name: "home", Push: func(protocol.RelayOpen) error { return nil }, Close: func() {}}
	reg.RegisterAgent("home", agent)

	_, err := reg.Open(context.Background(), "home", "203.0.113.5:1234", "home.relay.test")
	if err == nil {
		t.Fatal("expected a dial-back timeout error")
	}
}

func TestRegistry_OpenUnknownOrOfflineTenant(t *testing.T) {
	reg := NewRegistry(nil, testLimits())
	if _, err := reg.Open(context.Background(), "ghost", "203.0.113.5:1234", "ghost.relay.test"); err != ErrTenantUnknown {
		t.Fatalf("err = %v, want ErrTenantUnknown", err)
	}
}

func TestRegistry_ConnIDExpires(t *testing.T) {
	reg := NewRegistry(nil, Limits{DialBackTimeout: 20 * time.Millisecond, MaxPendingPerServer: 2, MaxConnsPerServer: 2})
	agent := &Agent{Name: "home", Push: func(protocol.RelayOpen) error { return nil }, Close: func() {}}
	reg.RegisterAgent("home", agent)

	pushedCh := make(chan protocol.RelayOpen, 1)
	origPush := agent.Push
	agent.Push = func(o protocol.RelayOpen) error { pushedCh <- o; return origPush(o) }

	go func() { reg.Open(context.Background(), "home", "1.2.3.4:1", "home.relay.test") }()
	var pushed protocol.RelayOpen
	select {
	case pushed = <-pushedCh:
	case <-time.After(time.Second):
		t.Fatal("RelayOpen never pushed")
	}
	time.Sleep(50 * time.Millisecond) // let the conn_id's TTL lapse
	if _, ok := reg.Redeem(pushed.ConnID); ok {
		t.Fatal("expired conn_id should not be redeemable")
	}
}

func TestRegistry_MaxPendingPerServer(t *testing.T) {
	reg := NewRegistry(nil, Limits{DialBackTimeout: 200 * time.Millisecond, MaxPendingPerServer: 1, MaxConnsPerServer: 10})
	agent := &Agent{Name: "home", Push: func(protocol.RelayOpen) error { return nil }, Close: func() {}}
	reg.RegisterAgent("home", agent)

	// First Open blocks pending redemption, consuming the only pending slot.
	go reg.Open(context.Background(), "home", "1.1.1.1:1", "home.relay.test")
	time.Sleep(20 * time.Millisecond)

	_, err := reg.Open(context.Background(), "home", "2.2.2.2:2", "home.relay.test")
	if err != ErrTenantAtCapacity {
		t.Fatalf("err = %v, want ErrTenantAtCapacity", err)
	}
}

// TestRegistry_MaxConnsPerServerHoldsAcrossRedeemedConnections is the
// discriminating regression test for the pending double-decrement bug
// (registry.go's Open success branch used to decrement pending a second time
// after Redeem already had). TestRegistry_MaxPendingPerServer never redeems,
// so it cannot see this: the bug only manifests once connections complete
// the full Open->Redeem->deliver->Release cycle, at which point pending
// drifts negative and both max_pending_per_server and max_conns_per_server
// stop rejecting anything. This test fails against the pre-fix code.
func TestRegistry_MaxConnsPerServerHoldsAcrossRedeemedConnections(t *testing.T) {
	limits := Limits{DialBackTimeout: 500 * time.Millisecond, MaxPendingPerServer: 10, MaxConnsPerServer: 2}
	reg := NewRegistry(nil, limits)
	noopPush := func(protocol.RelayOpen) error { return nil }
	agent := &Agent{Name: "home", Push: noopPush, Close: func() {}}
	reg.RegisterAgent("home", agent)

	// openRedeemDeliver installs a one-shot Push wrapper to capture the
	// conn_id, then restores agent.Push to the harmless noop before
	// returning. It must not accumulate wrapper layers across calls: a
	// permanently-nested Push, still holding earlier calls' now-unread
	// buffered channels, deadlocks the later concurrent phase below the
	// moment two saturating Opens land on the same stale channel.
	openRedeemDeliver := func() net.Conn {
		t.Helper()
		pushedCh := make(chan protocol.RelayOpen, 1)
		agent.Push = func(o protocol.RelayOpen) error { pushedCh <- o; return nil }

		resultCh := make(chan net.Conn, 1)
		go func() {
			c, _ := reg.Open(context.Background(), "home", "203.0.113.5:1234", "home.relay.test")
			resultCh <- c
		}()

		var pushed protocol.RelayOpen
		select {
		case pushed = <-pushedCh:
		case <-time.After(time.Second):
			t.Fatal("RelayOpen never pushed")
		}
		agent.Push = noopPush

		handoff, ok := reg.Redeem(pushed.ConnID)
		if !ok {
			t.Fatal("Redeem failed on a fresh conn_id")
		}
		conn := &fakeConn{}
		handoff.Deliver <- conn
		got := <-resultCh
		if got != conn {
			t.Fatal("Open did not return the delivered connection")
		}
		return got
	}

	// Fully cycle MaxConnsPerServer connections through Open/Redeem/Release.
	// Under the pre-fix code, pending goes negative each time this succeeds,
	// so the concurrent, never-redeemed opens below (which must reject once
	// the cap is reached) instead keep succeeding.
	for i := 0; i < limits.MaxConnsPerServer; i++ {
		openRedeemDeliver()
		reg.Release("home")
	}

	reg.mu.Lock()
	ts := reg.tenants["home"]
	if ts.pending != 0 || ts.live != 0 {
		t.Fatalf("counters did not return to zero after full cycles: pending=%d live=%d", ts.pending, ts.live)
	}
	reg.mu.Unlock()

	// Saturate the tenant with MaxConnsPerServer concurrent, never-redeemed
	// opens (each holds a pending slot for the whole DialBackTimeout), then
	// assert the next Open is rejected immediately with ErrTenantAtCapacity
	// rather than blocking for a timeout. Concurrency matters: sequential
	// calls would each time out on their own and mask the counter bug.
	errCh := make(chan error, limits.MaxConnsPerServer)
	for i := 0; i < limits.MaxConnsPerServer; i++ {
		go func(i int) {
			_, err := reg.Open(context.Background(), "home", fmt.Sprintf("203.0.113.%d:1", i), "home.relay.test")
			errCh <- err
		}(i)
	}
	time.Sleep(50 * time.Millisecond) // let all saturating opens register their pending slot

	_, err := reg.Open(context.Background(), "home", "203.0.113.99:1", "home.relay.test")
	if err != ErrTenantAtCapacity {
		t.Fatalf("err = %v, want ErrTenantAtCapacity once pending+live reaches MaxConnsPerServer", err)
	}
	for i := 0; i < limits.MaxConnsPerServer; i++ {
		<-errCh // drain the saturating opens' eventual timeouts
	}
}

func TestRegistry_DeregisterOnlyClearsCurrentAgent(t *testing.T) {
	reg := NewRegistry(nil, testLimits())
	first := &Agent{Name: "home", Push: func(protocol.RelayOpen) error { return nil }, Close: func() {}}
	reg.RegisterAgent("home", first)
	second := &Agent{Name: "home", Push: func(protocol.RelayOpen) error { return nil }, Close: func() {}}
	reg.RegisterAgent("home", second)

	// A stale deregister for the evicted first agent must not clear second.
	reg.DeregisterAgent("home", first)
	if _, err := reg.Open(context.Background(), "home", "1.1.1.1:1", "home.relay.test"); err == ErrTenantUnknown {
		t.Fatal("deregistering a stale agent incorrectly took the tenant offline")
	}
}
