package relay

import (
	"context"
	"crypto/x509"
	"encoding/pem"
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
	name, err := reg.Register(req)
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
	_, err := reg.Register(req)
	if err == nil || err.Code != protocol.ErrorUnknownKey {
		t.Fatalf("err = %v, want unknown_key", err)
	}
}

func TestRegistry_RegisterBadSignature(t *testing.T) {
	k := generateTestKey(t)
	reg := NewRegistry([]Registration{{Name: "home", PublicKey: k.pub}}, testLimits())
	req := signedRegisterRequest(t, k, "home", "nonce-1")
	req.Signature = req.Signature[:len(req.Signature)-4] + "abcd"
	_, err := reg.Register(req)
	if err == nil || err.Code != protocol.ErrorBadSignature {
		t.Fatalf("err = %v, want bad_signature", err)
	}
}

func TestRegistry_RegisterNameMismatch(t *testing.T) {
	k := generateTestKey(t)
	reg := NewRegistry([]Registration{{Name: "home", PublicKey: k.pub}}, testLimits())
	req := signedRegisterRequest(t, k, "not-home", "nonce-1")
	_, err := reg.Register(req)
	if err == nil || err.Code != protocol.ErrorRelayNameNotAllowed {
		t.Fatalf("err = %v, want relay_name_not_allowed", err)
	}
}

func TestRegistry_RegisterReplayedNonce(t *testing.T) {
	k := generateTestKey(t)
	reg := NewRegistry([]Registration{{Name: "home", PublicKey: k.pub}}, testLimits())
	req := signedRegisterRequest(t, k, "home", "reused-nonce")
	if _, err := reg.Register(req); err != nil {
		t.Fatalf("first registration failed: %v", err)
	}
	req2 := signedRegisterRequest(t, k, "home", "reused-nonce")
	req2.Timestamp = req.Timestamp
	req2.Signature = req.Signature
	if _, err := reg.Register(req2); err == nil || err.Code != protocol.ErrorReplayedNonce {
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
	_, err := reg.Register(req)
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

	deliver, ok := reg.Redeem(pushed.ConnID)
	if !ok {
		t.Fatal("Redeem failed on a fresh conn_id")
	}
	want := &fakeConn{}
	deliver <- want

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
