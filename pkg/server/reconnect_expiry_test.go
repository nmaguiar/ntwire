package server

import (
	"io"
	"net"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/client"
	"github.com/nmaguiar/ntwire/pkg/protocol"
)

func TestClientRecoversExpiredSessionWithNewAddress(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	s, key, _ := newTestServer(t, []TunnelConfig{{Name: "echo", Target: target.Addr().String(), VirtualPort: 18080, Allow: []string{"*"}}})
	s.Config.Auth.SessionTTL = 3 * time.Second
	startTestDataPlane(t, s)
	h := httptest.NewServer(s.Handler())
	defer h.Close()
	c, err := client.ConnectWithOptions(h.URL, key, protocol.ClientInfo{}, client.Options{NoWebUI: true, NoDirectUpgrade: true, NoSystemProxy: true, StatusFile: filepath.Join(t.TempDir(), "status.json")})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	pub := c.Stack.PublicKey()
	old, ok := s.sessions.FindWireGuardPublicKey(pub)
	if !ok {
		t.Fatal("missing initial session")
	}
	address := c.State().Tunnels[0].LocalAddress
	s.operationMu.Lock()
	s.sessions.mu.Lock()
	expired := s.sessions.byToken[old.Token]
	expired.Expires = time.Now().Add(-time.Second)
	s.sessions.byToken[old.Token] = expired
	s.sessions.mu.Unlock()
	s.reapSessionsLocked()
	s.operationMu.Unlock()
	deadline := time.Now().Add(8 * time.Second)
	for c.State().Reconnections == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if c.State().Reconnections == 0 {
		t.Fatal("client did not recover expired session")
	}
	next, ok := s.sessions.FindWireGuardPublicKey(pub)
	if !ok || next.TunnelIP == old.TunnelIP {
		t.Fatal("expected a new address after expiry")
	}
	if c.State().Tunnels[0].LocalAddress != address {
		t.Fatal("local listener changed")
	}
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("recovered")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 9)
	if _, err := io.ReadFull(conn, b); err != nil {
		t.Fatal(err)
	}
	if string(b) != "recovered" {
		t.Fatalf("response %q", b)
	}
}
