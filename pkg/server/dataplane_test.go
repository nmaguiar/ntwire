package server

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
)

// startTestDataPlane starts a data plane on loopback with the given tunnels,
// filling in the network/listener defaults LoadConfig would normally apply
// (newTestServer's Config is built by hand, not through LoadConfig).
func startTestDataPlane(t *testing.T, s *Server) {
	t.Helper()
	startTestDataPlaneWithCIDR(t, s, "100.64.0.0/16")
}

// startTestDataPlaneWithCIDR is startTestDataPlane with a caller-chosen
// tunnel_cidr, so tests can exercise an IPv6 prefix without disturbing the
// existing IPv4 fixtures.
func startTestDataPlaneWithCIDR(t *testing.T, s *Server, cidr string) {
	t.Helper()
	s.Config.Network.TunnelCIDR = cidr
	s.Config.Listen.WireGuard = "127.0.0.1:0"
	if err := s.StartDataPlane(); err != nil {
		t.Fatalf("StartDataPlane: %v", err)
	}
	t.Cleanup(s.Close)
}

// TestAllocateIPSequenceIPv4Unchanged pins allocateIP's IPv4 allocation order
// across the As4()/As16() rewrite: it must return the exact same addresses,
// in the exact same order, as before IPv6 support was added.
func TestAllocateIPSequenceIPv4Unchanged(t *testing.T) {
	s, _, _ := newTestServer(t, nil)
	startTestDataPlane(t, s)

	want := []string{"100.64.0.2", "100.64.0.3", "100.64.0.4"}
	for i, w := range want {
		ip, err := s.allocateIP()
		if err != nil {
			t.Fatalf("allocateIP: %v", err)
		}
		if ip != w {
			t.Fatalf("allocation %d = %q, want %q", i, ip, w)
		}
		s.sessions.Create(CreateParams{Method: "ssh", Identity: fmt.Sprintf("id-%d", i), TunnelIP: ip, TTL: time.Minute})
	}
}

// TestAllocateAndAddPeerIPv6 exercises allocateIP and addPeer end-to-end
// against an IPv6 tunnel_cidr, asserting no panic, addresses land inside the
// configured prefix, are distinct, and addPeer (which must emit a /128 mask
// for an IPv6 address) succeeds.
func TestAllocateAndAddPeerIPv6(t *testing.T) {
	s, _, _ := newTestServer(t, nil)
	startTestDataPlaneWithCIDR(t, s, "fd00:ac1d::/64")

	prefix := netip.MustParsePrefix("fd00:ac1d::/64")
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		ip, err := s.allocateIP()
		if err != nil {
			t.Fatalf("allocateIP: %v", err)
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			t.Fatalf("allocateIP returned invalid address %q: %v", ip, err)
		}
		if !addr.Is6() {
			t.Fatalf("expected an IPv6 address, got %q", ip)
		}
		if !prefix.Contains(addr) {
			t.Fatalf("allocated address %q is outside prefix %v", ip, prefix)
		}
		if seen[ip] {
			t.Fatalf("allocateIP returned a duplicate address %q", ip)
		}
		seen[ip] = true

		key, err := wgnet.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		if err := s.addPeer(key.Public, ip); err != nil {
			t.Fatalf("addPeer: %v", err)
		}
		// Register a session for this address so the next allocation skips it.
		s.sessions.Create(CreateParams{Method: "ssh", Identity: fmt.Sprintf("id-%d", i), TunnelIP: ip, TTL: time.Minute})
	}
}

func TestReloadRecyclesListenerWhenTunnelTargetChanges(t *testing.T) {
	s, _, _ := newTestServer(t, []TunnelConfig{
		{Name: "svc", Target: "127.0.0.1:1", VirtualPort: 18081, Allow: []string{"*"}},
	})
	startTestDataPlane(t, s)

	s.data.mu.Lock()
	orig := s.data.listeners["svc"]
	s.data.mu.Unlock()
	if orig == nil {
		t.Fatal("expected a listener for tunnel svc after boot")
	}

	changed := s.Config
	changed.Tunnels = []TunnelConfig{{Name: "svc", Target: "127.0.0.1:2", VirtualPort: 18081, Allow: []string{"*"}}}
	s.Reload(changed)

	if _, err := orig.listener.Accept(); err == nil {
		t.Fatal("old listener should be closed once its tunnel's target changes on reload")
	}

	s.data.mu.Lock()
	updated := s.data.listeners["svc"]
	s.data.mu.Unlock()
	if updated == nil {
		t.Fatal("expected a replacement listener for tunnel svc after reload")
	}
	if updated == orig {
		t.Fatal("expected reload to open a new listener, not keep the stale one")
	}
	if updated.config.Target != "127.0.0.1:2" {
		t.Fatalf("replacement listener has stale target %q, want 127.0.0.1:2", updated.config.Target)
	}
}

func TestReloadKeepsListenerWhenTunnelUnchanged(t *testing.T) {
	s, _, _ := newTestServer(t, []TunnelConfig{
		{Name: "svc", Target: "127.0.0.1:1", VirtualPort: 18082, Allow: []string{"*"}},
	})
	startTestDataPlane(t, s)

	s.data.mu.Lock()
	orig := s.data.listeners["svc"]
	s.data.mu.Unlock()

	// Reload with an identical tunnel list; only an unrelated field changes.
	same := s.Config
	same.Auth.SessionTTL = s.Config.Auth.SessionTTL + 1
	s.Reload(same)

	s.data.mu.Lock()
	after := s.data.listeners["svc"]
	s.data.mu.Unlock()
	if after != orig {
		t.Fatal("reload should not recycle a listener for an unchanged tunnel")
	}
}

func TestReloadOpensListenerForNewTunnelWithoutRestart(t *testing.T) {
	s, _, _ := newTestServer(t, nil)
	startTestDataPlane(t, s)

	s.data.mu.Lock()
	n := len(s.data.listeners)
	s.data.mu.Unlock()
	if n != 0 {
		t.Fatalf("expected no listeners at boot, got %d", n)
	}

	withTunnel := s.Config
	withTunnel.Tunnels = []TunnelConfig{{Name: "new", Target: "127.0.0.1:1", VirtualPort: 18083, Allow: []string{"*"}}}
	s.Reload(withTunnel)

	s.data.mu.Lock()
	tl := s.data.listeners["new"]
	s.data.mu.Unlock()
	if tl == nil {
		t.Fatal("expected a newly added tunnel to get a listener on reload, without a restart")
	}
}

func TestReloadClosesListenerForRemovedTunnel(t *testing.T) {
	s, _, _ := newTestServer(t, []TunnelConfig{
		{Name: "svc", Target: "127.0.0.1:1", VirtualPort: 18084, Allow: []string{"*"}},
	})
	startTestDataPlane(t, s)

	s.data.mu.Lock()
	orig := s.data.listeners["svc"]
	s.data.mu.Unlock()

	without := s.Config
	without.Tunnels = nil
	s.Reload(without)

	if _, err := orig.listener.Accept(); err == nil {
		t.Fatal("listener for a removed tunnel should be closed on reload")
	}
	s.data.mu.Lock()
	_, exists := s.data.listeners["svc"]
	s.data.mu.Unlock()
	if exists {
		t.Fatal("removed tunnel should no longer have an entry in the listener map")
	}
}

// TestConcurrentReloadAndAllowedIPDoesNotRace exercises reconcileTunnels
// (invoked by Reload) concurrently with allowedIP (invoked by the data
// plane for every proxied connection) on the same live session, to catch a
// torn read/write on Session.Tunnels under `go test -race`.
func TestConcurrentReloadAndAllowedIPDoesNotRace(t *testing.T) {
	_, authLine := genTestKey(t, t.TempDir(), "")
	pub, _, err := sshkey.ParsePublicString(authLine)
	if err != nil {
		t.Fatal(err)
	}
	fp := sshkey.Fingerprint(pub)

	keysDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(keysDir, "key.pub"), []byte(authLine+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{Tunnels: []TunnelConfig{{Name: "reports", Target: "x:1", VirtualPort: 1, Allow: []string{"*"}}}}
	cfg.Auth.AuthorizedKeysDir = keysDir
	cfg.Auth.SessionTTL = time.Minute
	s := New(cfg, nil)
	startTestDataPlane(t, s)

	session := s.sessions.Create(CreateParams{
		Method: "ssh", Identity: fp, Fingerprint: fp,
		TunnelIP: "100.64.0.5",
		Tunnels:  []protocol.Tunnel{{Name: "reports"}},
		TTL:      time.Minute,
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			s.allowedIP(session.TunnelIP, "reports")
		}
	}()
	for i := 0; i < 200; i++ {
		s.Reload(s.Config)
	}
	<-done
}
