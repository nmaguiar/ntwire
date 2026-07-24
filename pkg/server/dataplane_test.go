package server

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
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

// TestReloadRecyclesListenerWhenSocksFilterChanges pins the extension to
// reloadTunnels' recycle condition: a socks tunnel's virtual_port and
// target ("socks") don't change when only its filters do, so the diff must
// separately notice a changed socks: block or a filter edit would never
// take effect on SIGHUP/config-watch.
func TestReloadRecyclesListenerWhenSocksFilterChanges(t *testing.T) {
	s, _, _ := newTestServer(t, []TunnelConfig{
		{Name: "egress", Target: "socks", VirtualPort: 18085, Allow: []string{"*"}, Socks: &SocksConfig{AllowAll: true}},
	})
	startTestDataPlane(t, s)

	s.data.mu.Lock()
	orig := s.data.listeners["egress"]
	s.data.mu.Unlock()
	if orig == nil || orig.socks == nil {
		t.Fatal("expected a socks-backed listener for tunnel egress after boot")
	}

	changed := s.Config
	changed.Tunnels = []TunnelConfig{
		{Name: "egress", Target: "socks", VirtualPort: 18085, Allow: []string{"*"}, Socks: &SocksConfig{OnlyLocal: true}},
	}
	s.Reload(changed)

	if _, err := orig.listener.Accept(); err == nil {
		t.Fatal("old listener should be closed once its tunnel's socks config changes on reload")
	}

	s.data.mu.Lock()
	updated := s.data.listeners["egress"]
	s.data.mu.Unlock()
	if updated == nil || updated.socks == nil {
		t.Fatal("expected a replacement socks-backed listener for tunnel egress after reload")
	}
	if updated == orig {
		t.Fatal("expected reload to open a new listener, not keep the stale one")
	}
	if !updated.config.Socks.OnlyLocal {
		t.Fatal("replacement listener has stale socks config")
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

// freeUDPPort finds a currently-unused UDP port by briefly binding to
// 127.0.0.1:0 and releasing it, so StartDataPlane can be given a fixed,
// known listen.wireguard port for a second, independent client-side Stack
// to dial back to (mirrors pkg/wgnet's own freeUDPPort test helper).
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// TestProxySocksOverRealWireGuardConn drives a target: socks tunnel through
// the real accept-loop wiring (StartDataPlane -> listenTunnel -> proxy ->
// proxySocks), using a second, independent wgnet.Stack as an ntwire client
// would: a genuine WireGuard handshake, then a real *gonet.TCPConn dialed
// through it. This is deliberately not net.Pipe (used by pkg/socks's own
// tests): net.Pipe conns don't implement CloseWrite, so they can't catch a
// regression in countingConn's half-close forwarding to the accepted
// gonet.TCPConn, which is the type every real SOCKS tunnel connection
// actually is.
func TestProxySocksOverRealWireGuardConn(t *testing.T) {
	upstream := echoUpstream(t)

	wgPort := freeUDPPort(t)
	s, _, _ := newTestServer(t, []TunnelConfig{
		{Name: "egress", Target: "socks", VirtualPort: 11090, Allow: []string{"*"}, Socks: &SocksConfig{AllowAll: true}},
	})
	s.Config.Network.TunnelCIDR = "100.64.0.0/16"
	s.Config.Listen.WireGuard = "127.0.0.1:" + fmt.Sprint(wgPort)
	if err := s.StartDataPlane(); err != nil {
		t.Fatalf("StartDataPlane: %v", err)
	}
	t.Cleanup(s.Close)

	clientTunnelIP := netip.MustParseAddr("100.64.0.5")
	clientStack, err := wgnet.New(wgnet.Config{Addresses: []netip.Addr{clientTunnelIP}})
	if err != nil {
		t.Fatalf("client wgnet.New: %v", err)
	}
	t.Cleanup(func() { clientStack.Close() })

	if err := s.addPeer(clientStack.PublicKey(), clientTunnelIP.String()); err != nil {
		t.Fatalf("server addPeer: %v", err)
	}
	if err := clientStack.AddPeer(wgnet.Endpoint{PublicKey: s.data.stack.PublicKey(), Address: "0.0.0.0/0@127.0.0.1:" + fmt.Sprint(wgPort)}); err != nil {
		t.Fatalf("client AddPeer: %v", err)
	}
	s.sessions.Create(CreateParams{
		Method: "ssh", Identity: "id", TunnelIP: clientTunnelIP.String(),
		Tunnels: []protocol.Tunnel{{Name: "egress"}}, TTL: time.Minute,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := clientStack.DialContext(ctx, "tcp", net.JoinHostPort(s.data.serverIP.String(), "11090"))
	if err != nil {
		t.Fatalf("client.DialContext through WireGuard peer: %v", err)
	}

	// SOCKS5 no-auth greeting.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil || buf[1] != 0x00 {
		t.Fatalf("method reply = %v, err = %v", buf, err)
	}

	req := []byte{0x05, 0x01, 0x00, 0x01}
	ip4 := upstream.Addr().As4()
	req = append(req, ip4[:]...)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], upstream.Port())
	req = append(req, portBuf[:]...)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("expected CONNECT success over the real WireGuard conn, got rep=%d", reply[1])
	}

	msg := []byte("hello over real wireguard+socks")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo = %q, want %q", got, msg)
	}

	// Closing the client's write side (the real CloseWrite path
	// countingConn must forward) must let the relay -- and so the whole
	// accepted server-side connection -- wind down on its own, not hang.
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
	} else {
		t.Fatal("expected the dialed conn to implement CloseWrite (gonet.TCPConn)")
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != io.EOF {
		t.Fatalf("expected EOF after the server relayed the half-close, got %v", err)
	}
	conn.Close()
}

// echoUpstream is a real TCP listener that echoes back whatever it reads,
// standing in for a SOCKS CONNECT destination.
func echoUpstream(t *testing.T) netip.AddrPort {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	return netip.MustParseAddrPort(l.Addr().String())
}

// newSocksProxyCall wires up a target: socks tunnel's proxy path exactly as
// listenTunnel would, without needing a real WireGuard/netstack listener:
// s.proxy is driven directly against a fake accepted conn (via relayConn,
// the same RemoteAddr-overriding wrapper the relay data plane uses) whose
// reported remote host matches a live session's TunnelIP, so allowedIP
// passes the same gate a real connection would.
func newSocksProxyCall(t *testing.T, s *Server, tunnel TunnelConfig, tunnelIP string) net.Conn {
	t.Helper()
	tl := &tunnelListener{config: tunnel, socks: s.newSocksRuntime(tunnel)}
	if tl.socks == nil {
		t.Fatal("newSocksRuntime returned nil")
	}
	s.sessions.Create(CreateParams{
		Method: "ssh", Identity: "id", TunnelIP: tunnelIP,
		Tunnels: []protocol.Tunnel{{Name: tunnel.Name}}, TTL: time.Minute,
	})
	client, server := net.Pipe()
	fake := &relayConn{Conn: server, remoteAddr: stringAddr(tunnelIP + ":9999")}
	go s.proxy(tl, fake)
	return client
}

func TestProxySocksConnectAllowedRelays(t *testing.T) {
	upstream := echoUpstream(t)
	s, _, _ := newTestServer(t, nil)

	tunnel := TunnelConfig{
		Name: "egress", Target: "socks", VirtualPort: 11080, Allow: []string{"*"},
		Socks: &SocksConfig{AllowAll: true},
	}
	client := newSocksProxyCall(t, s, tunnel, "100.64.0.5")

	// SOCKS5 no-auth greeting.
	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(client, buf); err != nil || buf[1] != 0x00 {
		t.Fatalf("method reply = %v, err = %v", buf, err)
	}

	req := []byte{0x05, 0x01, 0x00, 0x01}
	ip4 := upstream.Addr().As4()
	req = append(req, ip4[:]...)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], upstream.Port())
	req = append(req, portBuf[:]...)
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("expected CONNECT success, got rep=%d", reply[1])
	}

	msg := []byte("hello through socks")
	if _, err := client.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo = %q, want %q", got, msg)
	}
}

func TestProxySocksConnectDeniedByDefault(t *testing.T) {
	upstream := echoUpstream(t)
	s, _, _ := newTestServer(t, nil)

	// No socks.filters/allow_all: deny-by-default should refuse every
	// destination, unlike socksd's own allow-all default.
	tunnel := TunnelConfig{
		Name: "egress", Target: "socks", VirtualPort: 11081, Allow: []string{"*"},
		Socks: &SocksConfig{},
	}
	client := newSocksProxyCall(t, s, tunnel, "100.64.0.6")

	client.Write([]byte{0x05, 0x01, 0x00})
	buf := make([]byte, 2)
	io.ReadFull(client, buf)

	req := []byte{0x05, 0x01, 0x00, 0x01}
	ip4 := upstream.Addr().As4()
	req = append(req, ip4[:]...)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], upstream.Port())
	req = append(req, portBuf[:]...)
	client.Write(req)

	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0x02 { // not allowed by ruleset
		t.Fatalf("expected denial (rep=0x02), got rep=%d", reply[1])
	}
}

func TestProxySocksRejectsUnauthorizedTunnelIP(t *testing.T) {
	s, _, _ := newTestServer(t, nil)
	tunnel := TunnelConfig{
		Name: "egress", Target: "socks", VirtualPort: 11082, Allow: []string{"*"},
		Socks: &SocksConfig{AllowAll: true},
	}
	tl := &tunnelListener{config: tunnel, socks: s.newSocksRuntime(tunnel)}
	// Deliberately do not register a session for this tunnel IP: the
	// allowedIP gate (shared with the fixed-target path) must still apply
	// to SOCKS tunnels.
	client, server := net.Pipe()
	fake := &relayConn{Conn: server, remoteAddr: stringAddr("100.64.0.9:9999")}
	go s.proxy(tl, fake)

	client.Write([]byte{0x05, 0x01, 0x00})
	buf := make([]byte, 2)
	client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := client.Read(buf); err == nil {
		t.Fatal("expected the connection to be dropped for an unauthorized tunnel IP, got a SOCKS reply instead")
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
