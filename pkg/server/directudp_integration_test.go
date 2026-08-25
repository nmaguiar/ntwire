package server

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/client"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/relay"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
)

// TestDirectUpgradeEndToEnd is the full-stack proof that the opportunistic
// direct-UDP upgrade (pkg/client's directupgrade.go) works through real
// components, not just their pieces in isolation: a real relay UDP
// reflector, a real server with relay.advertise_direct's mechanism enabled,
// and a real client connected the normal way (client.ConnectWithOptions)
// over the WebSocket fallback.
//
// It asserts on the client's actual WireGuard peer endpoint
// (Stack.PeerEndpoint), not merely that a probe happened to succeed --
// pkg/client's tryDirectUpgrade and directPathHealthy both need that
// stronger check: a probe alone cannot tell "upgraded to direct" apart from
// "WireGuard's own roaming quietly moved the peer back to WebSocket", since
// both transports stay live on the same device and either one answering
// makes a probe succeed.
//
// See TestForcedWebSocketNeverUpgrades for the companion case: a client that
// passed --websocket (Options.UseWebSocket) must never leave it, even though
// the same server/relay would otherwise offer the ladder.
//
// This test lives in pkg/server rather than pkg/client because verifying
// the revert path requires closing only the server's UDP transport while
// leaving its WebSocket transport live -- s.data.ws.UDP is unexported, and
// an earlier version of this test that tried to simulate that from the
// client side by seeding a bogus peer endpoint failed: WireGuard's own
// passive roaming immediately overwrote it back to the real, still-working
// address the moment any ordinary packet arrived from the server, since
// that manual injection never actually broke the underlying path.
func TestDirectUpgradeEndToEnd(t *testing.T) {
	fastTiming := &client.DirectUpgradeTiming{
		InitialDelay: 100 * time.Millisecond, RetryInterval: 500 * time.Millisecond,
		HealthCheckInterval: 500 * time.Millisecond, ReflectTimeout: 2 * time.Second, ProbeTimeout: 1 * time.Second,
	}

	relayCfg := relay.Config{Domain: "relay.test"}
	relayCfg.Listen.Public = "127.0.0.1:0"
	relayCfg.Listen.Agents = "127.0.0.1:0"
	relayCfg.Listen.Reflect = "127.0.0.1:0"
	relayCfg.TLS.Ephemeral = true
	relayCfg.Limits.HandshakeTimeout = 5 * time.Second
	relayCfg.Limits.DialBackTimeout = 3 * time.Second
	relayCfg.Limits.MaxNewConnsPerMinute = 1000
	r, err := relay.New(relayCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	reflectAddr := r.ReflectAddr()
	if reflectAddr == "" {
		t.Fatal("relay did not bind listen.reflect")
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	if _, err := sshkey.GenerateIdentityFile(keyPath); err != nil {
		t.Fatal(err)
	}
	authorizedLine, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	keysDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(keysDir, "test.pub"), authorizedLine, 0644); err != nil {
		t.Fatal(err)
	}

	scfg := Config{}
	multipath := false
	scfg.Transport.Multipath = &multipath
	scfg.Auth.AuthorizedKeysDir = keysDir
	scfg.Auth.SessionTTL = time.Minute
	scfg.Network.TunnelCIDR = "100.66.0.0/16"
	scfg.Listen.WireGuard = "127.0.0.1:0"
	s := New(scfg, nil)
	if err := s.StartDataPlane(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// In production this is main.go wiring RelayAgent.OnReflectAddr, gated
	// on relay.advertise_direct; calling it directly exercises the exact
	// same server-side mechanism without also standing up the relay's
	// TCP-splice control connection, which is unrelated to what this test
	// is verifying.
	s.EnableDirectUpgrade(reflectAddr)

	httpSrv := httptest.NewTLSServer(s.Handler())
	defer httpSrv.Close()

	conn, err := client.ConnectWithOptions(httpSrv.URL, keyPath, protocol.ClientInfo{OS: "linux"}, client.Options{
		Insecure: true, NoWebUI: true, StatusFile: filepath.Join(dir, "status.json"), DirectUpgradeTiming: fastTiming,
	})
	if err != nil {
		t.Fatalf("ConnectWithOptions() = %v", err)
	}
	defer conn.Close()

	serverPub := conn.Response.ServerPublicKey
	ep := pollPeerEndpoint(t, conn, serverPub, 10*time.Second, func(ep string) bool {
		return ep != "" && ep != "0.0.0.0:0"
	})
	t.Logf("upgraded to direct candidate %q", ep)

	// Kill only the UDP transport, leaving the WebSocket connection --
	// carried over the same httptest TLS server, entirely independent of
	// s.data.ws.UDP -- alive. This is the realistic failure mode
	// directPathHealthy exists to catch (a NAT mapping expiring, a route
	// change) and, critically, one probeDirectPath's dial genuinely cannot
	// get any response for, unlike the earlier client-side injection
	// attempt this test's doc comment describes.
	_ = s.data.ws.UDP.Close()

	pollPeerEndpoint(t, conn, serverPub, 15*time.Second, func(ep string) bool {
		return ep == "0.0.0.0:0"
	})
}

// TestForcedWebSocketNeverUpgrades is the regression case for a client that
// forced WebSocket via Options.UseWebSocket (--websocket on the CLI): even
// against a server/relay pair fully capable of the UDP-relay and direct-UDP
// rungs (the same setup TestDirectUpgradeEndToEnd escalates through), the
// connection must stay on the WebSocket fallback ("ws:relay") for the
// caller-chosen transport's whole lifetime -- directUpgradeLoop must not even
// start.
func TestForcedWebSocketNeverUpgrades(t *testing.T) {
	fastTiming := &client.DirectUpgradeTiming{
		InitialDelay: 100 * time.Millisecond, RetryInterval: 200 * time.Millisecond,
		HealthCheckInterval: 200 * time.Millisecond, ReflectTimeout: 2 * time.Second, ProbeTimeout: 1 * time.Second,
	}

	relayCfg := relay.Config{Domain: "relay.test"}
	relayCfg.Listen.Public = "127.0.0.1:0"
	relayCfg.Listen.Agents = "127.0.0.1:0"
	relayCfg.Listen.Reflect = "127.0.0.1:0"
	relayCfg.TLS.Ephemeral = true
	relayCfg.Limits.HandshakeTimeout = 5 * time.Second
	relayCfg.Limits.DialBackTimeout = 3 * time.Second
	relayCfg.Limits.MaxNewConnsPerMinute = 1000
	r, err := relay.New(relayCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	reflectAddr := r.ReflectAddr()
	if reflectAddr == "" {
		t.Fatal("relay did not bind listen.reflect")
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	if _, err := sshkey.GenerateIdentityFile(keyPath); err != nil {
		t.Fatal(err)
	}
	authorizedLine, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	keysDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(keysDir, "test.pub"), authorizedLine, 0644); err != nil {
		t.Fatal(err)
	}

	scfg := Config{}
	multipath := false
	scfg.Transport.Multipath = &multipath
	scfg.Auth.AuthorizedKeysDir = keysDir
	scfg.Auth.SessionTTL = time.Minute
	scfg.Network.TunnelCIDR = "100.66.0.0/16"
	scfg.Listen.WireGuard = "127.0.0.1:0"
	s := New(scfg, nil)
	if err := s.StartDataPlane(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.EnableDirectUpgrade(reflectAddr)

	httpSrv := httptest.NewTLSServer(s.Handler())
	defer httpSrv.Close()

	conn, err := client.ConnectWithOptions(httpSrv.URL, keyPath, protocol.ClientInfo{OS: "linux"}, client.Options{
		Insecure: true, NoWebUI: true, UseWebSocket: true,
		StatusFile: filepath.Join(dir, "status.json"), DirectUpgradeTiming: fastTiming,
	})
	if err != nil {
		t.Fatalf("ConnectWithOptions() = %v", err)
	}
	defer conn.Close()

	// WSSentinel ("ws:relay") isn't a parseable host:port, so
	// endpointAddress falls back to the unspecified 0.0.0.0:0 -- that is
	// what PeerEndpoint() reports the whole time this connection rides the
	// WebSocket fallback. If directUpgradeLoop had started despite
	// UseWebSocket being forced, this deadline is comfortably longer than
	// fastTiming's initialDelay + retryInterval, giving it ample opportunity
	// to escalate the endpoint to something else.
	serverPub := conn.Response.ServerPublicKey
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ep, _, err := conn.Stack.PeerEndpoint(serverPub)
		if err != nil {
			t.Fatal(err)
		}
		if ep != "0.0.0.0:0" {
			t.Fatalf("PeerEndpoint() = %q, want the WebSocket sentinel's 0.0.0.0:0 to stay put since UseWebSocket was forced", ep)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// pollPeerEndpoint polls Stack.PeerEndpoint until ok reports satisfied or
// timeout elapses, returning the last observed value either way (and
// failing the test on timeout).
func pollPeerEndpoint(t *testing.T, conn *client.Connection, publicKey string, timeout time.Duration, ok func(string) bool) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var ep string
	for time.Now().Before(deadline) {
		var err error
		ep, _, err = conn.Stack.PeerEndpoint(publicKey)
		if err != nil {
			t.Fatal(err)
		}
		if ok(ep) {
			return ep
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("PeerEndpoint() never satisfied the expected condition within %v; last seen %q", timeout, ep)
	return ep
}
