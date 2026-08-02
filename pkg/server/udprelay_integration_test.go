package server

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/relay"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"golang.org/x/crypto/ssh"
)

// findFreeUDPPortForTest finds a currently-unused UDP port by briefly
// binding to it and releasing it, mirroring pkg/client's identically-shaped
// test helper -- used here to give the relay's listen.udp_relay_ports a
// single concrete port to bind (the range validator rejects port 0, so a
// real ephemeral-but-known port has to be found up front instead).
func findFreeUDPPortForTest(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback UDP unavailable: %v", err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// TestUDPRelayAllocateEndToEndWithRealRelay is the full-stack proof that the
// UDP-relay tier's allocation dance (POST /v1/udp-relay -> udpRelay.sessionFor
// -> RelayAgent.AllocateUDPSession -> a real relay control-connection round
// trip -> udpSessionTable.Allocate -> the server's own WireGuard peer
// endpoint reseeded) works through real components end to end, not just its
// pieces in isolation -- mirroring TestRelayAgent_EndToEndWithRealRelay's and
// TestDirectUpgradeEndToEnd's use of a real relay.Relay and RelayAgent rather
// than fakes for exactly this kind of wire-protocol integration risk.
//
// It deliberately does not route a client through the relay's SNI-based
// listen.public (unlike TestDirectUpgradeEndToEnd): the UDP-relay tier's
// allocation call is an ordinary server endpoint a client reaches over
// whatever control-plane transport it already has, so exercising it directly
// against s.Handler() covers the same integration risk without also needing
// DNS/SNI plumbing for "home.relay.test" that has nothing to do with this
// feature.
func TestUDPRelayAllocateEndToEndWithRealRelay(t *testing.T) {
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
	idPath := t.TempDir() + "/id"
	if err := os.WriteFile(idPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	pubLine := string(ssh.MarshalAuthorizedKey(pub))

	poolPort := findFreeUDPPortForTest(t)

	relayCfg := relay.Config{Domain: "relay.test", Registrations: []relay.RegistrationConfig{{Name: "home", PublicKey: pubLine}}}
	relayCfg.Listen.Public = "127.0.0.1:0"
	relayCfg.Listen.Agents = "127.0.0.1:0"
	relayCfg.Listen.UDPRelay = "127.0.0.1:0"
	relayCfg.Listen.UDPRelayPorts = fmt.Sprintf("%d-%d", poolPort, poolPort)
	relayCfg.TLS.Ephemeral = true
	relayCfg.Limits.HandshakeTimeout = 5 * time.Second
	relayCfg.Limits.DialBackTimeout = 3 * time.Second
	relayCfg.Limits.MaxPendingPerServer = 32
	relayCfg.Limits.MaxConnsPerServer = 256
	relayCfg.Limits.MaxNewConnsPerMinute = 1000
	relayCfg.Limits.MaxUDPRelaySessionsPerServer = 10
	rl, err := relay.New(relayCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rl.Start(); err != nil {
		t.Fatal(err)
	}
	defer rl.Close()
	udpRelayAddr := rl.UDPRelayAddr()
	if udpRelayAddr == "" {
		t.Fatal("relay did not bind listen.udp_relay")
	}

	agentCfg := RelayConfig{Enabled: true, URL: "wss://" + rl.AgentsAddr().String(), Name: "home", IdentityFile: idPath, Fingerprint: rl.Fingerprint()}
	agent, err := NewRelayAgent(agentCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go agent.Run(ctx)
	defer agent.Close()
	time.Sleep(200 * time.Millisecond) // allow registration to complete

	scfg := Config{}
	scfg.Network.TunnelCIDR = "100.66.0.0/16"
	scfg.Listen.WireGuard = "127.0.0.1:0"
	s := New(scfg, nil)
	if err := s.StartDataPlane(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// In production this is main.go wiring RelayAgent.OnUDPRelayAddr,
	// unconditionally (no advertise_direct-style gate); calling it directly
	// exercises the exact same server-side mechanism.
	s.EnableUDPRelay(agent, udpRelayAddr)

	peer, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sess := s.sessions.Create(CreateParams{WireGuardPublicKey: peer.Public, TTL: time.Minute})

	postUDPRelay := func() protocol.UDPRelayResponse {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/v1/udp-relay", bytes.NewReader([]byte(`{}`)))
		req.Header.Set("Authorization", "Bearer "+sess.Token)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("/v1/udp-relay status = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		var resp protocol.UDPRelayResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp := postUDPRelay()
	if resp.Token == "" {
		t.Fatal("/v1/udp-relay returned an empty token against a real, registered relay")
	}
	if resp.RelayAddr != udpRelayAddr {
		t.Fatalf("/v1/udp-relay relay_addr = %q, want the relay's own udp_relay address %q", resp.RelayAddr, udpRelayAddr)
	}

	// A second call for the same session must be idempotent: same token, no
	// second allocation consumed from the relay's one-port pool (which a
	// non-idempotent implementation would immediately exhaust here).
	resp2 := postUDPRelay()
	if resp2 != resp {
		t.Fatalf("/v1/udp-relay second call = %+v, want identical to the first %+v (idempotency)", resp2, resp)
	}

	// The allocation must have actually reseeded this server's own WireGuard
	// peer endpoint for the client's public key to the relay's (only) pooled
	// port -- not merely returned a plausible-looking response.
	ep, found, err := s.data.stack.PeerEndpoint(peer.Public)
	if err != nil {
		t.Fatal(err)
	}
	if !found || ep == "" {
		t.Fatalf("server's WireGuard peer endpoint was not seeded after allocation (found=%v, ep=%q)", found, ep)
	}
	wantSuffix := fmt.Sprintf(":%d", poolPort)
	if !strings.HasSuffix(ep, wantSuffix) {
		t.Fatalf("server's WireGuard peer endpoint = %q, want it to end in %q (the relay's only pooled UDP-relay port)", ep, wantSuffix)
	}
}
