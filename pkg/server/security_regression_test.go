package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
)

type stalledSecurityBody struct {
	entered chan struct{}
	release chan struct{}
}

func (b *stalledSecurityBody) Read([]byte) (int, error) {
	close(b.entered)
	<-b.release
	return 0, io.EOF
}
func (*stalledSecurityBody) Close() error { return nil }
func TestStalledControlBodiesDoNotHoldLifecycleLock(t *testing.T) {
	for _, path := range []string{"/v1/auth", "/v1/auth/oidc", "/v1/renew", "/v1/transport/direct", "/v1/udp-relay"} {
		t.Run(path, func(t *testing.T) {
			s := New(Config{}, nil)
			session := s.sessions.Create(CreateParams{TTL: time.Minute})
			body := &stalledSecurityBody{entered: make(chan struct{}), release: make(chan struct{})}
			req := httptest.NewRequest("POST", path, body)
			req.Header.Set("Authorization", "Bearer "+session.Token)
			done := make(chan struct{})
			go func() { defer close(done); s.Handler().ServeHTTP(httptest.NewRecorder(), req) }()
			defer func() { close(body.release); <-done }()
			select {
			case <-body.entered:
			case <-time.After(time.Second):
				t.Fatal("body not read")
			}
			reaped := make(chan struct{})
			go func() { s.reapSessions(); close(reaped) }()
			select {
			case <-reaped:
			case <-time.After(time.Second):
				t.Fatal("stalled body holds lifecycle lock")
			}
		})
	}
}
func TestPrincipalRejectsExpiryBeforeReaping(t *testing.T) {
	s := New(Config{}, nil)
	s.sessions.Create(CreateParams{TunnelIP: "100.64.0.2", Tunnels: []protocol.Tunnel{{Name: "private"}}, TTL: -time.Second})
	if _, ok := s.principalForIP("100.64.0.2"); ok {
		t.Fatal("expired record authorizes data plane")
	}
}

type deadlineSecurityRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (w *deadlineSecurityRecorder) SetReadDeadline(d time.Time) error {
	w.deadlines = append(w.deadlines, d)
	return nil
}
func TestControlBodyDeadlineIsRequestScoped(t *testing.T) {
	w := &deadlineSecurityRecorder{ResponseRecorder: httptest.NewRecorder()}
	var v any
	if err := decodeControlBody(w, httptest.NewRequest("POST", "/v1/auth", strings.NewReader(`{}`)), 100, &v); err != nil {
		t.Fatal(err)
	}
	if len(w.deadlines) != 2 || w.deadlines[0].IsZero() || !w.deadlines[1].IsZero() {
		t.Fatal("body deadline not set and cleared")
	}
}
func TestPeerReconnectRequiresSamePrincipal(t *testing.T) {
	for _, variant := range []string{"different-user", "different-method", "different-issuer", "same-owner-alias", "native-reserved"} {
		t.Run(variant, func(t *testing.T) {
			s := New(Config{}, nil)
			s.Config.Auth.SessionTTL = time.Minute
			startTestDataPlane(t, s)
			key, _ := wgnet.GenerateKey()
			old := s.sessions.Create(CreateParams{Method: "oidc", Identity: "owner", Issuer: "idp", WireGuardPublicKey: key.Public, TunnelIP: "100.64.0.2", TTL: time.Minute})
			req := sessionRequest{Method: "oidc", Identity: "owner", Issuer: "idp", WireGuardPublicKey: key.Public[:20] + "\n" + key.Public[20:]}
			switch variant {
			case "different-user":
				req.Identity = "attacker"
			case "different-method":
				req.Method = "ssh"
			case "different-issuer":
				req.Issuer = "other"
			case "native-reserved":
				s.Config.NativeWireGuard.Enabled = true
				s.Config.NativeWireGuard.Peers = []NativeWireGuardPeer{{PublicKey: key.Public}}
			}
			w := httptest.NewRecorder()
			ok := s.establishSession(w, httptest.NewRequest("POST", "/v1/auth", nil), req, nil)
			_, oldExists := s.sessions.Get(old.Token)
			if variant == "same-owner-alias" {
				if !ok || oldExists {
					t.Fatal("same-owner reconnect failed")
				}
			} else if ok || !oldExists || w.Code != 403 {
				t.Fatalf("cross-owner replacement accepted: %v %v %d", ok, oldExists, w.Code)
			}
		})
	}
}
func TestNativeReloadRetiresDynamicAddressAndKeyCollisions(t *testing.T) {
	for _, collision := range []string{"address", "key"} {
		t.Run(collision, func(t *testing.T) {
			s, _, line := newTestServer(t, []TunnelConfig{{Name: "reports", Target: "127.0.0.1:1", VirtualPort: 1234, Allow: []string{"*"}}})
			startTestDataPlane(t, s)
			pub, _, _ := sshkey.ParsePublicString(line)
			fp := sshkey.Fingerprint(pub)
			key, _ := wgnet.GenerateKey()
			native, _ := wgnet.GenerateKey()
			old := s.sessions.Create(CreateParams{Method: "ssh", Identity: fp, Fingerprint: fp, WireGuardPublicKey: key.Public, TunnelIP: "100.64.0.2", Tunnels: []protocol.Tunnel{{Name: "reports"}}, TTL: time.Minute})
			if err := s.addPeer(key.Public, old.TunnelIP); err != nil {
				t.Fatal(err)
			}
			cfg := s.Config
			cfg.NativeWireGuard.Enabled = true
			peer := NativeWireGuardPeer{Name: "phone", PublicKey: native.Public, TunnelIP: old.TunnelIP}
			if collision == "key" {
				peer.PublicKey = key.Public[:20] + "\n" + key.Public[20:]
				peer.TunnelIP = "100.64.0.3"
			}
			cfg.NativeWireGuard.Peers = []NativeWireGuardPeer{peer}
			s.Reload(cfg)
			if _, ok := s.sessions.Get(old.Token); ok {
				t.Fatal("conflicting dynamic identity retained")
			}
			p, ok := s.principalForIP(peer.TunnelIP)
			if !ok || p.Method != "native-wireguard" || p.Tunnels["reports"] {
				t.Fatal("native peer inherited dynamic grants")
			}
			if _, found, err := s.data.stack.LastHandshake(peer.PublicKey); err != nil || !found {
				t.Fatal("replacement native peer removed by cleanup")
			}
		})
	}
}
func TestReloadUpdatesDestinationPolicyAttachments(t *testing.T) {
	for _, protocolName := range []string{"tcp", "udp", "socks"} {
		t.Run(protocolName, func(t *testing.T) {
			tunnel := TunnelConfig{Name: "reports", Target: "203.0.113.1:443", VirtualPort: 12345, Allow: []string{"*"}}
			if protocolName == "udp" {
				tunnel.Protocol = "udp"
			}
			if protocolName == "socks" {
				tunnel.Target = "socks"
				tunnel.Socks = &SocksConfig{AllowAll: true}
			}
			s := New(Config{Tunnels: []TunnelConfig{tunnel}, DestinationPolicies: map[string]DestinationPolicy{"deny": {}}}, nil)
			startTestDataPlane(t, s)
			previous := s.data.listeners[tunnel.Name]
			cfg := s.Config
			cfg.Tunnels = append([]TunnelConfig(nil), cfg.Tunnels...)
			cfg.Tunnels[0].DestinationPolicy = "deny"
			s.Reload(cfg)
			current := s.data.listeners[tunnel.Name]
			if current == previous || current.config.DestinationPolicy != "deny" {
				t.Fatal("stale runtime retained on policy change")
			}
			p := DataPlanePrincipal{TunnelIP: netip.MustParseAddr("100.64.0.2")}
			if protocolName == "socks" {
				ctx := context.WithValue(context.Background(), principalContextKey{}, p)
				if _, ok := current.socks.server.AuthorizeUDP(ctx, "", netip.MustParseAddr("203.0.113.1"), 443); ok {
					t.Fatal("SOCKS closure uses old attachment")
				}
			} else if s.destinationAllowed(context.Background(), p, current.config, "", netip.MustParseAddr("203.0.113.1"), 443, protocolName) {
				t.Fatal("new policy not enforced")
			}
		})
	}
}
func TestMASQUEAppliesDestinationPolicyBeforeDial(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	s := New(Config{Tunnels: []TunnelConfig{{Name: "reports", Target: target.Addr().String(), VirtualPort: 443, DestinationPolicy: "deny"}}, DestinationPolicies: map[string]DestinationPolicy{"deny": {}}}, nil)
	session := s.sessions.Create(CreateParams{TTL: time.Minute, Tunnels: []protocol.Tunnel{{Name: "reports"}}})
	gateway := &MASQUEGateway{server: s, config: MASQUEConfig{Tunnels: map[string]string{"reports.private": "reports"}}}
	req := httptest.NewRequest(http.MethodConnect, "https://reports.private:443", nil)
	req.Host = "reports.private:443"
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{SubjectKeyId: []byte(session.ID)}}}
	w := fullDuplexRecorder{httptest.NewRecorder()}
	gateway.connect(w, req)
	if w.Code != 502 {
		t.Fatal(w.Code)
	}
	target.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Millisecond))
	if c, err := target.Accept(); err == nil {
		c.Close()
		t.Fatal("policy-denied target was dialed")
	}
}

func TestPendingSocksCommandUsesReloadedPolicy(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	tunnel := TunnelConfig{Name: "egress", Target: "socks", VirtualPort: 12345, Allow: []string{"*"}, Socks: &SocksConfig{AllowAll: true, AllowLocalEgress: true}}
	s := New(Config{Tunnels: []TunnelConfig{tunnel}, DestinationPolicies: map[string]DestinationPolicy{"deny": {}}}, nil)
	startTestDataPlane(t, s)
	runtime := s.data.listeners[tunnel.Name].socks
	client, server := net.Pipe()
	defer client.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	ctx := context.WithValue(context.Background(), principalContextKey{}, DataPlanePrincipal{TunnelIP: netip.MustParseAddr("100.64.0.2")})
	done := make(chan struct{})
	go func() { defer close(done); runtime.server.ServeConn(ctx, server) }()
	defer func() { client.Close(); <-done }()
	if _, err := client.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil || reply[1] != 0 {
		t.Fatalf("greeting: %v %v", reply, err)
	}
	cfg := s.Config
	cfg.Tunnels = append([]TunnelConfig(nil), cfg.Tunnels...)
	cfg.Tunnels[0].DestinationPolicy = "deny"
	s.Reload(cfg)
	request := []byte{5, 1, 0, 1, 127, 0, 0, 1}
	request = binary.BigEndian.AppendUint16(request, uint16(target.Addr().(*net.TCPAddr).Port))
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	reply = make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil || reply[1] == 0 {
		t.Fatalf("pending CONNECT bypasses reloaded policy: %v %v", reply, err)
	}
	target.(*net.TCPListener).SetDeadline(time.Now().Add(50 * time.Millisecond))
	if c, err := target.Accept(); err == nil {
		c.Close()
		t.Fatal("denied target dialed")
	}
}
