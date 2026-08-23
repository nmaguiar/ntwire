package server

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/relay"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"golang.org/x/crypto/ssh"
	"golang.zx2c4.com/wireguard/conn"
)

// TestNativeWireGuardRelayHostnameEndToEnd covers the path an ordinary
// WireGuard client uses: a real relay registration advertises a hostname-bound
// native listener, the server-side UDP bind associates with it, and opaque
// WireGuard packets cross the relay in both directions. In particular, the
// response must not advertise 0.0.0.0 or [::] when the listener was bound
// with a hostname or an ephemeral port.
func TestNativeWireGuardRelayHostnameEndToEnd(t *testing.T) {
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
	idPath := t.TempDir() + "/relay-id"
	if err := os.WriteFile(idPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}

	relayCfg := relay.Config{
		Domain: "relay.test",
		Registrations: []relay.RegistrationConfig{{
			Name: "home", PublicKey: string(ssh.MarshalAuthorizedKey(pub)),
		}},
	}
	relayCfg.Registrations[0].NativeWireGuard.Listen = "localhost:0"
	relayCfg.Listen.Public = "127.0.0.1:0"
	relayCfg.Listen.Agents = "127.0.0.1:0"
	relayCfg.TLS.Ephemeral = true
	r, err := relay.New(relayCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	agent, err := NewRelayAgent(RelayConfig{Enabled: true, URL: "wss://" + r.AgentsAddr().String(), Name: "home", IdentityFile: idPath, Fingerprint: r.Fingerprint()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	registered := make(chan protocol.RelayRegisterResponse, 1)
	agent.OnRegistration = func(resp protocol.RelayRegisterResponse) { registered <- resp }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go agent.Run(ctx)
	defer agent.Close()

	var registration protocol.RelayRegisterResponse
	select {
	case registration = <-registered:
	case <-time.After(5 * time.Second):
		t.Fatal("server agent did not register with relay")
	}
	if registration.NativeWireGuardAddr == "" || registration.NativeWireGuardToken == "" {
		t.Fatalf("native WireGuard registration = %+v, want address and token", registration)
	}
	advertised, err := net.ResolveUDPAddr("udp", registration.NativeWireGuardAddr)
	if err != nil {
		t.Fatalf("advertised native address %q is not resolvable: %v", registration.NativeWireGuardAddr, err)
	}
	if advertised.IP.IsUnspecified() {
		t.Fatalf("advertised native address = %q, must not be unspecified", registration.NativeWireGuardAddr)
	}

	serverBind := wstransport.NewFilterBind(conn.NewStdNetBind())
	recvFns, _, err := serverBind.Open(0)
	if err != nil {
		t.Skipf("server UDP bind unavailable: %v", err)
	}
	defer serverBind.Close()
	if err := serverBind.SendControl(wstransport.FrameNativeWireGuardAssociate, []byte(registration.NativeWireGuardToken), registration.NativeWireGuardAddr); err != nil {
		t.Fatalf("server association to %q: %v", registration.NativeWireGuardAddr, err)
	}
	time.Sleep(50 * time.Millisecond) // allow association frame to reach relay

	clientHost := "127.0.0.1"
	if advertised.IP.To4() == nil {
		clientHost = "::1"
	}
	client, err := net.ListenPacket("udp", net.JoinHostPort(clientHost, "0"))
	if err != nil {
		t.Skipf("client UDP bind unavailable: %v", err)
	}
	defer client.Close()
	init := make([]byte, 148)
	binary.LittleEndian.PutUint32(init, 1)
	binary.LittleEndian.PutUint32(init[4:8], 77)

	stopInit := make(chan struct{})
	defer close(stopInit)
	go func() {
		for {
			_, _ = client.WriteTo(init, advertised)
			select {
			case <-stopInit:
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}()

	if got := receiveNativeWGPacket(t, recvFns); string(got) != string(init) {
		t.Fatalf("relay forwarded %d bytes to server, want initiation %d bytes", len(got), len(init))
	}

	response := make([]byte, 92)
	binary.LittleEndian.PutUint32(response, 2)
	binary.LittleEndian.PutUint32(response[4:8], 99)
	binary.LittleEndian.PutUint32(response[8:12], 77)
	ep, err := serverBind.ParseEndpoint(registration.NativeWireGuardAddr)
	if err != nil {
		t.Fatal(err)
	}
	if err := serverBind.Send([][]byte{response}, ep); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatalf("client did not receive relayed server response: %v", err)
	}
	if string(buf[:n]) != string(response) {
		t.Fatalf("client received %x, want %x", buf[:n], response)
	}
}

func receiveNativeWGPacket(t *testing.T, fns []conn.ReceiveFunc) []byte {
	t.Helper()
	type result struct {
		packet []byte
		err    error
	}
	got := make(chan result, len(fns))
	for _, fn := range fns {
		go func(fn conn.ReceiveFunc) {
			for {
				bufs := [][]byte{make([]byte, 2048)}
				sizes := make([]int, 1)
				eps := make([]conn.Endpoint, 1)
				n, err := fn(bufs, sizes, eps)
				if err != nil {
					got <- result{err: err}
					return
				}
				if n > 0 {
					got <- result{packet: append([]byte(nil), bufs[0][:sizes[0]]...)}
					return
				}
			}
		}(fn)
	}
	select {
	case result := <-got:
		if result.err != nil {
			t.Fatal(result.err)
		}
		return result.packet
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not forward client initiation to associated server")
		return nil
	}
}

// TestUnchangedWireGuardClient_ThroughRelay_ToNTWireServer covers the complete
// scenario: an unmodified, official WireGuard client (modelled via wgnet.Stack)
// connecting through an ntwire relay to an ntwire server behind NAT.
//
// It validates:
// 1. Automatic relay-native-wireguard association handshake.
// 2. Full WireGuard Noise cryptographic handshake through the relay.
// 3. Bidirectional data transfer over a fixed-target tunnel.
// 4. Bidirectional data transfer over an embedded SOCKS proxy tunnel.
// 5. Native peer destination policy / tunnel grant enforcement (unauthorized tunnel rejected).
// 6. Unknown WireGuard key rejection.
func TestUnchangedWireGuardClient_ThroughRelay_ToNTWireServer(t *testing.T) {
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
	idPath := filepath.Join(t.TempDir(), "relay-id")
	if err := os.WriteFile(idPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}

	relayCfg := relay.Config{
		Domain: "relay.test",
		Registrations: []relay.RegistrationConfig{{
			Name:      "home",
			PublicKey: string(ssh.MarshalAuthorizedKey(pub)),
		}},
	}
	relayCfg.Registrations[0].NativeWireGuard.Listen = "127.0.0.1:0"
	relayCfg.Listen.Public = "127.0.0.1:0"
	relayCfg.Listen.Agents = "127.0.0.1:0"
	relayCfg.TLS.Ephemeral = true
	r, err := relay.New(relayCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	upstream := echoUpstream(t)

	serverWGKey, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	serverWGKeyPath := filepath.Join(t.TempDir(), "server_wg.key")
	if err := os.WriteFile(serverWGKeyPath, []byte(serverWGKey.Private+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	clientWGKey, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	clientTunnelIP := "100.64.0.10"

	laptopWGKey, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	laptopTunnelIP := "100.64.0.20"

	serverCfg := Config{
		DestinationPolicies: map[string]DestinationPolicy{
			"corp-only": {
				Filters: []string{"192.0.2.0/24"},
			},
		},
		Tunnels: []TunnelConfig{
			{Name: "echo-svc", Target: upstream.String(), VirtualPort: 18080, Allow: []string{"*"}},
			{Name: "socks-svc", Target: "socks", VirtualPort: 11080, Allow: []string{"*"}, Socks: &SocksConfig{AllowAll: true}},
			{Name: "restricted-svc", Target: upstream.String(), VirtualPort: 19090, Allow: []string{"*"}},
		},
		NativeWireGuard: NativeWireGuardConfig{
			Enabled: true,
			Peers: []NativeWireGuardPeer{
				{
					Name:      "phone",
					PublicKey: clientWGKey.Public,
					TunnelIP:  clientTunnelIP,
					Tunnels:   []string{"echo-svc", "socks-svc"},
				},
				{
					Name:              "laptop",
					PublicKey:         laptopWGKey.Public,
					TunnelIP:          laptopTunnelIP,
					Tunnels:           []string{"echo-svc"},
					DestinationPolicy: "corp-only",
				},
			},
		},
	}
	serverCfg.Network.TunnelCIDR = "100.64.0.0/16"
	serverCfg.Network.WireGuardPrivateKeyFile = serverWGKeyPath
	serverCfg.Listen.WireGuard = "127.0.0.1:0"
	serverCfg.Relay.Enabled = true
	serverCfg.Relay.URL = "wss://" + r.AgentsAddr().String()
	serverCfg.Relay.Name = "home"
	serverCfg.Relay.IdentityFile = idPath
	serverCfg.Relay.Fingerprint = r.Fingerprint()

	s := New(serverCfg, nil)
	if err := s.StartDataPlane(); err != nil {
		t.Fatalf("StartDataPlane: %v", err)
	}
	defer s.Close()

	agent, err := NewRelayAgent(s.Config.Relay, nil)
	if err != nil {
		t.Fatalf("NewRelayAgent: %v", err)
	}
	registered := make(chan protocol.RelayRegisterResponse, 1)
	agent.OnRegistration = func(resp protocol.RelayRegisterResponse) {
		s.EnableNativeWireGuardRelay(resp.NativeWireGuardAddr, resp.NativeWireGuardToken)
		registered <- resp
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go agent.Run(ctx)
	defer agent.Close()

	var registration protocol.RelayRegisterResponse
	select {
	case registration = <-registered:
	case <-time.After(5 * time.Second):
		t.Fatal("server agent did not register with relay")
	}
	if registration.NativeWireGuardAddr == "" || registration.NativeWireGuardToken == "" {
		t.Fatalf("native WireGuard registration = %+v, want address and token", registration)
	}
	time.Sleep(50 * time.Millisecond) // allow association frame to reach relay

	// 1. Unchanged official WireGuard client setup
	clientIP := netip.MustParseAddr(clientTunnelIP)
	clientStack, err := wgnet.New(wgnet.Config{
		PrivateKey: clientWGKey.Private,
		Addresses:  []netip.Addr{clientIP},
	})
	if err != nil {
		t.Fatalf("client wgnet.New: %v", err)
	}
	defer clientStack.Close()

	if err := clientStack.AddPeer(wgnet.Endpoint{
		PublicKey: serverWGKey.Public,
		Address:   "100.64.0.0/16@" + registration.NativeWireGuardAddr,
	}); err != nil {
		t.Fatalf("client AddPeer: %v", err)
	}

	serverTunnelIP := s.data.serverIP.String()
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dialCancel()

	// 2. Reach fixed-target tunnel
	conn, err := clientStack.DialContext(dialCtx, "tcp", net.JoinHostPort(serverTunnelIP, "18080"))
	if err != nil {
		t.Fatalf("client failed to dial fixed-target tunnel through relay: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello from unchanged wireguard client through relay")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write to tunnel: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read from tunnel: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("fixed-target tunnel echo = %q, want %q", string(got), string(msg))
	}

	// 3. Reach SOCKS tunnel
	socksConn, err := clientStack.DialContext(dialCtx, "tcp", net.JoinHostPort(serverTunnelIP, "11080"))
	if err != nil {
		t.Fatalf("client failed to dial socks tunnel through relay: %v", err)
	}
	defer socksConn.Close()

	if _, err := socksConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	sbuf := make([]byte, 2)
	if _, err := io.ReadFull(socksConn, sbuf); err != nil || sbuf[1] != 0x00 {
		t.Fatalf("socks method reply = %v, err = %v", sbuf, err)
	}

	sreq := []byte{0x05, 0x01, 0x00, 0x01}
	ip4 := upstream.Addr().As4()
	sreq = append(sreq, ip4[:]...)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], upstream.Port())
	sreq = append(sreq, portBuf[:]...)
	if _, err := socksConn.Write(sreq); err != nil {
		t.Fatal(err)
	}
	sreply := make([]byte, 10)
	if _, err := io.ReadFull(socksConn, sreply); err != nil || sreply[1] != 0x00 {
		t.Fatalf("socks connect failed: reply=%v, err=%v", sreply, err)
	}

	socksMsg := []byte("hello over socks via native wireguard relay")
	if _, err := socksConn.Write(socksMsg); err != nil {
		t.Fatal(err)
	}
	socksGot := make([]byte, len(socksMsg))
	if _, err := io.ReadFull(socksConn, socksGot); err != nil {
		t.Fatal(err)
	}
	if string(socksGot) != string(socksMsg) {
		t.Fatalf("socks echo = %q, want %q", string(socksGot), string(socksMsg))
	}

	// 4. Unauthorized tunnel is rejected for this native peer
	restrConn, err := clientStack.DialContext(dialCtx, "tcp", net.JoinHostPort(serverTunnelIP, "19090"))
	if err == nil {
		_ = restrConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		rbuf := make([]byte, 1)
		_, rerr := restrConn.Read(rbuf)
		if rerr == nil {
			t.Fatal("expected connection to restricted tunnel to be closed by server, but read succeeded")
		}
		restrConn.Close()
	}

	// 5. Destination policy enforcement on native peer (laptop has corp-only policy denying 127.0.0.1)
	laptopIP := netip.MustParseAddr(laptopTunnelIP)
	laptopStack, err := wgnet.New(wgnet.Config{
		PrivateKey: laptopWGKey.Private,
		Addresses:  []netip.Addr{laptopIP},
	})
	if err != nil {
		t.Fatalf("laptop wgnet.New: %v", err)
	}
	defer laptopStack.Close()

	if err := laptopStack.AddPeer(wgnet.Endpoint{
		PublicKey: serverWGKey.Public,
		Address:   "100.64.0.0/16@" + registration.NativeWireGuardAddr,
	}); err != nil {
		t.Fatalf("laptop AddPeer: %v", err)
	}

	laptopConn, err := laptopStack.DialContext(dialCtx, "tcp", net.JoinHostPort(serverTunnelIP, "18080"))
	if err == nil {
		_ = laptopConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		rbuf := make([]byte, 1)
		_, rerr := laptopConn.Read(rbuf)
		if rerr == nil {
			t.Fatal("expected connection denied by destination policy to be closed, but read succeeded")
		}
		laptopConn.Close()
	}

	// 6. Unknown WireGuard peer key is rejected
	unknownWGKey, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	unknownStack, err := wgnet.New(wgnet.Config{
		PrivateKey: unknownWGKey.Private,
		Addresses:  []netip.Addr{netip.MustParseAddr("100.64.0.99")},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer unknownStack.Close()

	if err := unknownStack.AddPeer(wgnet.Endpoint{
		PublicKey: serverWGKey.Public,
		Address:   "100.64.0.0/16@" + registration.NativeWireGuardAddr,
	}); err != nil {
		t.Fatal(err)
	}

	uctx, ucancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer ucancel()
	_, uerr := unknownStack.DialContext(uctx, "tcp", net.JoinHostPort(serverTunnelIP, "18080"))
	if uerr == nil {
		t.Fatal("expected dial from unknown wireguard peer to fail")
	}

	// 7. Dynamic peer revocation on config reload
	reloadedCfg := serverCfg
	reloadedCfg.NativeWireGuard.Peers = []NativeWireGuardPeer{
		{
			Name:      "laptop",
			PublicKey: laptopWGKey.Public,
			TunnelIP:  laptopTunnelIP,
			Tunnels:   []string{"echo-svc"},
		},
	}
	s.Reload(reloadedCfg)

	revokedCtx, revokedCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer revokedCancel()
	_, rerr := clientStack.DialContext(revokedCtx, "tcp", net.JoinHostPort(serverTunnelIP, "18080"))
	if rerr == nil {
		t.Fatal("expected dial from revoked peer to fail after reload")
	}
}

// TestUnchangedWireGuardClient_MultiClientThroughRelay verifies that multiple
// unmodified WireGuard clients can concurrently establish independent tunnels
// and stream data through a single tenant relay UDP port to the server.
func TestUnchangedWireGuardClient_MultiClientThroughRelay(t *testing.T) {
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
	idPath := filepath.Join(t.TempDir(), "relay-id")
	if err := os.WriteFile(idPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}

	relayCfg := relay.Config{
		Domain: "relay.test",
		Registrations: []relay.RegistrationConfig{{
			Name:      "home",
			PublicKey: string(ssh.MarshalAuthorizedKey(pub)),
		}},
	}
	relayCfg.Registrations[0].NativeWireGuard.Listen = "127.0.0.1:0"
	relayCfg.Listen.Public = "127.0.0.1:0"
	relayCfg.Listen.Agents = "127.0.0.1:0"
	relayCfg.TLS.Ephemeral = true
	r, err := relay.New(relayCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	upstream := echoUpstream(t)

	serverWGKey, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	serverWGKeyPath := filepath.Join(t.TempDir(), "server_wg.key")
	if err := os.WriteFile(serverWGKeyPath, []byte(serverWGKey.Private+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	client1WGKey, _ := wgnet.GenerateKey()
	client2WGKey, _ := wgnet.GenerateKey()

	serverCfg := Config{
		Tunnels: []TunnelConfig{
			{Name: "echo-svc", Target: upstream.String(), VirtualPort: 18080, Allow: []string{"*"}},
		},
		NativeWireGuard: NativeWireGuardConfig{
			Enabled: true,
			Peers: []NativeWireGuardPeer{
				{Name: "client-1", PublicKey: client1WGKey.Public, TunnelIP: "100.64.0.11", Tunnels: []string{"echo-svc"}},
				{Name: "client-2", PublicKey: client2WGKey.Public, TunnelIP: "100.64.0.12", Tunnels: []string{"echo-svc"}},
			},
		},
	}
	serverCfg.Network.TunnelCIDR = "100.64.0.0/16"
	serverCfg.Network.WireGuardPrivateKeyFile = serverWGKeyPath
	serverCfg.Listen.WireGuard = "127.0.0.1:0"
	serverCfg.Relay.Enabled = true
	serverCfg.Relay.URL = "wss://" + r.AgentsAddr().String()
	serverCfg.Relay.Name = "home"
	serverCfg.Relay.IdentityFile = idPath
	serverCfg.Relay.Fingerprint = r.Fingerprint()

	s := New(serverCfg, nil)
	if err := s.StartDataPlane(); err != nil {
		t.Fatalf("StartDataPlane: %v", err)
	}
	defer s.Close()

	agent, err := NewRelayAgent(s.Config.Relay, nil)
	if err != nil {
		t.Fatalf("NewRelayAgent: %v", err)
	}
	registered := make(chan protocol.RelayRegisterResponse, 1)
	agent.OnRegistration = func(resp protocol.RelayRegisterResponse) {
		s.EnableNativeWireGuardRelay(resp.NativeWireGuardAddr, resp.NativeWireGuardToken)
		registered <- resp
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go agent.Run(ctx)
	defer agent.Close()

	var registration protocol.RelayRegisterResponse
	select {
	case registration = <-registered:
	case <-time.After(5 * time.Second):
		t.Fatal("server agent did not register with relay")
	}
	time.Sleep(50 * time.Millisecond)

	startClient := func(key wgnet.Key, ipStr string) *wgnet.Stack {
		ip := netip.MustParseAddr(ipStr)
		stack, err := wgnet.New(wgnet.Config{
			PrivateKey: key.Private,
			Addresses:  []netip.Addr{ip},
		})
		if err != nil {
			t.Fatalf("wgnet.New: %v", err)
		}
		if err := stack.AddPeer(wgnet.Endpoint{
			PublicKey: serverWGKey.Public,
			Address:   "100.64.0.0/16@" + registration.NativeWireGuardAddr,
		}); err != nil {
			t.Fatalf("AddPeer: %v", err)
		}
		return stack
	}

	c1 := startClient(client1WGKey, "100.64.0.11")
	defer c1.Close()
	c2 := startClient(client2WGKey, "100.64.0.12")
	defer c2.Close()

	serverTunnelIP := s.data.serverIP.String()
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dialCancel()

	runEcho := func(stack *wgnet.Stack, name string) {
		conn, err := stack.DialContext(dialCtx, "tcp", net.JoinHostPort(serverTunnelIP, "18080"))
		if err != nil {
			t.Fatalf("%s failed to dial: %v", name, err)
		}
		defer conn.Close()
		for i := 0; i < 5; i++ {
			msg := fmt.Sprintf("message %d from %s", i, name)
			if _, err := conn.Write([]byte(msg)); err != nil {
				t.Fatalf("%s write: %v", name, err)
			}
			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(conn, buf); err != nil {
				t.Fatalf("%s read: %v", name, err)
			}
			if string(buf) != msg {
				t.Fatalf("%s got %q, want %q", name, string(buf), msg)
			}
		}
	}

	done := make(chan error, 2)
	go func() {
		runEcho(c1, "client-1")
		done <- nil
	}()
	go func() {
		runEcho(c2, "client-2")
		done <- nil
	}()

	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for concurrent client transfers")
		}
	}
}
