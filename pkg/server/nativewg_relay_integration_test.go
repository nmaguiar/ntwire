package server

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"net"
	"os"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/relay"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
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

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("client UDP bind unavailable: %v", err)
	}
	defer client.Close()
	init := make([]byte, 148)
	binary.LittleEndian.PutUint32(init, 1)
	binary.LittleEndian.PutUint32(init[4:8], 77)
	if _, err := client.WriteTo(init, advertised); err != nil {
		t.Fatal(err)
	}
	if got := receiveNativeWGPacket(t, recvFns); string(got) != string(init) {
		t.Fatalf("relay forwarded %d bytes to server, want initiation %d bytes", len(got), len(init))
	}

	response := make([]byte, 92)
	binary.LittleEndian.PutUint32(response, 2)
	binary.LittleEndian.PutUint32(response[4:8], 77)
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
			bufs := [][]byte{make([]byte, 2048)}
			sizes := make([]int, 1)
			eps := make([]conn.Endpoint, 1)
			n, err := fn(bufs, sizes, eps)
			if err != nil || n == 0 {
				got <- result{err: err}
				return
			}
			got <- result{packet: append([]byte(nil), bufs[0][:sizes[0]]...)}
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
