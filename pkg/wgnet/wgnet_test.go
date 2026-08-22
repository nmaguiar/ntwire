package wgnet

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDecodeKeyConvertsProtocolBase64ToWireGuardIPCBytes(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}

	decoded, err := decodeKey(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(decoded), hex.EncodeToString(raw); got != want {
		t.Errorf("WireGuard IPC key = %q, want %q", got, want)
	}
}

func TestDecodeKeyRejectsInvalidLengths(t *testing.T) {
	_, err := decodeKey(base64.StdEncoding.EncodeToString([]byte("too short")))
	if err == nil || !strings.Contains(err.Error(), "expected 32 bytes") {
		t.Fatalf("decodeKey() error = %v, want 32-byte validation error", err)
	}
}

func TestGenerateKeyProducesDistinctValidKeys(t *testing.T) {
	a, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if a.Private == b.Private || a.Public == b.Public {
		t.Fatalf("GenerateKey() produced repeated key material: %+v, %+v", a, b)
	}
	if _, err := decodeKey(a.Private); err != nil {
		t.Errorf("private key not valid WireGuard IPC material: %v", err)
	}
	if _, err := decodeKey(a.Public); err != nil {
		t.Errorf("public key not valid WireGuard IPC material: %v", err)
	}
}

func TestPublicKeyFromPrivate(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	derived, err := PublicKeyFromPrivate(key.Private)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate failed: %v", err)
	}
	if derived != key.Public {
		t.Errorf("PublicKeyFromPrivate() = %q, want %q", derived, key.Public)
	}

	if _, err := PublicKeyFromPrivate("invalid-base64"); err == nil {
		t.Errorf("PublicKeyFromPrivate(\"invalid-base64\") should fail")
	}
}

func TestNewDerivesPublicKeyFromProvidedPrivateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{PrivateKey: key.Private, Addresses: []netip.Addr{netip.MustParseAddr("100.65.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.PublicKey() != key.Public {
		t.Errorf("PublicKey() = %q, want %q (derived from the supplied private key)", s.PublicKey(), key.Public)
	}
}

func TestNewGeneratesKeyWhenPrivateKeyOmitted(t *testing.T) {
	s, err := New(Config{Addresses: []netip.Addr{netip.MustParseAddr("100.65.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.PublicKey() == "" {
		t.Errorf("PublicKey() empty, want a generated key")
	}
}

func TestAddPeerRejectsInvalidPublicKey(t *testing.T) {
	s, err := New(Config{Addresses: []netip.Addr{netip.MustParseAddr("100.65.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.AddPeer(Endpoint{PublicKey: "not-base64!!", Address: "100.65.0.2/32"}); err == nil {
		t.Fatal("AddPeer() with an invalid public key succeeded, want an error")
	}
}

func TestRemovePeerAfterAdd(t *testing.T) {
	s, err := New(Config{Addresses: []netip.Addr{netip.MustParseAddr("100.65.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	peer, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddPeer(Endpoint{PublicKey: peer.Public, Address: "100.65.0.2/32"}); err != nil {
		t.Fatalf("AddPeer() = %v", err)
	}
	if err := s.RemovePeer(hex.EncodeToString(mustDecodeKey(t, peer.Public))); err != nil {
		t.Fatalf("RemovePeer() = %v", err)
	}
}

func TestListenRejectsNonTCPNetwork(t *testing.T) {
	s, err := New(Config{Addresses: []netip.Addr{netip.MustParseAddr("100.65.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Listen("udp", "100.65.0.1:9000"); err == nil {
		t.Fatal("Listen(\"udp\", ...) succeeded, want an error: only tcp is supported")
	}
}

// TestStackRoundTripsTCPThroughWireGuardPeers builds two real Stacks (server
// and client), peers them over loopback UDP the same way pkg/server and
// pkg/client do (server AddPeer has no endpoint and learns the client's
// source address from its handshake; client AddPeer points at the server's
// known endpoint), then proves a TCP byte stream survives an actual
// WireGuard handshake and netstack forward end to end.
func TestStackRoundTripsTCPThroughWireGuardPeers(t *testing.T) {
	serverPort := freeUDPPort(t)
	serverIP := netip.MustParseAddr("100.65.0.1")
	clientIP := netip.MustParseAddr("100.65.0.2")

	server, err := New(Config{Addresses: []netip.Addr{serverIP}, ListenPort: serverPort})
	if err != nil {
		t.Fatalf("server New() = %v", err)
	}
	defer server.Close()
	client, err := New(Config{Addresses: []netip.Addr{clientIP}})
	if err != nil {
		t.Fatalf("client New() = %v", err)
	}
	defer client.Close()

	if err := server.AddPeer(Endpoint{PublicKey: client.PublicKey(), Address: clientIP.String() + "/32"}); err != nil {
		t.Fatalf("server.AddPeer() = %v", err)
	}
	if err := client.AddPeer(Endpoint{PublicKey: server.PublicKey(), Address: "0.0.0.0/0@127.0.0.1:" + strconv.Itoa(serverPort)}); err != nil {
		t.Fatalf("client.AddPeer() = %v", err)
	}

	ln, err := server.Listen("tcp", serverIP.String()+":9000")
	if err != nil {
		t.Fatalf("server.Listen() = %v", err)
	}
	defer ln.Close()

	echoErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			echoErr <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		if _, err := conn.Read(buf); err != nil {
			echoErr <- err
			return
		}
		_, err = conn.Write(buf)
		echoErr <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", serverIP.String()+":9000")
	if err != nil {
		t.Fatalf("client.DialContext() through WireGuard peer = %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write = %v", err)
	}
	reply := make([]byte, 4)
	if _, err := conn.Read(reply); err != nil {
		t.Fatalf("read = %v", err)
	}
	if !bytes.Equal(reply, []byte("ping")) {
		t.Fatalf("echoed payload = %q, want %q", reply, "ping")
	}
	if err := <-echoErr; err != nil {
		t.Fatalf("server-side echo goroutine error = %v", err)
	}
}

func TestLastHandshakeReportsUnknownPeer(t *testing.T) {
	s, err := New(Config{Addresses: []netip.Addr{netip.MustParseAddr("100.65.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	peer, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.LastHandshake(peer.Public); err != nil || found {
		t.Fatalf("LastHandshake() for a never-added peer = (found=%v, err=%v), want (false, nil)", found, err)
	}
}

func TestUpdateEndpointRejectsInvalidPublicKey(t *testing.T) {
	s, err := New(Config{Addresses: []netip.Addr{netip.MustParseAddr("100.65.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.UpdateEndpoint("not-base64!!", "127.0.0.1:1"); err == nil {
		t.Fatal("UpdateEndpoint() with an invalid public key succeeded, want an error")
	}
}

// TestLastHandshakeAfterRoundTripAndUpdateEndpoint reuses
// TestStackRoundTripsTCPThroughWireGuardPeers' two-Stack fixture to prove
// LastHandshake reports a real, recent time once a handshake has actually
// completed (not just the zero Unix epoch a never-handshaked peer reports),
// and that UpdateEndpoint accepts a valid peer without erroring -- exactly
// the two calls pkg/client's opportunistic direct-UDP upgrade depends on for
// seeding a candidate and detecting whether it needs to revert.
func TestLastHandshakeAfterRoundTripAndUpdateEndpoint(t *testing.T) {
	serverPort := freeUDPPort(t)
	serverIP := netip.MustParseAddr("100.65.0.1")
	clientIP := netip.MustParseAddr("100.65.0.2")

	server, err := New(Config{Addresses: []netip.Addr{serverIP}, ListenPort: serverPort})
	if err != nil {
		t.Fatalf("server New() = %v", err)
	}
	defer server.Close()
	client, err := New(Config{Addresses: []netip.Addr{clientIP}})
	if err != nil {
		t.Fatalf("client New() = %v", err)
	}
	defer client.Close()

	if err := server.AddPeer(Endpoint{PublicKey: client.PublicKey(), Address: clientIP.String() + "/32"}); err != nil {
		t.Fatalf("server.AddPeer() = %v", err)
	}
	if err := client.AddPeer(Endpoint{PublicKey: server.PublicKey(), Address: "0.0.0.0/0@127.0.0.1:" + strconv.Itoa(serverPort)}); err != nil {
		t.Fatalf("client.AddPeer() = %v", err)
	}

	if _, found, err := server.LastHandshake(client.PublicKey()); err != nil || !found {
		t.Fatalf("LastHandshake() before any traffic = (found=%v, err=%v), want (true, nil)", found, err)
	}

	ln, err := server.Listen("tcp", serverIP.String()+":9000")
	if err != nil {
		t.Fatalf("server.Listen() = %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", serverIP.String()+":9000")
	if err != nil {
		t.Fatalf("client.DialContext() through WireGuard peer = %v", err)
	}
	conn.Close()

	// The TCP handshake above forced a WireGuard handshake as a side
	// effect; give the device a moment to record it before polling.
	deadline := time.Now().Add(5 * time.Second)
	var last time.Time
	for time.Now().Before(deadline) {
		last, _, err = server.LastHandshake(client.PublicKey())
		if err != nil {
			t.Fatalf("LastHandshake() = %v", err)
		}
		if time.Since(last) < time.Minute {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if time.Since(last) >= time.Minute {
		t.Fatalf("LastHandshake() = %v, want a time within the last minute", last)
	}

	if err := client.UpdateEndpoint(server.PublicKey(), "127.0.0.1:"+strconv.Itoa(serverPort)); err != nil {
		t.Fatalf("UpdateEndpoint() on an existing peer = %v", err)
	}
}

// TestPeerEndpointTracksSeededValue is the assertion pkg/client's
// opportunistic direct-UDP upgrade depends on to tell "the direct candidate
// I seeded is still active" apart from "wireguard-go's own roaming silently
// moved it back to whatever transport a packet last arrived on" -- a plain
// probe cannot distinguish those two cases if both transports are live on
// the same device, but the peer's actual recorded endpoint can.
func TestPeerEndpointTracksSeededValue(t *testing.T) {
	s, err := New(Config{Addresses: []netip.Addr{netip.MustParseAddr("100.65.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	peer, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	if _, found, err := s.PeerEndpoint(peer.Public); err != nil || found {
		t.Fatalf("PeerEndpoint() for a never-added peer = (found=%v, err=%v), want (false, nil)", found, err)
	}

	if err := s.AddPeer(Endpoint{PublicKey: peer.Public, Address: "100.65.0.2/32"}); err != nil {
		t.Fatalf("AddPeer() = %v", err)
	}
	if ep, found, err := s.PeerEndpoint(peer.Public); err != nil || !found || ep != "" {
		t.Fatalf("PeerEndpoint() for a peer added with no @host:port = (ep=%q, found=%v, err=%v), want (\"\", true, nil)", ep, found, err)
	}

	if err := s.UpdateEndpoint(peer.Public, "127.0.0.1:51000"); err != nil {
		t.Fatalf("UpdateEndpoint() = %v", err)
	}
	if ep, found, err := s.PeerEndpoint(peer.Public); err != nil || !found || ep != "127.0.0.1:51000" {
		t.Fatalf("PeerEndpoint() after UpdateEndpoint(\"127.0.0.1:51000\") = (ep=%q, found=%v, err=%v), want (\"127.0.0.1:51000\", true, nil)", ep, found, err)
	}

	if err := s.UpdateEndpoint(peer.Public, "0.0.0.0:0"); err != nil {
		t.Fatalf("UpdateEndpoint() = %v", err)
	}
	if ep, found, err := s.PeerEndpoint(peer.Public); err != nil || !found || ep != "0.0.0.0:0" {
		t.Fatalf("PeerEndpoint() after UpdateEndpoint(\"0.0.0.0:0\") = (ep=%q, found=%v, err=%v), want (\"0.0.0.0:0\", true, nil)", ep, found, err)
	}
}

// TestUpdateEndpointPreservesAllowedIPs guards against the single most
// destructive possible regression in this area: UpdateEndpoint's IpcSet
// payload is deliberately just "public_key=...\nendpoint=...\n", with no
// replace_allowed_ips or allowed_ip line, on the assumption that wireguard-go
// only touches a peer's allowed-ips when one of those is present (see
// device/uapi.go). If that assumption were ever wrong, every tunnel would
// die the instant the opportunistic direct-UDP upgrade seeded a candidate --
// silently, since UpdateEndpoint itself would still return nil. This proves
// it empirically with a real TCP round trip through the tunnel, both before
// and after an UpdateEndpoint call, reusing
// TestStackRoundTripsTCPThroughWireGuardPeers' two-Stack fixture.
func TestUpdateEndpointPreservesAllowedIPs(t *testing.T) {
	serverPort := freeUDPPort(t)
	serverIP := netip.MustParseAddr("100.65.0.1")
	clientIP := netip.MustParseAddr("100.65.0.2")

	server, err := New(Config{Addresses: []netip.Addr{serverIP}, ListenPort: serverPort})
	if err != nil {
		t.Fatalf("server New() = %v", err)
	}
	defer server.Close()
	client, err := New(Config{Addresses: []netip.Addr{clientIP}})
	if err != nil {
		t.Fatalf("client New() = %v", err)
	}
	defer client.Close()

	if err := server.AddPeer(Endpoint{PublicKey: client.PublicKey(), Address: clientIP.String() + "/32"}); err != nil {
		t.Fatalf("server.AddPeer() = %v", err)
	}
	if err := client.AddPeer(Endpoint{PublicKey: server.PublicKey(), Address: "0.0.0.0/0@127.0.0.1:" + strconv.Itoa(serverPort)}); err != nil {
		t.Fatalf("client.AddPeer() = %v", err)
	}

	ln, err := server.Listen("tcp", serverIP.String()+":9001")
	if err != nil {
		t.Fatalf("server.Listen() = %v", err)
	}
	defer ln.Close()
	echo := func() error {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		defer conn.Close()
		buf := make([]byte, 4)
		if _, err := conn.Read(buf); err != nil {
			return err
		}
		_, err = conn.Write(buf)
		return err
	}
	roundTrip := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := client.DialContext(ctx, "tcp", serverIP.String()+":9001")
		if err != nil {
			return fmt.Errorf("dial: %w", err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("ping")); err != nil {
			return fmt.Errorf("write: %w", err)
		}
		reply := make([]byte, 4)
		if _, err := conn.Read(reply); err != nil {
			return fmt.Errorf("read: %w", err)
		}
		if !bytes.Equal(reply, []byte("ping")) {
			return fmt.Errorf("echoed payload = %q, want %q", reply, "ping")
		}
		return nil
	}

	echoErr := make(chan error, 1)
	go func() { echoErr <- echo() }()
	if err := roundTrip(); err != nil {
		t.Fatalf("round trip before UpdateEndpoint failed: %v", err)
	}
	if err := <-echoErr; err != nil {
		t.Fatalf("server-side echo before UpdateEndpoint failed: %v", err)
	}

	// Re-seed the client's peer endpoint to the exact same address it
	// already has -- UpdateEndpoint doesn't know or care that this is a
	// no-op destination; what matters is whether its bare
	// "public_key=...\nendpoint=...\n" IPC write leaves allowed-ips intact.
	if err := client.UpdateEndpoint(server.PublicKey(), "127.0.0.1:"+strconv.Itoa(serverPort)); err != nil {
		t.Fatalf("UpdateEndpoint() = %v", err)
	}

	go func() { echoErr <- echo() }()
	if err := roundTrip(); err != nil {
		t.Fatalf("round trip after UpdateEndpoint failed (allowed-ips likely cleared): %v", err)
	}
	if err := <-echoErr; err != nil {
		t.Fatalf("server-side echo after UpdateEndpoint failed: %v", err)
	}
}

func mustDecodeKey(t *testing.T, encoded string) []byte {
	t.Helper()
	raw, err := decodeKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// freeUDPPort finds a currently-unused UDP port by briefly binding to
// 127.0.0.1:0 and releasing it, so a Stack under test can be given a fixed,
// known ListenPort for its peer to dial back to.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}
