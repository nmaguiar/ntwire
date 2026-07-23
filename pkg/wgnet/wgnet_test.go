package wgnet

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
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
