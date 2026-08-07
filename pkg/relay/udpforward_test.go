package relay

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

func mustListenUDPForTest(t *testing.T) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback UDP unavailable: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc
}

func readWithTimeout(t *testing.T, pc net.PacketConn, timeout time.Duration) ([]byte, bool) {
	t.Helper()
	_ = pc.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 2048)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		return nil, false
	}
	out := make([]byte, n)
	copy(out, buf[:n])
	return out, true
}

// newTestDatagramRelay wires a datagramRelay with a one-port pool exactly as
// Relay.Start would for a listen.udp_relay_ports range covering one port,
// and starts its serve goroutines.
func newTestDatagramRelay(t *testing.T) (table *udpSessionTable, clientFacing, pooled net.PacketConn) {
	t.Helper()
	clientFacing = mustListenUDPForTest(t)
	pooled = mustListenUDPForTest(t)
	poolPort := uint16(pooled.LocalAddr().(*net.UDPAddr).Port)
	alloc := newPortAllocator(map[uint16]net.PacketConn{poolPort: pooled})
	table = newUDPSessionTable(alloc, Limits{MaxUDPRelaySessionsPerServer: 10})
	dr := newDatagramRelay(table, clientFacing, 1000, nil)
	go dr.serveClientLeg()
	go dr.serveServerLeg(pooled, poolPort)
	return table, clientFacing, pooled
}

// bindTestSession allocates a session on tenant and performs the full
// bind dance from a pair of fresh loopback sockets standing in for the real
// server and client, returning both sockets once bound.
func bindTestSession(t *testing.T, table *udpSessionTable, clientFacing, pooled net.PacketConn, tenant string) (serverSock, clientSock net.PacketConn) {
	t.Helper()
	serverSock = mustListenUDPForTest(t)
	clientSock = mustListenUDPForTest(t)

	token, serverAddr, err := table.Allocate(tenant)
	if err != nil {
		t.Fatal(err)
	}
	relayServerAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		t.Fatal(err)
	}

	bind := wstransport.EncodeControlFrame(wstransport.FrameRelayBind, []byte(token))
	if _, err := serverSock.WriteTo(bind, relayServerAddr); err != nil {
		t.Fatal(err)
	}
	if _, ok := readWithTimeout(t, serverSock, time.Second); !ok {
		t.Fatal("did not receive FrameRelayBindAck for server bind")
	}
	if _, err := clientSock.WriteTo(bind, clientFacing.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if _, ok := readWithTimeout(t, clientSock, time.Second); !ok {
		t.Fatal("did not receive FrameRelayBindAck for client bind")
	}
	_ = pooled
	return serverSock, clientSock
}

func TestDatagramRelayDropsUntilBothLegsBound(t *testing.T) {
	table, clientFacing, pooled := newTestDatagramRelay(t)
	serverSock := mustListenUDPForTest(t)
	clientSock := mustListenUDPForTest(t)

	token, serverAddr, err := table.Allocate("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	relayServerAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x01}, 32)

	// Neither leg bound yet: dropped.
	if _, err := clientSock.WriteTo(payload, clientFacing.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if _, ok := readWithTimeout(t, serverSock, 200*time.Millisecond); ok {
		t.Fatal("unbound session forwarded a datagram, want it dropped")
	}

	// Bind only the server leg: still half-bound, still dropped.
	bind := wstransport.EncodeControlFrame(wstransport.FrameRelayBind, []byte(token))
	if _, err := serverSock.WriteTo(bind, relayServerAddr); err != nil {
		t.Fatal(err)
	}
	if _, ok := readWithTimeout(t, serverSock, time.Second); !ok {
		t.Fatal("did not receive FrameRelayBindAck for server bind")
	}
	if _, err := clientSock.WriteTo(payload, clientFacing.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if _, ok := readWithTimeout(t, serverSock, 200*time.Millisecond); ok {
		t.Fatal("half-bound (server only) session forwarded a datagram, want it dropped")
	}

	// Bind the client leg too: now forwarding must work.
	if _, err := clientSock.WriteTo(bind, clientFacing.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if _, ok := readWithTimeout(t, clientSock, time.Second); !ok {
		t.Fatal("did not receive FrameRelayBindAck for client bind")
	}
	if _, err := clientSock.WriteTo(payload, clientFacing.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	got, ok := readWithTimeout(t, serverSock, time.Second)
	if !ok || !bytes.Equal(got, payload) {
		t.Fatalf("server did not receive forwarded datagram once both legs bound (ok=%v)", ok)
	}
	_ = pooled
}

func TestDatagramRelayForwardsBothDirectionsOnceBound(t *testing.T) {
	table, clientFacing, pooled := newTestDatagramRelay(t)
	serverSock, clientSock := bindTestSession(t, table, clientFacing, pooled, "tenant-a")

	toServer := bytes.Repeat([]byte{0xAA}, 40)
	if _, err := clientSock.WriteTo(toServer, clientFacing.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	got, ok := readWithTimeout(t, serverSock, time.Second)
	if !ok || !bytes.Equal(got, toServer) {
		t.Fatalf("server did not receive client->server datagram (ok=%v)", ok)
	}

	toClient := bytes.Repeat([]byte{0xBB}, 40)
	if _, err := serverSock.WriteTo(toClient, pooled.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	got, ok = readWithTimeout(t, clientSock, time.Second)
	if !ok || !bytes.Equal(got, toClient) {
		t.Fatalf("client did not receive server->client datagram (ok=%v)", ok)
	}
}

func TestDatagramRelayDropsOversizedDatagram(t *testing.T) {
	table, clientFacing, pooled := newTestDatagramRelay(t)
	serverSock, clientSock := bindTestSession(t, table, clientFacing, pooled, "tenant-a")

	oversized := bytes.Repeat([]byte{0xCC}, wstransport.MaxRelayDatagram+100)
	if _, err := clientSock.WriteTo(oversized, clientFacing.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if _, ok := readWithTimeout(t, serverSock, 300*time.Millisecond); ok {
		t.Fatal("oversized datagram was forwarded, want it dropped")
	}
}

// TestDatagramRelayForwardsPathProbeOnlyWhenBound exercises the A6 claim
// directly: a FramePathProbe/FramePathAck is opaque to the relay, but still
// only ever forwarded under the same token-verified bind/address-lock check
// as an ordinary WireGuard datagram -- never trusted on frame type alone.
func TestDatagramRelayForwardsPathProbeOnlyWhenBound(t *testing.T) {
	table, clientFacing, pooled := newTestDatagramRelay(t)
	serverSock, clientSock := bindTestSession(t, table, clientFacing, pooled, "tenant-probe")

	probe := wstransport.EncodeControlFrame(wstransport.FramePathProbe, bytes.Repeat([]byte{0x05}, 12))

	// An unbound sender's probe must be dropped, exactly like an ordinary
	// unbound datagram.
	unbound := mustListenUDPForTest(t)
	if _, err := unbound.WriteTo(probe, clientFacing.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if _, ok := readWithTimeout(t, serverSock, 200*time.Millisecond); ok {
		t.Fatal("path probe from an unbound sender was forwarded, want it dropped")
	}

	// The bound client's probe forwards byte-for-byte, opaque to the relay.
	if _, err := clientSock.WriteTo(probe, clientFacing.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	got, ok := readWithTimeout(t, serverSock, time.Second)
	if !ok || !bytes.Equal(got, probe) {
		t.Fatalf("path probe from the bound client was not forwarded byte-for-byte (ok=%v)", ok)
	}

	// The ack direction (server leg -> client-facing socket) is symmetric.
	ack := wstransport.EncodeControlFrame(wstransport.FramePathAck, bytes.Repeat([]byte{0x06}, 12))
	if _, err := serverSock.WriteTo(ack, pooled.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	got, ok = readWithTimeout(t, clientSock, time.Second)
	if !ok || !bytes.Equal(got, ack) {
		t.Fatalf("path ack from the bound server was not forwarded byte-for-byte (ok=%v)", ok)
	}
}

// TestDatagramRelayDropsMalformedPathControl confirms a probe/ack frame
// whose payload doesn't match the fixed 12-byte shape is dropped even from a
// fully bound sender, rather than forwarded as if it were valid.
func TestDatagramRelayDropsMalformedPathControl(t *testing.T) {
	table, clientFacing, pooled := newTestDatagramRelay(t)
	serverSock, clientSock := bindTestSession(t, table, clientFacing, pooled, "tenant-probe")

	malformed := wstransport.EncodeControlFrame(wstransport.FramePathProbe, []byte{0x01, 0x02})
	if _, err := clientSock.WriteTo(malformed, clientFacing.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if _, ok := readWithTimeout(t, serverSock, 200*time.Millisecond); ok {
		t.Fatal("malformed path probe was forwarded, want it dropped")
	}
}

func TestDatagramRelayIsolatesConcurrentSessions(t *testing.T) {
	clientFacing := mustListenUDPForTest(t)
	pooled1 := mustListenUDPForTest(t)
	pooled2 := mustListenUDPForTest(t)
	port1 := uint16(pooled1.LocalAddr().(*net.UDPAddr).Port)
	port2 := uint16(pooled2.LocalAddr().(*net.UDPAddr).Port)
	alloc := newPortAllocator(map[uint16]net.PacketConn{port1: pooled1, port2: pooled2})
	table := newUDPSessionTable(alloc, Limits{MaxUDPRelaySessionsPerServer: 10})
	dr := newDatagramRelay(table, clientFacing, 1000, nil)
	go dr.serveClientLeg()
	go dr.serveServerLeg(pooled1, port1)
	go dr.serveServerLeg(pooled2, port2)

	serverA, clientA := bindTestSession(t, table, clientFacing, pooled1, "tenant-a")
	serverB, _ := bindTestSession(t, table, clientFacing, pooled2, "tenant-b")

	payloadA := bytes.Repeat([]byte{0xAA}, 20)
	if _, err := clientA.WriteTo(payloadA, clientFacing.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	got, ok := readWithTimeout(t, serverA, time.Second)
	if !ok || !bytes.Equal(got, payloadA) {
		t.Fatalf("server A did not receive its own client's datagram (ok=%v)", ok)
	}
	if _, ok := readWithTimeout(t, serverB, 200*time.Millisecond); ok {
		t.Fatal("server B received a datagram meant for server A's session, want session isolation")
	}
}
