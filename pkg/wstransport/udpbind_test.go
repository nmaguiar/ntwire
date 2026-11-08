package wstransport

import (
	"bytes"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

func TestUDPBindTunesSocketsAndRetainsBatchedIPv4IO(t *testing.T) {
	receiver := NewUDPBind(64<<10, nil)
	defer receiver.Close()
	receiveFns, port, err := receiver.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	var v4 UDPBufferStatus
	for _, status := range receiver.BufferStatus() {
		if status.Socket == "ipv4" {
			v4 = status
			break
		}
	}
	if v4.Requested != 64<<10 {
		t.Fatalf("IPv4 requested buffer = %d, want %d", v4.Requested, 64<<10)
	}
	if v4.Err != nil || v4.Read <= 0 || v4.Write <= 0 {
		t.Fatalf("IPv4 effective buffers = %+v, want positive accepted values", v4)
	}
	if receiver.BatchSize() != conn.IdealBatchSize && receiver.BatchSize() != 1 {
		t.Fatalf("unexpected batch size %d", receiver.BatchSize())
	}

	sender := NewUDPBind(0, nil)
	defer sender.Close()
	if _, _, err := sender.Open(0); err != nil {
		t.Fatal(err)
	}
	ep, err := sender.ParseEndpoint("127.0.0.1:" + strconv.Itoa(int(port)))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("tuned UDP bind")
	if err := sender.Send([][]byte{want}, ep); err != nil {
		t.Fatal(err)
	}
	bufs := make([][]byte, receiver.BatchSize())
	for i := range bufs {
		bufs[i] = make([]byte, 128)
	}
	sizes := make([]int, len(bufs))
	eps := make([]conn.Endpoint, len(bufs))
	n, err := receiveFns[0](bufs, sizes, eps)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || !bytes.Equal(bufs[0][:sizes[0]], want) || !eps[0].DstIP().Is4() {
		t.Fatalf("receive = n=%d payload=%q endpoint=%v; want one IPv4 %q packet", n, bufs[0][:sizes[0]], eps[0], want)
	}
}

func TestUDPBind_AltPortRepliesFromSocketPeerUsed(t *testing.T) {
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	altPort := uint16(probe.LocalAddr().(*net.UDPAddr).Port)
	_ = probe.Close()

	b := NewUDPBind(0, nil)
	b.SetAltPort(altPort)
	fns, port, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer b.Close()
	if port == altPort {
		t.Fatalf("primary port %d equals alt port", port)
	}
	received := make(chan string, 8)
	for _, fn := range fns {
		go func(fn conn.ReceiveFunc) {
			bufs := make([][]byte, conn.IdealBatchSize)
			for i := range bufs {
				bufs[i] = make([]byte, 1500)
			}
			sizes := make([]int, len(bufs))
			eps := make([]conn.Endpoint, len(bufs))
			for {
				n, err := fn(bufs[:1], sizes, eps)
				if err != nil {
					return
				}
				for i := 0; i < n; i++ {
					received <- eps[i].DstToString()
				}
			}
		}(fn)
	}
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	roundTrip := func(serverPort uint16) int {
		t.Helper()
		if _, err := peer.WriteToUDP([]byte("hello"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(serverPort)}); err != nil {
			t.Fatal(err)
		}
		var from string
		select {
		case from = <-received:
		case <-time.After(2 * time.Second):
			t.Fatal("bind did not receive datagram")
		}
		ep, err := b.ParseEndpoint(from)
		if err != nil {
			t.Fatal(err)
		}
		if err := b.Send([][]byte{[]byte("reply")}, ep); err != nil {
			t.Fatal(err)
		}
		_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 64)
		_, src, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("no reply: %v", err)
		}
		return src.Port
	}
	if got := roundTrip(altPort); got != int(altPort) {
		t.Fatalf("reply after alt datagram came from port %d, want alt %d", got, altPort)
	}
	if got := roundTrip(port); got != int(port) {
		t.Fatalf("reply after primary datagram came from port %d, want primary %d", got, port)
	}
}

func TestUDPBind_NoAltPortByDefault(t *testing.T) {
	b := NewUDPBind(0, nil)
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for _, s := range b.BufferStatus() {
		if strings.HasSuffix(s.Socket, "-alt") {
			t.Fatalf("default bind opened alternate socket %q", s.Socket)
		}
	}
	if len(fns) > 2 {
		t.Fatalf("default bind returned %d receive funcs, want at most 2", len(fns))
	}
}

func TestUDPBind_AltPeersBoundedAndExpire(t *testing.T) {
	b := NewUDPBind(0, nil)
	now := time.Now()
	for i := 0; i < altPeerLimit+500; i++ {
		b.noteAltPeer(netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), 4000), now)
	}
	if got := b.altPeerCount.Load(); got != altPeerLimit {
		t.Fatalf("alt peers = %d, want capped at %d", got, altPeerLimit)
	}
	late := netip.MustParseAddrPort("192.0.2.1:5000")
	b.noteAltPeer(late, now)
	if b.isAltPeer(late, now) {
		t.Fatal("source admitted beyond the cap while no entry had expired")
	}
	// Once entries expire, a sweep makes room again.
	later := now.Add(altPeerTTL + time.Second)
	b.noteAltPeer(late, later)
	if !b.isAltPeer(late, later) {
		t.Fatal("source not admitted after expired entries were swept")
	}
	if got := b.altPeerCount.Load(); got != 1 {
		t.Fatalf("alt peers after sweep = %d, want 1", got)
	}
	old := netip.MustParseAddrPort("192.0.2.2:5000")
	b.noteAltPeer(old, now)
	if b.isAltPeer(old, now.Add(altPeerTTL+time.Second)) {
		t.Fatal("expired source still routed to the alternate socket")
	}
}
