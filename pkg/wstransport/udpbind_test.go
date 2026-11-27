package wstransport

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/ipv6"
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
	want := bytes.Repeat([]byte{0x7f}, 1420)
	if err := sender.Send([][]byte{want}, ep); err != nil {
		t.Fatal(err)
	}
	bufs := make([][]byte, receiver.BatchSize())
	for i := range bufs {
		bufs[i] = make([]byte, 1500)
	}
	sizes := make([]int, len(bufs))
	eps := make([]conn.Endpoint, len(bufs))
	n, err := receiveFns[0](bufs, sizes, eps)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || !bytes.Equal(bufs[0][:sizes[0]], want) || !eps[0].DstIP().Is4() {
		t.Fatalf("receive = n=%d size=%d endpoint=%v; want one intact %d-byte IPv4 packet", n, sizes[0], eps[0], len(want))
	}
}

func TestUDPBindReceive_PreservesPeerAndDatagram(t *testing.T) {
	for _, tc := range []struct{ network, host string }{
		{"udp4", "127.0.0.1"},
		{"udp6", "::1"},
	} {
		t.Run(tc.network, func(t *testing.T) {
			bind := NewUDPBind(0, nil)
			defer bind.Close()
			receive, port, err := bind.Open(0)
			if err != nil {
				t.Fatal(err)
			}
			index := 0
			if tc.network == "udp6" && bind.ipv4 != nil {
				index++
			}
			if index >= len(receive) || (tc.network == "udp4" && bind.ipv4 == nil) {
				t.Skip("address family is unavailable")
			}
			local := &net.UDPAddr{IP: net.ParseIP(tc.host)}
			sender, err := net.ListenUDP(tc.network, local)
			if tc.network == "udp6" && (errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL)) {
				t.Skipf("IPv6 loopback is unavailable: %v", err)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer sender.Close()
			watchdog := time.AfterFunc(5*time.Second, func() { _ = bind.Close() })
			defer watchdog.Stop()
			wantPeer := sender.LocalAddr().(*net.UDPAddr).AddrPort()
			dst := netip.AddrPortFrom(netip.MustParseAddr(tc.host), port)
			bufs := [][]byte{make([]byte, 128)}
			sizes := make([]int, 1)
			eps := make([]conn.Endpoint, 1)
			for _, payload := range [][]byte{[]byte("first"), bytes.Repeat([]byte("x"), 128)} {
				if _, err := sender.WriteToUDPAddrPort(payload, dst); err != nil {
					t.Fatal(err)
				}
				n, err := receive[index](bufs, sizes, eps)
				if err != nil || n != 1 {
					t.Fatalf("received %d datagrams: %v", n, err)
				}
				peer, ok := eps[0].(udpEndpoint)
				if !ok || peer.addr != wantPeer || !bytes.Equal(bufs[0][:sizes[0]], payload) {
					t.Fatalf("peer %v, datagram %q", eps[0], bufs[0][:sizes[0]])
				}
			}
		})
	}
}

type udpReadBatchFunc func([]ipv6.Message, int) (int, error)

func (f udpReadBatchFunc) ReadBatch(msgs []ipv6.Message, flags int) (int, error) {
	return f(msgs, flags)
}

func TestUDPBindReceive_WindowFollowsReadDensity(t *testing.T) {
	var wantWindow, packets int
	var backing []ipv6.Message
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51820}
	wantPeer := peer.AddrPort().String()
	receive := makeUDPBatchReceive(udpReadBatchFunc(func(msgs []ipv6.Message, _ int) (int, error) {
		t.Helper()
		if len(msgs) != wantWindow {
			t.Fatalf("prepared %d receive slots, want %d", len(msgs), wantWindow)
		}
		backing = msgs[:cap(msgs)]
		for i := range packets {
			msgs[i].Addr = peer
			msgs[i].N = copy(msgs[i].Buffers[0], []byte{byte(i)})
		}
		return packets, nil
	}))
	bufs := make([][]byte, conn.IdealBatchSize)
	sizes := make([]int, len(bufs))
	endpoints := make([]conn.Endpoint, len(bufs))
	for i := range bufs {
		bufs[i] = make([]byte, 8)
	}
	read := func(slots, window, count int) {
		t.Helper()
		wantWindow, packets = window, count
		n, err := receive(bufs[:slots], sizes, endpoints)
		if err != nil || n != count {
			t.Fatalf("receive returned %d, %v, want %d packets", n, err, count)
		}
		for i := range n {
			if sizes[i] != 1 || bufs[i][0] != byte(i) || endpoints[i].DstToString() != wantPeer {
				t.Fatalf("unexpected datagram %d: %v, size %d, endpoint %v", i, bufs[i], sizes[i], endpoints[i])
			}
		}
	}
	read(len(bufs), 8, 1)
	for window := 8; window <= conn.IdealBatchSize; window *= 2 {
		read(len(bufs), window, window)
	}
	read(len(bufs), conn.IdealBatchSize, conn.IdealBatchSize)
	for range 32 {
		read(1, 1, 1)
	}
	for window := conn.IdealBatchSize; window > 8; window /= 2 {
		for range 32 {
			read(len(bufs), window, 1)
		}
		for i := window / 2; i < window; i++ {
			if backing[i].Buffers[0] != nil || backing[i].Addr != nil {
				t.Fatalf("retired receive slot %d retained a previous packet or endpoint", i)
			}
		}
	}
	read(len(bufs), 8, 1)
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
		reply := bytes.Repeat([]byte{0x29}, 1420)
		if err := b.Send([][]byte{reply}, ep); err != nil {
			t.Fatal(err)
		}
		_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1500)
		n, src, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("no reply: %v", err)
		}
		if !bytes.Equal(buf[:n], reply) {
			t.Fatalf("reply corrupted: received %d bytes, want %d", n, len(reply))
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

// BenchmarkUDPBindSendSingle isolates per-datagram work in the bind, including
// its endpoint handling. The disposable local receiver drains the socket.
func BenchmarkUDPBindSendSingle(b *testing.B) {
	benchmarkUDPBindSend(b, 1, 128)
}

func BenchmarkUDPBindSendBatch(b *testing.B) {
	for _, count := range []int{1, 8, 64} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			if count > (&UDPBind{}).BatchSize() {
				b.Skip("UDP batching is unavailable")
			}
			b.Run("standard", func(b *testing.B) { benchmarkUDPBindSend(b, count, 1420) })
		})
	}
}

// BenchmarkUDPBindReceiveSingle includes one local send and the bind's receive
// path. The same payload and receive buffers are reused on every iteration.
func BenchmarkUDPBindReceiveSingle(b *testing.B) {
	benchmarkUDPBindReceive(b, 1, 1)
}

// BenchmarkUDPBindReceiveWindow exercises the full receive buffer array used
// by WireGuard with both sparse arrivals and prequeued bursts.
func BenchmarkUDPBindReceiveWindow(b *testing.B) {
	window := (&UDPBind{}).BatchSize()
	if window == 1 {
		b.Skip("UDP batching is unavailable")
	}
	for _, arrivals := range []int{1, 8, 64} {
		b.Run(strconv.Itoa(arrivals), func(b *testing.B) {
			benchmarkUDPBindReceive(b, window, arrivals)
		})
	}
}

func benchmarkUDPBindReceive(b *testing.B, window, arrivals int) {
	b.Helper()
	receiver := NewUDPBind(0, nil)
	b.Cleanup(func() { _ = receiver.Close() })
	receive, port, err := receiver.Open(0)
	if err != nil {
		b.Fatal(err)
	}
	if receiver.ipv4 == nil {
		b.Skip("IPv4 is unavailable")
	}
	watchdog := time.AfterFunc(45*time.Second, func() { _ = receiver.Close() })
	b.Cleanup(func() { watchdog.Stop() })
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = sender.Close() })
	dst := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
	const size = 128
	payload := make([]byte, size)
	bufs := make([][]byte, window)
	for i := range bufs {
		bufs[i] = make([]byte, size)
	}
	sizes := make([]int, window)
	eps := make([]conn.Endpoint, window)
	b.SetBytes(int64(size * arrivals))
	b.ReportAllocs()
	for b.Loop() {
		for range arrivals {
			if _, err := sender.WriteToUDPAddrPort(payload, dst); err != nil {
				b.Fatal(err)
			}
		}
		for remaining := arrivals; remaining > 0; {
			n, err := receive[0](bufs, sizes, eps)
			if err != nil || n <= 0 || n > remaining {
				b.Fatalf("receive = %d packets, want up to %d, error %v", n, remaining, err)
			}
			for i := range n {
				if sizes[i] != size {
					b.Fatalf("receive size = %d, want %d", sizes[i], size)
				}
			}
			remaining -= n
		}
	}
}

func benchmarkUDPBindSend(b *testing.B, count, packetSize int) {
	b.Helper()
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			if _, err := receiver.Read(buf); err != nil {
				return
			}
		}
	}()
	b.Cleanup(func() { _ = receiver.Close(); <-done })

	sender := NewUDPBind(0, nil)
	b.Cleanup(func() { _ = sender.Close() })
	if _, _, err := sender.Open(0); err != nil {
		b.Fatal(err)
	}
	endpoint, err := sender.ParseEndpoint(receiver.LocalAddr().String())
	if err != nil {
		b.Fatal(err)
	}
	batch := make([][]byte, count)
	for i := range batch {
		batch[i] = make([]byte, packetSize)
	}
	b.SetBytes(int64(count * packetSize))
	b.ReportAllocs()
	for b.Loop() {
		if err := sender.Send(batch, endpoint); err != nil {
			b.Fatal(err)
		}
	}
}

type wrappedUDPEndpoint struct {
	conn.Endpoint
}

func TestUDPBindSend_ConcurrentBatchesKeepDestinationAndData(t *testing.T) {
	sender := NewUDPBind(0, nil)
	if sender.BatchSize() == 1 {
		t.Skip("UDP batching is unavailable")
	}
	t.Cleanup(func() { _ = sender.Close() })
	_, port, err := sender.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	for id := 0; id < 12; id++ {
		t.Run(strconv.Itoa(id), func(t *testing.T) {
			t.Parallel()
			receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer receiver.Close()
			endpoint, err := sender.ParseEndpoint(receiver.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			first := bytes.Repeat([]byte{byte(id)}, 512)
			second := bytes.Repeat([]byte{byte(id + 12)}, 1024)
			if err := sender.Send([][]byte{first, second}, endpoint); err != nil {
				t.Fatal(err)
			}
			if err := receiver.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 1024)
			for _, want := range [][]byte{first, second} {
				n, from, err := receiver.ReadFromUDPAddrPort(buf)
				if err != nil {
					t.Fatal(err)
				}
				if from.Port() != port || !bytes.Equal(buf[:n], want) {
					t.Fatalf("datagram mismatch: %d bytes from %s, want %d bytes from port %d", n, from, len(want), port)
				}
			}
		})
	}
}

func TestUDPBindSend_PublicEndpoints(t *testing.T) {
	for _, addr := range []string{"127.0.0.1", "::1"} {
		t.Run(addr, func(t *testing.T) {
			ip := netip.MustParseAddr(addr)
			network := "udp4"
			if ip.Is6() {
				network = "udp6"
			}
			receiver, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, 0)))
			if err != nil && ip.Is6() {
				t.Skipf("IPv6 loopback unavailable: %v", err)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer receiver.Close()
			sender := NewUDPBind(0, nil)
			defer sender.Close()
			_, sourcePort, err := sender.Open(0)
			if err != nil {
				t.Fatal(err)
			}
			ep, err := sender.ParseEndpoint(receiver.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			for _, batch := range [][][]byte{{[]byte("single")}, {bytes.Repeat([]byte{1}, 1420)}, {[]byte("batch one"), []byte("batch two")}} {
				if len(batch) > sender.BatchSize() {
					continue
				}
				for _, endpoint := range []conn.Endpoint{ep, wrappedUDPEndpoint{ep}} {
					if err := sender.Send(batch, endpoint); err != nil {
						t.Fatal(err)
					}
					if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
						t.Fatal(err)
					}
					for _, want := range batch {
						buf := make([]byte, 1500)
						n, from, err := receiver.ReadFromUDPAddrPort(buf)
						if err != nil {
							t.Fatal(err)
						}
						if !bytes.Equal(buf[:n], want) || from.Port() != sourcePort {
							t.Fatalf("received %q from %v, want %q from port %d", buf[:n], from, want, sourcePort)
						}
					}
				}
			}
		})
	}
}
