package wstransport

import (
	"strconv"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

func openLoopbackFilterBind(t *testing.T) (*FilterBind, []conn.ReceiveFunc, uint16) {
	t.Helper()
	b := NewFilterBind(conn.NewStdNetBind())
	fns, port, err := b.Open(0)
	if err != nil {
		t.Skipf("loopback UDP unavailable: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b, fns, port
}

// TestFilterBindPassesWireGuardTrafficThrough asserts that an ordinary
// WireGuard-shaped datagram (first byte in {1,2,3,4}, never FilterBind's
// magic 0x00) reaches the wrapped receive func unchanged, so wrapping
// StdNetBind does not disturb the normal WireGuard fast path.
func TestFilterBindPassesWireGuardTrafficThrough(t *testing.T) {
	server, serverFns, serverPort := openLoopbackFilterBind(t)
	client, _, _ := openLoopbackFilterBind(t)

	ep, err := client.ParseEndpoint("127.0.0.1:" + strconv.Itoa(int(serverPort)))
	if err != nil {
		t.Fatal(err)
	}
	wgLike := make([]byte, 32)
	wgLike[0] = 4 // MessageTransportType
	if err := client.Send([][]byte{wgLike}, ep); err != nil {
		t.Fatal(err)
	}

	bufs, sizes, eps := [][]byte{make([]byte, 128)}, make([]int, 1), make([]conn.Endpoint, 1)
	n, err := waitReceive(t, serverFns[0], bufs, sizes, eps)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || sizes[0] != len(wgLike) || bufs[0][0] != 4 {
		t.Fatalf("unexpected receive: n=%d size=%d byte0=%d", n, sizes[0], bufs[0][0])
	}

	select {
	case cp := <-server.Control():
		t.Fatalf("WireGuard-shaped packet was misrouted to Control: %+v", cp)
	default:
	}
}

// TestFilterBindInterceptsControlFrames asserts that a magic-prefixed
// control frame never reaches the wrapped receive func -- it would be
// silently dropped by wireguard-go's own demux instead -- and is delivered
// on Control with its payload and source address intact.
func TestFilterBindInterceptsControlFrames(t *testing.T) {
	server, serverFns, serverPort := openLoopbackFilterBind(t)
	client, _, _ := openLoopbackFilterBind(t)

	// The control frame is only pulled out of the socket, and thus only
	// reaches Control, once something pumps the wrapped receive func --
	// exactly as wireguard-go's own receive loop would in production. This
	// goroutine's call blocks past the control frame (since wrapReceive
	// filters it out and keeps waiting for a real WireGuard packet, which
	// this test never sends), so its result is only used to detect the
	// bug this test guards against: a control frame slipping through.
	done := make(chan struct{})
	go func() {
		bufs, sizes, eps := [][]byte{make([]byte, 128)}, make([]int, 1), make([]conn.Endpoint, 1)
		_, _ = serverFns[0](bufs, sizes, eps)
		close(done)
	}()

	if err := client.SendControl(FrameReflectRequest, []byte("hello"), "127.0.0.1:"+strconv.Itoa(int(serverPort))); err != nil {
		t.Fatal(err)
	}

	select {
	case cp := <-server.Control():
		if cp.Type != FrameReflectRequest || string(cp.Payload) != "hello" {
			t.Fatalf("unexpected control packet: %+v", cp)
		}
		if !cp.From.IsValid() || cp.From.Addr().String() != "127.0.0.1" {
			t.Fatalf("unexpected control source: %v", cp.From)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for control frame")
	}

	select {
	case <-done:
		t.Fatal("receive func unexpectedly returned for a control-only datagram")
	case <-time.After(200 * time.Millisecond):
	}
}

func waitReceive(t *testing.T, fn conn.ReceiveFunc, bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	t.Helper()
	type result struct {
		n   int
		err error
	}
	ch := make(chan result, 1)
	go func() {
		n, err := fn(bufs, sizes, eps)
		ch <- result{n, err}
	}()
	select {
	case r := <-ch:
		return r.n, r.err
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for receive")
		return 0, nil
	}
}
