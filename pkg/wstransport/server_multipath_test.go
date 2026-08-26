package wstransport

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

type fakeEndpoint struct{ id string }

func (e fakeEndpoint) ClearSrc()           {}
func (e fakeEndpoint) SrcToString() string { return e.id }
func (e fakeEndpoint) DstToString() string { return e.id }
func (e fakeEndpoint) DstToBytes() []byte  { return []byte(e.id) }
func (e fakeEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (e fakeEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

// fakeBind is a minimal, in-memory conn.Bind that just records what Send is
// called with, so ServerMultipathBind's probe orchestration can be tested
// deterministically without a real socket on either side.
type fakeBind struct {
	mu    sync.Mutex
	sent  [][]byte
	dests []conn.Endpoint
}

func (f *fakeBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) { return nil, 0, nil }
func (f *fakeBind) Close() error                                    { return nil }
func (f *fakeBind) SetMark(uint32) error                            { return nil }
func (f *fakeBind) BatchSize() int                                  { return 1 }
func (f *fakeBind) ParseEndpoint(s string) (conn.Endpoint, error)   { return fakeEndpoint{id: s}, nil }
func (f *fakeBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, b := range bufs {
		f.sent = append(f.sent, append([]byte(nil), b...))
		f.dests = append(f.dests, ep)
	}
	return nil
}
func (f *fakeBind) lastSent() ([]byte, conn.Endpoint, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sent) == 0 {
		return nil, nil, false
	}
	return f.sent[len(f.sent)-1], f.dests[len(f.dests)-1], true
}
func (f *fakeBind) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent, f.dests = nil, nil
}

// startServerMultipathReceivers drains the wrapped bind with buffers sized
// according to the underlying conn.Bind contract. StdNetBind receives one
// datagram at a time on macOS, but uses batched UDP reads on Linux.
func startServerMultipathReceivers(t *testing.T, bind conn.Bind, fns []conn.ReceiveFunc) {
	t.Helper()
	batchSize := bind.BatchSize()
	for _, fn := range fns {
		go func(fn conn.ReceiveFunc) {
			bufs := make([][]byte, batchSize)
			for i := range bufs {
				bufs[i] = make([]byte, 2048)
			}
			sizes := make([]int, batchSize)
			eps := make([]conn.Endpoint, batchSize)
			for {
				if _, err := fn(bufs, sizes, eps); err != nil {
					return
				}
			}
		}(fn)
	}
}

// TestServerMultipathRegisterPathProbesImmediatelyAndAckMarksHealthy is the
// server-side counterpart to bind_test.go's
// TestMultipathHybridClientRegistersWSSAfterOpen: RegisterPath must fire a
// real probe right away (not wait for the next probeLoop tick), and a
// matching ack must be what actually marks the candidate healthy -- there is
// no synthetic seeding left anywhere in this path (see A5).
func TestServerMultipathRegisterPathProbesImmediatelyAndAckMarksHealthy(t *testing.T) {
	base := &fakeBind{}
	m := NewServerMultipathBind(base, V2Options{})
	defer m.Close()

	ep := fakeEndpoint{id: "client-udp-relay"}
	m.RegisterPath("peer-1", "udp-relay", PathUDPRelay, ep, false, false)

	deadline := time.Now().Add(time.Second)
	var frame []byte
	var dest conn.Endpoint
	for time.Now().Before(deadline) {
		if b, d, ok := base.lastSent(); ok {
			frame, dest = b, d
			break
		}
		time.Sleep(time.Millisecond)
	}
	if frame == nil {
		t.Fatal("RegisterPath did not send an immediate probe")
	}
	typ, payload, ok := DecodeControlFrame(frame)
	if !ok || typ != FramePathProbe || dest.DstToString() != ep.DstToString() {
		t.Fatalf("unexpected probe frame: typ=%d ok=%v dest=%v", typ, ok, dest)
	}

	m.mu.RLock()
	p := m.peers["peer-1"]
	m.mu.RUnlock()
	if p == nil {
		t.Fatal("peer not registered")
	}
	if primary, _, _ := p.scheduler.Select(); primary != "" {
		t.Fatalf("primary before any ack = %q, want none (candidate should start unhealthy)", primary)
	}

	// Simulate the peer echoing the ack back over the UDP carrier.
	m.HandlePathControl(FramePathAck, payload, ep)

	if primary, _, _ := p.scheduler.Select(); primary != "udp-relay" {
		t.Fatalf("primary after ack = %q, want udp-relay", primary)
	}
}

func TestServerMultipathForcedTransportAppliesToExistingAndFuturePeers(t *testing.T) {
	m := NewServerMultipathBind(conn.NewStdNetBind(), V2Options{})
	defer m.Close()
	m.SetForced("wss")
	ep := fakeEndpoint{id: "peer-wss"}
	m.RegisterPath("peer-1", "wss", PathWSS, ep, false, false)
	m.mu.RLock()
	p := m.peers["peer-1"]
	m.mu.RUnlock()
	if p == nil || p.scheduler.Forced() != "wss" {
		t.Fatalf("future peer force = %q, want wss", p.scheduler.Forced())
	}
	m.SetForced("direct-udp")
	if got := p.scheduler.Forced(); got != "direct-udp" {
		t.Fatalf("existing peer force = %q, want direct-udp", got)
	}
}

// TestServerMultipathWrapInterceptsWSSControlFrames confirms wrap (the WSS
// receive path, which has no FilterBind-style interception of its own)
// consumes a probe frame -- answering it and never forwarding it to
// WireGuard -- while passing an ordinary WireGuard packet through unchanged.
func TestServerMultipathWrapInterceptsWSSControlFrames(t *testing.T) {
	base := &fakeBind{}
	m := NewServerMultipathBind(base, V2Options{})
	defer m.Close()

	wssEP := fakeEndpoint{id: "wss-peer"}
	m.RegisterPath("peer-1", "wss", PathWSS, wssEP, false, false)
	base.reset() // discard the immediate probe RegisterPath just sent

	probe := EncodeControlFrame(FramePathProbe, bytes.Repeat([]byte{0x09}, pathProbeSize))
	wgPacket := make([]byte, 32)
	binary.LittleEndian.PutUint32(wgPacket, 4)

	fakeFn := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		sizes[0] = copy(bufs[0], probe)
		eps[0] = wssEP
		sizes[1] = copy(bufs[1], wgPacket)
		eps[1] = wssEP
		return 2, nil
	}
	wrapped := m.wrap(fakeFn)
	bufs := [][]byte{make([]byte, 128), make([]byte, 128)}
	sizes := make([]int, 2)
	eps := make([]conn.Endpoint, 2)
	n, err := wrapped(bufs, sizes, eps)
	if err != nil || n != 1 {
		t.Fatalf("wrap returned n=%d err=%v, want 1 surviving packet (control frame consumed)", n, err)
	}
	if sizes[0] != len(wgPacket) {
		t.Fatalf("surviving packet size = %d, want %d", sizes[0], len(wgPacket))
	}

	frame, dest, ok := base.lastSent()
	if !ok {
		t.Fatal("wrap did not reply to the intercepted probe")
	}
	typ, _, decOK := DecodeControlFrame(frame)
	if !decOK || typ != FramePathAck || dest.DstToString() != wssEP.DstToString() {
		t.Fatalf("unexpected reply to probe: typ=%d ok=%v dest=%v", typ, decOK, dest)
	}
}

// TestServerMultipathUDPRelayCandidateBecomesHealthyOverRealSockets uses a
// real conn.NewStdNetBind() and a real UDP socket standing in for the
// relay's per-session pooled port, mirroring udprelay.go's sessionFor
// exactly: RegisterPath is given ep = base.ParseEndpoint(serverAddr), where
// serverAddr is the same address the relay's pooled-port socket is bound
// to -- so this settles, with real StdNetBind endpoint equality semantics
// rather than the string-keyed fakeEndpoint the other tests in this file
// use, whether ServerMultipathBind.bySource's DstToString() lookup actually
// matches an inbound relayed packet's source address to the candidate
// RegisterPath registered.
func TestServerMultipathUDPRelayCandidateBecomesHealthyOverRealSockets(t *testing.T) {
	pooled, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback UDP unavailable: %v", err)
	}
	defer pooled.Close()

	base := conn.NewStdNetBind()
	m := NewServerMultipathBind(base, V2Options{})
	defer m.Close()
	fns, _, err := m.Open(0)
	if err != nil {
		t.Skipf("loopback UDP unavailable: %v", err)
	}
	startServerMultipathReceivers(t, m, fns)

	serverAddr := pooled.LocalAddr().String() // exactly udprelay.go's serverAddr
	ep, err := base.ParseEndpoint(serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	m.RegisterPath("peer-1", "udp-relay", PathUDPRelay, ep, false, false)

	_ = pooled.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, from, err := pooled.ReadFrom(buf)
	if err != nil {
		t.Fatalf("pooled socket did not receive the outgoing probe: %v", err)
	}
	typ, payload, ok := DecodeControlFrame(buf[:n])
	if !ok || typ != FramePathProbe {
		t.Fatalf("expected a path probe on the pooled socket, got typ=%d ok=%v", typ, ok)
	}
	// Echo the ack back from the pooled socket, exactly as the relay's
	// forwardFromServer/forwardFromClient opaquely relays a real
	// FramePathAck between the two bound legs.
	if _, err := pooled.WriteTo(EncodeControlFrame(FramePathAck, payload), from); err != nil {
		t.Fatal(err)
	}

	m.mu.RLock()
	p := m.peers["peer-1"]
	m.mu.RUnlock()
	if p == nil {
		t.Fatal("peer not registered")
	}
	deadline := time.Now().Add(2 * time.Second)
	var primary string
	for time.Now().Before(deadline) {
		if primary, _, _ = p.scheduler.Select(); primary == "udp-relay" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if primary != "udp-relay" {
		t.Fatalf("primary after real-socket ack round trip = %q, want udp-relay -- bySource lookup did not match a real StdNetBind endpoint", primary)
	}
}
