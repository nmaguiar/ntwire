package wstransport

import (
	"bytes"
	"encoding/binary"
	"errors"
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
	fail  map[string]error
}

func (f *fakeBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) { return nil, 0, nil }
func (f *fakeBind) Close() error                                    { return nil }
func (f *fakeBind) SetMark(uint32) error                            { return nil }
func (f *fakeBind) BatchSize() int                                  { return 1 }
func (f *fakeBind) ParseEndpoint(s string) (conn.Endpoint, error)   { return fakeEndpoint{id: s}, nil }
func (f *fakeBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail[ep.DstToString()]; err != nil {
		return err
	}
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
	m.RegisterPath("peer-1", "udp-relay", PathUDPRelay, ep, false, false, false)

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
	m.RegisterPath("peer-1", "wss", PathWSS, ep, false, false, false)
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
	m.RegisterPath("peer-1", "wss", PathWSS, wssEP, false, false, false)
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

// TestServerMultipathPayloadIngressMakesWSSImmediatelyReplyCapable covers
// relay startup ordering. The client can send its first authenticated
// WireGuard transport packet before the server's independent path probe has
// made a round trip. That packet itself proves the authenticated WSS carrier
// is usable, so the server must be able to route the corresponding reply.
func TestServerMultipathPayloadIngressMakesWSSImmediatelyReplyCapable(t *testing.T) {
	base := &fakeBind{}
	m := NewServerMultipathBind(base, V2Options{})
	defer m.Close()

	wssEP := fakeEndpoint{id: "wss-peer"}
	m.RegisterPath("peer-1", "wss", PathWSS, wssEP, false, false, false)
	base.reset() // discard the registration probe; no probe ACK is delivered.

	wgPacket := make([]byte, 32)
	binary.LittleEndian.PutUint32(wgPacket, 4)
	fakeFn := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		sizes[0] = copy(bufs[0], wgPacket)
		eps[0] = wssEP
		return 1, nil
	}
	bufs := [][]byte{make([]byte, len(wgPacket))}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	if n, err := m.wrap(fakeFn)(bufs, sizes, eps); err != nil || n != 1 {
		t.Fatalf("wrap returned n=%d err=%v, want one payload", n, err)
	}

	replyEP, err := m.ParseEndpoint("peer-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Send([][]byte{wgPacket}, replyEP); err != nil {
		t.Fatalf("Send reply after inbound WSS payload = %v", err)
	}
	_, dest, ok := base.lastSent()
	if !ok || dest.DstToString() != wssEP.DstToString() {
		t.Fatalf("reply destination = %v, want %v", dest, wssEP)
	}
}

func TestServerMultipathPayloadAcknowledgementIsCapabilityGated(t *testing.T) {
	base := &fakeBind{}
	m := NewServerMultipathBind(base, V2Options{})
	defer m.Close()
	ep := fakeEndpoint{id: "wss-peer"}
	m.RegisterPath("peer-1", "wss", PathWSS, ep, true, true, false)
	base.reset() // discard RegisterPath's immediate health probe

	p := m.peers["peer-1"]
	m.sendPayloadAck(p, ep)
	deadline := time.Now().Add(time.Second)
	var frame []byte
	var dest conn.Endpoint
	var ok bool
	for time.Now().Before(deadline) {
		if frame, dest, ok = base.lastSent(); ok {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !ok {
		t.Fatal("payload acknowledgement was not sent")
	}
	typ, payload, ok := DecodeControlFrame(frame)
	if !ok || typ != FramePathDataAck || !ValidPathDataAck(payload) || dest.DstToString() != ep.DstToString() {
		t.Fatalf("payload acknowledgement = type=%d payload=%x dest=%v", typ, payload, dest)
	}

	p.scheduler.RecordPayloadSent("wss", time.Now())
	m.dispatchControl(p, FramePathDataAck, make([]byte, pathProbeSize), ep)
	if p.scheduler.candidates["wss"].payloadAck.Load() == 0 {
		t.Fatal("payload acknowledgement did not record candidate progress")
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
	m.RegisterPath("peer-1", "udp-relay", PathUDPRelay, ep, false, false, false)

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

// TestServerMultipathDuplicationBudgetLimitsAndCounts is item 6's end-to-end
// check: once Select's reactive duplication triggers, Send must still cap
// how much of it actually goes out to a small configured budget, and must
// record what happened (allowed vs. suppressed) per candidate so the budget's
// effect is inspectable rather than only silently bounding traffic.
func TestServerMultipathDuplicationBudgetLimitsAndCounts(t *testing.T) {
	base := &fakeBind{}
	m := NewServerMultipathBind(base, V2Options{DuplicateRateBytesPerSec: 100})
	defer m.Close()

	wssEP := fakeEndpoint{id: "wss-ep"}
	relayEP := fakeEndpoint{id: "relay-ep"}
	m.RegisterPath("peer-1", "wss", PathWSS, wssEP, false, false, false)
	m.RegisterPath("peer-1", "relay", PathUDPRelay, relayEP, false, false, false)

	m.mu.RLock()
	p := m.peers["peer-1"]
	m.mu.RUnlock()

	// Mirrors TestSchedulerSelectsBestAndDuplicatesOnlyWhenNeeded: relay
	// starts fast and healthy, then accumulates enough loss that wss (slow
	// but lossless) becomes primary and Select asks to duplicate onto relay.
	now := time.Now()
	for i := 0; i < 4; i++ {
		p.scheduler.ProbeResult("wss", 300*time.Millisecond, true, now)
		p.scheduler.ProbeResult("relay", 20*time.Millisecond, true, now)
	}
	for i := 0; i < 16; i++ {
		p.scheduler.ProbeResult("relay", 20*time.Millisecond, true, now)
	}
	p.scheduler.ProbeResult("relay", 0, false, now)
	primary, alternate, dup := p.scheduler.Select()
	if primary != "wss" || alternate != "relay" || !dup {
		t.Fatalf("setup did not reach a duplicating state: primary=%q alternate=%q dup=%v", primary, alternate, dup)
	}

	packet := make([]byte, 40)
	binary.LittleEndian.PutUint32(packet[:4], 4)
	base.reset()

	// wireguard-go calls Send with its whole outbound batch (see
	// device.Peer.SendBuffers), not one packet at a time -- exercise that
	// shape here so the budget/counters are charged for the full 80-byte
	// batch, not just bufs[0]'s 40.
	batch := [][]byte{packet, packet}
	if err := m.Send(batch, p.endpoint); err != nil {
		t.Fatalf("first Send: %v", err)
	}
	if err := m.Send(batch, p.endpoint); err != nil {
		t.Fatalf("second Send: %v", err)
	}

	base.mu.Lock()
	relaySends := 0
	for _, d := range base.dests {
		if d.DstToString() == "relay-ep" {
			relaySends++
		}
	}
	base.mu.Unlock()
	// Budget is 100 bytes/sec and starts full; the first 80-byte batch
	// (both packets in it, so 2 sends to relay-ep) exhausts most of it, so
	// the second batch (sent immediately after, with negligible refill)
	// must be withheld entirely -- 0 further sends, not 2.
	if relaySends != 2 {
		t.Fatalf("duplicated packets sent to relay = %d, want exactly 2 (one batch allowed, the next denied)", relaySends)
	}

	var relayStatus PathStatus
	for _, s := range p.scheduler.Status() {
		if s.Name == "relay" {
			relayStatus = s
		}
	}
	if relayStatus.DuplicatedBytes != 80 {
		t.Fatalf("DuplicatedBytes = %d, want 80 (both packets in the allowed batch)", relayStatus.DuplicatedBytes)
	}
	if relayStatus.DuplicationSuppressedBytes != 80 {
		t.Fatalf("DuplicationSuppressedBytes = %d, want 80 (both packets in the denied batch)", relayStatus.DuplicationSuppressedBytes)
	}
}

func TestMultipathClientPrimarySendFailureFallsBackImmediately(t *testing.T) {
	base := &fakeBind{fail: map[string]error{"wss-ep": errors.New("websocket closed")}}
	m := NewMultipathBind(base, "relay-server", false, false, V2Options{})
	defer m.Close()

	m.RegisterPath("wss", PathWSS, fakeEndpoint{id: "wss-ep"})
	m.RegisterPath("udp-relay", PathUDPRelay, fakeEndpoint{id: "relay-ep"})
	now := time.Now()
	m.scheduler.ProbeResult("wss", 10*time.Millisecond, true, now)
	m.scheduler.ProbeResult("udp-relay", 80*time.Millisecond, true, now)
	base.reset()

	packet := make([]byte, 40)
	binary.LittleEndian.PutUint32(packet[:4], 4)
	if err := m.Send([][]byte{packet}, m.endpoint); err != nil {
		t.Fatalf("Send did not recover over alternate: %v", err)
	}
	if primary, _, _ := m.scheduler.Select(); primary != "udp-relay" {
		t.Fatalf("primary after WSS send failure = %q, want udp-relay", primary)
	}
	base.mu.Lock()
	defer base.mu.Unlock()
	if len(base.dests) != 1 || base.dests[0].DstToString() != "relay-ep" {
		t.Fatalf("successful destinations = %v, want one relay send", base.dests)
	}
}

func TestServerMultipathPrimarySendFailureFallsBackImmediately(t *testing.T) {
	base := &fakeBind{fail: map[string]error{"wss-ep": errors.New("websocket closed")}}
	m := NewServerMultipathBind(base, V2Options{})
	defer m.Close()

	m.RegisterPath("peer-1", "wss", PathWSS, fakeEndpoint{id: "wss-ep"}, false, false, false)
	m.RegisterPath("peer-1", "udp-relay", PathUDPRelay, fakeEndpoint{id: "relay-ep"}, false, false, false)
	m.mu.RLock()
	p := m.peers["peer-1"]
	m.mu.RUnlock()
	now := time.Now()
	p.scheduler.ProbeResult("wss", 10*time.Millisecond, true, now)
	p.scheduler.ProbeResult("udp-relay", 80*time.Millisecond, true, now)
	base.reset()

	packet := make([]byte, 40)
	binary.LittleEndian.PutUint32(packet[:4], 4)
	if err := m.Send([][]byte{packet}, p.endpoint); err != nil {
		t.Fatalf("Send did not recover over alternate: %v", err)
	}
	if primary, _, _ := p.scheduler.Select(); primary != "udp-relay" {
		t.Fatalf("primary after WSS send failure = %q, want udp-relay", primary)
	}
}

func makeSchedulerDuplicateToRelay(s *Scheduler) {
	now := time.Now()
	for i := 0; i < 4; i++ {
		s.ProbeResult("wss", 300*time.Millisecond, true, now)
		s.ProbeResult("udp-relay", 20*time.Millisecond, true, now)
	}
	for i := 0; i < 16; i++ {
		s.ProbeResult("udp-relay", 20*time.Millisecond, true, now)
	}
	s.ProbeResult("udp-relay", 0, false, now)
}

func TestMultipathClientAlternateSendFailureDoesNotFailPrimary(t *testing.T) {
	base := &fakeBind{fail: map[string]error{"relay-ep": errors.New("relay write failed")}}
	m := NewMultipathBind(base, "relay-server", false, false, V2Options{})
	defer m.Close()
	m.RegisterPath("wss", PathWSS, fakeEndpoint{id: "wss-ep"})
	m.RegisterPath("udp-relay", PathUDPRelay, fakeEndpoint{id: "relay-ep"})
	makeSchedulerDuplicateToRelay(m.scheduler)
	base.reset()

	packet := make([]byte, 40)
	binary.LittleEndian.PutUint32(packet[:4], 4)
	if err := m.Send([][]byte{packet}, m.endpoint); err != nil {
		t.Fatalf("successful primary send was failed by alternate: %v", err)
	}
	if primary, _, _ := m.scheduler.Select(); primary != "wss" {
		t.Fatalf("primary after alternate failure = %q, want wss", primary)
	}
	for _, status := range m.scheduler.Status() {
		if status.Name == "udp-relay" && status.DuplicatedBytes != 0 {
			t.Fatalf("failed alternate write counted as %d duplicated bytes", status.DuplicatedBytes)
		}
	}
}

func TestServerMultipathAlternateSendFailureDoesNotFailPrimary(t *testing.T) {
	base := &fakeBind{fail: map[string]error{"relay-ep": errors.New("relay write failed")}}
	m := NewServerMultipathBind(base, V2Options{})
	defer m.Close()
	m.RegisterPath("peer-1", "wss", PathWSS, fakeEndpoint{id: "wss-ep"}, false, false, false)
	m.RegisterPath("peer-1", "udp-relay", PathUDPRelay, fakeEndpoint{id: "relay-ep"}, false, false, false)
	m.mu.RLock()
	p := m.peers["peer-1"]
	m.mu.RUnlock()
	makeSchedulerDuplicateToRelay(p.scheduler)
	base.reset()

	packet := make([]byte, 40)
	binary.LittleEndian.PutUint32(packet[:4], 4)
	if err := m.Send([][]byte{packet}, p.endpoint); err != nil {
		t.Fatalf("successful primary send was failed by alternate: %v", err)
	}
	if primary, _, _ := p.scheduler.Select(); primary != "wss" {
		t.Fatalf("primary after alternate failure = %q, want wss", primary)
	}
}

func TestMultipathMirroringChargesWholeBatch(t *testing.T) {
	base := &fakeBind{}
	m := NewMultipathBind(base, "relay-server", true, false, V2Options{MirrorRateBytesPerSec: 60})
	defer m.Close()

	m.RegisterPath("wss", PathWSS, fakeEndpoint{id: "wss-ep"})
	m.RegisterPath("udp-relay", PathUDPRelay, fakeEndpoint{id: "relay-ep"})
	now := time.Now()
	m.scheduler.ProbeResult("wss", 10*time.Millisecond, true, now)
	m.scheduler.ProbeResult("udp-relay", 20*time.Millisecond, true, now)
	m.SetForced("wss")
	base.reset()

	packet := make([]byte, 40)
	binary.LittleEndian.PutUint32(packet[:4], 4)
	if err := m.Send([][]byte{packet, packet}, m.endpoint); err != nil {
		t.Fatal(err)
	}
	base.mu.Lock()
	defer base.mu.Unlock()
	if len(base.dests) != 2 {
		t.Fatalf("sent datagrams = %d, want only the two primary batch packets", len(base.dests))
	}
	for _, ep := range base.dests {
		if ep.DstToString() != "wss-ep" {
			t.Fatalf("batch was mirrored despite 80 bytes exceeding 60-byte budget: %v", base.dests)
		}
	}
}

func TestServerMultipathMirroringChargesWholeBatch(t *testing.T) {
	base := &fakeBind{}
	m := NewServerMultipathBind(base, V2Options{MirrorRateBytesPerSec: 60})
	defer m.Close()

	m.RegisterPath("peer-1", "wss", PathWSS, fakeEndpoint{id: "wss-ep"}, true, false, false)
	m.RegisterPath("peer-1", "udp-relay", PathUDPRelay, fakeEndpoint{id: "relay-ep"}, true, false, false)
	m.mu.RLock()
	p := m.peers["peer-1"]
	m.mu.RUnlock()
	now := time.Now()
	p.scheduler.ProbeResult("wss", 10*time.Millisecond, true, now)
	p.scheduler.ProbeResult("udp-relay", 20*time.Millisecond, true, now)
	p.scheduler.SetForced("wss")
	base.reset()

	packet := make([]byte, 40)
	binary.LittleEndian.PutUint32(packet[:4], 4)
	if err := m.Send([][]byte{packet, packet}, p.endpoint); err != nil {
		t.Fatal(err)
	}
	base.mu.Lock()
	defer base.mu.Unlock()
	if len(base.dests) != 2 {
		t.Fatalf("sent datagrams = %d, want only the two primary batch packets", len(base.dests))
	}
}

func TestServerMultipathRegisterPathRemovesReplacedSource(t *testing.T) {
	m := NewServerMultipathBind(&fakeBind{}, V2Options{})
	defer m.Close()

	m.RegisterPath("peer-1", "direct-udp", PathDirect, fakeEndpoint{id: "old-source"}, true, false, false)
	m.RegisterPath("peer-1", "direct-udp", PathDirect, fakeEndpoint{id: "new-source"}, true, false, false)
	m.mu.RLock()
	oldPeer, oldExists := m.bySource["old-source"]
	newPeer := m.bySource["new-source"]
	m.mu.RUnlock()
	if oldExists || oldPeer != nil {
		t.Fatal("replaced endpoint remains accepted in bySource")
	}
	if newPeer == nil || newPeer.id != "peer-1" {
		t.Fatalf("new endpoint mapped to %#v, want peer-1", newPeer)
	}
}

func TestServerMultipathRegisterPathRejectsCrossPeerSourceCollision(t *testing.T) {
	m := NewServerMultipathBind(&fakeBind{}, V2Options{})
	defer m.Close()
	ep := fakeEndpoint{id: "shared-source"}
	if !m.RegisterPath("peer-1", "direct-udp", PathDirect, ep, true, false, false) {
		t.Fatal("first source registration was rejected")
	}
	if m.RegisterPath("peer-2", "direct-udp", PathDirect, ep, true, false, false) {
		t.Fatal("second peer stole an existing source registration")
	}
	m.mu.RLock()
	owner := m.bySource["shared-source"]
	_, peer2Created := m.peers["peer-2"]
	m.mu.RUnlock()
	if owner == nil || owner.id != "peer-1" {
		t.Fatalf("source owner = %#v, want peer-1", owner)
	}
	if peer2Created {
		t.Fatal("rejected collision left an empty peer registry entry")
	}
}

// TestMultipathBindTracksRelayLegTraffic is item 1's client-side
// hop-telemetry regression: MultipathBind must count its own sent/received
// bytes on the udp-relay candidate specifically, both directions, so
// pkg/client can report protocol.ClientUDPRelayStats to the server and
// close the client<->relay-leg loss-localization loop.
func TestMultipathBindTracksRelayLegTraffic(t *testing.T) {
	base := &fakeBind{}
	m := NewMultipathBind(base, "relay-server", false, false, V2Options{})
	defer m.Close()

	relayEP := fakeEndpoint{id: "relay-ep"}
	m.RegisterPath("udp-relay", PathUDPRelay, relayEP)
	// Mark the candidate healthy directly -- fakeBind never actually answers
	// the immediate probe RegisterPath just fired.
	m.scheduler.ProbeResult("udp-relay", 10*time.Millisecond, true, time.Now())
	base.reset()

	packet := make([]byte, 40)
	binary.LittleEndian.PutUint32(packet[:4], 4)
	if err := m.Send([][]byte{packet}, m.endpoint); err != nil {
		t.Fatalf("Send: %v", err)
	}
	sentBytes, sentPackets, _, _ := m.RelayLegStats()
	if sentBytes != 40 || sentPackets != 1 {
		t.Fatalf("RelayLegStats after one send = (%d, %d), want (40, 1)", sentBytes, sentPackets)
	}

	fakeFn := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		sizes[0] = copy(bufs[0], packet)
		eps[0] = relayEP
		return 1, nil
	}
	wrapped := m.wrapReceive(fakeFn)
	bufs := [][]byte{make([]byte, 128)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	if _, err := wrapped(bufs, sizes, eps); err != nil {
		t.Fatalf("wrapReceive: %v", err)
	}
	_, _, receivedBytes, receivedPackets := m.RelayLegStats()
	if receivedBytes != 40 || receivedPackets != 1 {
		t.Fatalf("RelayLegStats after one receive = (%d, %d), want (40, 1)", receivedBytes, receivedPackets)
	}
}
