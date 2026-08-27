package wstransport

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// TestServerMultipathCountsAndReportsMirroredTraffic proves the
// client-to-server half of multipath-v2's round trip actually works, using
// real UDP sockets and real StdNetBind endpoints throughout (not the
// string-keyed fakeEndpoint other tests in this package use, and not the
// probe/ack-only exchange TestServerMultipathUDPRelayCandidateBecomesHealthyOverRealSockets
// already covers): a peer's mirrored duplicate is counted server-side via
// the real bySource/nameForEndpoint lookups, reported back as a
// FrameThroughputReport, and -- fed into a delivery-ratio computation
// exactly as MultipathBind.handlePathControl's FrameThroughputReport case
// would -- produces a real, positive DeliveryRatio. This directly settles
// two things that were only reasoned about, not tested: whether
// RegisterPath's v2 flag is actually true by the time traffic counts, and
// whether a mirrored packet's arrival endpoint actually resolves to the
// right candidate name.
func TestServerMultipathCountsAndReportsMirroredTraffic(t *testing.T) {
	// primary/candidate stand in for two of a real client's carriers (e.g.
	// wss and udp-relay), each a distinct real UDP socket.
	primary, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback UDP unavailable: %v", err)
	}
	defer primary.Close()
	candidate, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback UDP unavailable: %v", err)
	}
	defer candidate.Close()

	base := conn.NewStdNetBind()
	// ReportInterval set far out: this test calls sendReports directly for
	// determinism rather than waiting on reportLoop's ticker.
	m := NewServerMultipathBind(base, V2Options{ReportInterval: time.Hour})
	defer m.Close()
	fns, serverPort, err := m.Open(0)
	if err != nil {
		t.Skipf("loopback UDP unavailable: %v", err)
	}
	startServerMultipathReceivers(t, m, fns)
	serverAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(serverPort)}

	primaryEP, err := base.ParseEndpoint(primary.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	candidateEP, err := base.ParseEndpoint(candidate.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	m.RegisterPath("peer-1", "primary", PathWSS, primaryEP, true, false, false)
	m.RegisterPath("peer-1", "candidate", PathUDPRelay, candidateEP, true, false, false)

	ackProbe := func(sock net.PacketConn) {
		t.Helper()
		_ = sock.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 2048)
		n, from, err := sock.ReadFrom(buf)
		if err != nil {
			t.Fatalf("socket did not receive its probe: %v", err)
		}
		typ, payload, ok := DecodeControlFrame(buf[:n])
		if !ok || typ != FramePathProbe {
			t.Fatalf("expected a path probe, got typ=%d ok=%v", typ, ok)
		}
		if _, err := sock.WriteTo(EncodeControlFrame(FramePathAck, payload), from); err != nil {
			t.Fatal(err)
		}
	}
	ackProbe(primary)
	ackProbe(candidate)

	m.mu.RLock()
	p := m.peers["peer-1"]
	m.mu.RUnlock()
	if p == nil {
		t.Fatal("peer not registered")
	}
	if !p.v2.Load() {
		t.Fatal("peer.v2 is false after RegisterPath(..., true) -- server-side v2 gating never activated")
	}
	deadline := time.Now().Add(2 * time.Second)
	pathsHealthy := false
	for time.Now().Before(deadline) {
		status := p.scheduler.Status()
		if len(status) == 2 && status[0].Healthy && status[1].Healthy {
			pathsHealthy = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !pathsHealthy {
		t.Fatalf("primary and candidate did not become healthy after probe acknowledgements: %+v", p.scheduler.Status())
	}

	// Simulate the client mirroring a real WireGuard transport packet: the
	// exact same bytes sent from both sockets, exactly as MultipathBind.Send
	// does for its primary send plus mirror send. Deliberately send the faster
	// candidate first: v2 must retain that first-arrival path and credit it
	// when the incumbent's later copy triggers deduplication.
	wgPacket := make([]byte, 128)
	binary.LittleEndian.PutUint32(wgPacket, 4) // type 4: WireGuard transport
	if _, err := candidate.WriteTo(wgPacket, serverAddr); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := primary.WriteTo(wgPacket, serverAddr); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)

	m.sendReports(p, 1000)

	_ = candidate.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := candidate.ReadFrom(buf)
	if err != nil {
		t.Fatalf("candidate socket did not receive a throughput report: %v", err)
	}
	typ, payload, ok := DecodeControlFrame(buf[:n])
	if !ok || typ != FrameThroughputReport {
		t.Fatalf("expected a throughput report, got typ=%d ok=%v", typ, ok)
	}
	report, ok := DecodeThroughputReport(payload)
	if !ok {
		t.Fatal("could not decode throughput report payload")
	}
	if report.BytesReceived != uint32(len(wgPacket)) {
		t.Fatalf("report.BytesReceived = %d, want %d", report.BytesReceived, len(wgPacket))
	}

	// Finally, feed it into a delivery-ratio computation exactly as
	// MultipathBind.handlePathControl's FrameThroughputReport case would,
	// given a matching attempted-bytes sample for the same window. The
	// sender and receiver windows are independently timed (see
	// mirrorAccounting's doc comment) -- this last step exercises the
	// arithmetic, not the window-alignment timing itself.
	s := NewScheduler()
	s.Register("candidate", PathUDPRelay)
	s.ReportDeliveryRatio("candidate", float64(report.BytesReceived)/float64(len(wgPacket)))
	status := s.Status()
	if len(status) != 1 || status[0].DeliveryRatio != 1.0 {
		t.Fatalf("delivery ratio = %+v, want 1.0 (all mirrored bytes reported back)", status)
	}
}

func TestMultipathClientCreditsFasterFirstArrivingMirror(t *testing.T) {
	m := NewMultipathBind(&fakeBind{}, "server", true, false, V2Options{ReportInterval: time.Hour})
	defer m.Close()
	m.RegisterPath("wss", PathWSS, fakeEndpoint{id: "wss-ep"})
	m.RegisterPath("direct-udp", PathDirect, fakeEndpoint{id: "direct-ep"})

	packet := make([]byte, 128)
	binary.LittleEndian.PutUint32(packet, 4)
	called := false
	wrapped := m.wrapReceive(func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if called {
			return 0, conn.ErrBindAlreadyOpen
		}
		called = true
		copy(bufs[0], packet)
		copy(bufs[1], packet)
		sizes[0], sizes[1] = len(packet), len(packet)
		// The mirrored direct candidate wins the race; WSS is the later
		// duplicate. Both paths must still receive one accounting credit.
		eps[0] = fakeEndpoint{id: "direct-ep"}
		eps[1] = fakeEndpoint{id: "wss-ep"}
		return 2, nil
	})
	bufs := [][]byte{make([]byte, 256), make([]byte, 256)}
	sizes := make([]int, 2)
	eps := make([]conn.Endpoint, 2)
	if n, err := wrapped(bufs, sizes, eps); err != nil || n != 1 {
		t.Fatalf("wrapped receive = (%d, %v), want one deduplicated packet", n, err)
	}

	m.recvMu.Lock()
	direct := m.recvCounters["direct-udp"]
	wss := m.recvCounters["wss"]
	m.recvMu.Unlock()
	if direct == nil || direct.bytes != uint32(len(packet)) {
		t.Fatalf("direct mirror counter = %#v, want %d bytes", direct, len(packet))
	}
	if wss == nil || wss.bytes != uint32(len(packet)) {
		t.Fatalf("WSS counter = %#v, want %d bytes", wss, len(packet))
	}
}

// TestMirrorLimiterBudget checks mirrorLimiter's token-bucket contract: a
// full bucket allows spending up to its capacity in one shot, and is
// exhausted immediately afterward -- the mechanism B3 relies on to bound
// mirroring's cost to MirrorRateBytesPerSec regardless of how much primary
// traffic is flowing.
func TestMirrorLimiterBudget(t *testing.T) {
	l := newMirrorLimiter(100) // 100 bytes/sec, starts full
	if !l.Allow(100) {
		t.Fatal("full bucket should allow spending its full capacity at once")
	}
	if l.Allow(1) {
		t.Fatal("bucket should be exhausted immediately after spending its full capacity")
	}
}

// TestMirrorAccountingRollWindow checks attemptedLastWindow's documented
// semantics: nothing recorded anywhere is not-ok, an in-progress (unrolled)
// window is already visible (this is the fix for the two independent
// per-side report tickers being phase-misaligned -- see its doc comment),
// a roll folds what was current into last without losing it, and an empty
// window (nothing in either last or current) reports not-ok rather than a
// stale value.
func TestMirrorAccountingRollWindow(t *testing.T) {
	a := newMirrorAccounting()
	if _, ok := a.attemptedLastWindow("x"); ok {
		t.Fatal("nothing recorded yet -- must report not-ok")
	}
	a.recordAttempt("x", 100)
	if n, ok := a.attemptedLastWindow("x"); !ok || n != 100 {
		t.Fatalf("attemptedLastWindow with only an in-progress window = (%d, %v), want (100, true)", n, ok)
	}
	a.rollWindow()
	if n, ok := a.attemptedLastWindow("x"); !ok || n != 100 {
		t.Fatalf("attemptedLastWindow after roll = (%d, %v), want (100, true)", n, ok)
	}
	a.recordAttempt("x", 30) // some further activity in the new current window
	if n, ok := a.attemptedLastWindow("x"); !ok || n != 130 {
		t.Fatalf("attemptedLastWindow with last+current = (%d, %v), want (130, true)", n, ok)
	}
	a.rollWindow() // folds the 30 into last; current starts fresh
	if n, ok := a.attemptedLastWindow("x"); !ok || n != 30 {
		t.Fatalf("attemptedLastWindow after second roll = (%d, %v), want (30, true)", n, ok)
	}
	a.rollWindow() // nothing recorded since the second rollWindow: both last and current are now empty
	if _, ok := a.attemptedLastWindow("x"); ok {
		t.Fatal("an empty window (both last and current) must report not-ok, not a stale value")
	}
}
