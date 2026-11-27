package wstransport

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

type adaptiveTestBind struct {
	fakeBind
	batch             int
	openPort, mark    uint32
	closeCount        int
	openErr, sendErr  error
	sendCount, failAt int
	fns               []conn.ReceiveFunc
}

func (f *adaptiveTestBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	f.openPort = uint32(port)
	return f.fns, port, f.openErr
}

func (f *adaptiveTestBind) Close() error { f.closeCount++; return nil }
func (f *adaptiveTestBind) SetMark(mark uint32) error {
	f.mark = mark
	return nil
}
func (f *adaptiveTestBind) BatchSize() int { return f.batch }
func (f *adaptiveTestBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	f.sendCount++
	if len(bufs) > f.batch {
		return errors.New("carrier send exceeded its batch size")
	}
	if f.sendCount == f.failAt {
		return f.sendErr
	}
	return f.fakeBind.Send(bufs, ep)
}

func testAdaptiveBind(t *testing.T, carriers ...Carrier) *AdaptiveBind {
	t.Helper()
	b, err := NewAdaptiveBind(2, carriers...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func testPath(id, carrier, addr string, expires time.Time) QualifiedPath {
	return QualifiedPath{ID: id, Carrier: carrier, Endpoint: udpEndpoint{addr: netip.MustParseAddrPort(addr)},
		SendMax: 1452, ReceiveMax: 1452, ValidUntil: expires}
}

func registerTestLane(t *testing.T, b *AdaptiveBind, id string) *LaneEndpoint {
	t.Helper()
	lane, err := b.RegisterLane(id, 1452)
	if err != nil {
		t.Fatal(err)
	}
	return lane
}

func TestAdaptiveBind_CloseReopenAndRejectStaleLane(t *testing.T) {
	transport := &adaptiveTestBind{batch: 1}
	b := testAdaptiveBind(t, Carrier{Name: "udp", Bind: transport, DatagramMax: 1500})
	lane := registerTestLane(t, b, "anchor")
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Open(42); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Open(42); !errors.Is(err, conn.ErrBindAlreadyOpen) {
		t.Fatalf("repeat open: %v", err)
	}
	path := testPath("direct", "udp", "192.0.2.1:8443", time.Now().Add(time.Minute))
	if err := b.InstallQualifiedPath(lane, 0, path); err != nil {
		t.Fatal(err)
	}
	if _, err := b.CommitPath(lane, path.ID, 0); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Open(43); err != nil {
		t.Fatal(err)
	}
	if ep, err := b.ParseEndpoint(lane.DstToString()); err != nil || ep != lane {
		t.Fatalf("reopened endpoint = %v / %v", ep, err)
	}
	if err := b.InstallQualifiedPath(lane, 1, path); !errors.Is(err, ErrStalePathEpoch) {
		t.Fatalf("pre-reopen path epoch accepted: %v", err)
	}
	if err := b.Send([][]byte{{1}}, lane); !errors.Is(err, ErrPathUnqualified) {
		t.Fatalf("unqualified reopened path sent data: %v", err)
	}
	b.RemoveLane(lane)
	newLane := registerTestLane(t, b, "anchor")
	if err := b.InstallQualifiedPath(lane, 0, path); !errors.Is(err, ErrStalePathEpoch) {
		t.Fatalf("retired lane installed path: %v", err)
	}
	b.RemoveLane(lane)
	if _, _, ok := b.LaneState(newLane); !ok {
		t.Fatal("stale handle removed replacement lane")
	}
}

func TestAdaptiveBind_MarksBatchAndPartialFailure(t *testing.T) {
	first := &adaptiveTestBind{batch: 4}
	second := &adaptiveTestBind{batch: 1, failAt: 2, sendErr: io.ErrShortWrite}
	b := testAdaptiveBind(t, Carrier{Name: "udp", Bind: first, DatagramMax: 1500},
		Carrier{Name: "relay", Bind: second, ListenPort: 443, DatagramMax: 1500})
	lane := registerTestLane(t, b, "anchor")
	if _, port, err := b.Open(51820); err != nil || port != 51820 {
		t.Fatalf("open: %d / %v", port, err)
	}
	if err := b.SetMark(5); err != nil || first.mark != 5 || second.mark != 5 || second.openPort != 443 {
		t.Fatal("ports or marks were not delegated to both carriers")
	}
	path := testPath("selected", "relay", "[2001:db8::1]:443", time.Now().Add(time.Minute))
	if err := b.InstallQualifiedPath(lane, 0, path); err != nil {
		t.Fatal(err)
	}
	if _, err := b.CommitPath(lane, path.ID, 0); err != nil {
		t.Fatal(err)
	}
	if b.BatchSize() != 4 {
		t.Fatalf("batch size = %d", b.BatchSize())
	}
	if err := b.Send([][]byte{{1}, make([]byte, 1453)}, lane); !errors.Is(err, ErrCarrierDatagram) || second.sendCount != 0 {
		t.Fatal("oversized packet allowed a partially dispatched batch")
	}
	if err := b.Send([][]byte{{1}, {2}, {3}}, lane); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("partial error = %v", err)
	}
	if len(second.sent) != 1 || second.sent[0][0] != 1 || second.sendCount != 2 || first.sendCount != 0 {
		t.Fatal("partial failure retried packets or used another carrier")
	}
}

func TestAdaptiveBind_PartialOpenRollsBack(t *testing.T) {
	first := &adaptiveTestBind{batch: 1}
	second := &adaptiveTestBind{batch: 1, openErr: io.ErrClosedPipe}
	b := testAdaptiveBind(t, Carrier{Name: "udp", Bind: first, DatagramMax: 1500},
		Carrier{Name: "relay", Bind: second, DatagramMax: 1500})
	if _, _, err := b.Open(0); !errors.Is(err, io.ErrClosedPipe) || first.closeCount != 1 {
		t.Fatalf("partial open error = %v, closes = %d", err, first.closeCount)
	}
	if _, ok := b.CarrierPort("udp"); ok {
		t.Fatal("failed open published a carrier")
	}
}

func TestAdaptiveBind_ReceiveOwnsBuffersAndEnforcesOverlap(t *testing.T) {
	now := time.Unix(100, 0)
	sourceA := udpEndpoint{addr: netip.MustParseAddrPort("192.0.2.1:8443")}
	sourceB := udpEndpoint{addr: netip.MustParseAddrPort("192.0.2.2:8443")}
	spoof := udpEndpoint{addr: netip.MustParseAddrPort("192.0.2.3:8443")}
	returned := []conn.Endpoint{spoof, sourceA, sourceB}
	received := false
	fn := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if received {
			return 0, io.EOF
		}
		received = true
		for i, ep := range returned {
			sizes[i] = copy(bufs[i], []byte{byte(i + 1)})
			eps[i] = ep
		}
		return len(returned), nil
	}
	carrier := &adaptiveTestBind{batch: 4, fns: []conn.ReceiveFunc{fn}}
	b := testAdaptiveBind(t, Carrier{Name: "udp", Bind: carrier, DatagramMax: 1500})
	b.now = func() time.Time { return now }
	lane := registerTestLane(t, b, "anchor")
	otherLane := registerTestLane(t, b, "other")
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	a := testPath("a", "udp", sourceA.DstToString(), now.Add(time.Minute))
	pathB := testPath("b", "udp", sourceB.DstToString(), now.Add(time.Minute))
	short := pathB
	short.ReceiveMax = 1200
	if err := b.InstallQualifiedPath(lane, 0, short); !errors.Is(err, ErrCarrierDatagram) {
		t.Fatalf("short receive MTU = %v", err)
	}
	for _, p := range []QualifiedPath{a, pathB} {
		if err := b.InstallQualifiedPath(lane, 0, p); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.InstallQualifiedPath(otherLane, 0, a); err == nil {
		t.Fatal("physical source was assigned to two lanes")
	}
	epoch, err := b.CommitPath(lane, "a", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.CommitPath(lane, "b", 0); !errors.Is(err, ErrStalePathEpoch) {
		t.Fatalf("stale commit = %v", err)
	}
	bufs, sizes, eps := receiveBatch(4)
	original := &bufs[0][0]
	check := func(want []byte) {
		t.Helper()
		received = false
		n, err := fns[0](bufs, sizes, eps)
		if err != nil || n != len(want) || &bufs[0][0] != original {
			t.Fatalf("receive count/backing array: n=%d err=%v", n, err)
		}
		var got []byte
		for i := range n {
			if eps[i] != lane || sizes[i] != 1 {
				t.Fatal("packet did not retain logical lane endpoint")
			}
			got = append(got, bufs[i][0])
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("received %v, want %v", got, want)
		}
	}
	check([]byte{2})
	release, err := b.PreparePathReceive(lane, "b", epoch)
	if err != nil {
		t.Fatal(err)
	}
	check([]byte{2, 3})
	if primary, current, _ := b.LaneState(lane); primary != "a" || current != epoch {
		t.Fatalf("receive preparation changed send path or epoch: %s/%d", primary, current)
	}
	if _, err := b.PreparePathReceive(lane, "b", epoch); !errors.Is(err, ErrStalePathEpoch) {
		t.Fatalf("second preparation = %v", err)
	}
	now = now.Add(pathReceiveOverlap)
	check([]byte{2})
	release()
	release, err = b.PreparePathReceive(lane, "b", epoch)
	if err != nil {
		t.Fatal(err)
	}
	release()
	check([]byte{2})
	if _, err := b.CommitPath(lane, "b", epoch); err != nil {
		t.Fatal(err)
	}
	primary, currentEpoch, paths, events := b.LaneDetails(lane)
	if primary != "b" || currentEpoch != epoch+1 || len(paths) != 2 || paths[0].Name != "a" ||
		paths[0].Primary || paths[1].Name != "b" || !paths[1].Primary ||
		paths[1].SendMax != pathB.SendMax || paths[1].ReceiveMax != pathB.ReceiveMax {
		t.Fatalf("unexpected lane details: active=%s epoch=%d paths=%+v", primary, currentEpoch, paths)
	}
	if len(events) != 2 || events[0].To != "a" || events[0].Reason != SwitchInitial ||
		events[1].From != "a" || events[1].To != "b" || events[1].Reason != SwitchQualified {
		t.Fatalf("unexpected lane switch history: %+v", events)
	}
	check([]byte{2, 3})
	now = now.Add(pathReceiveOverlap)
	check([]byte{3})
	now = now.Add(time.Minute)
	if primary, _, paths, _ := b.LaneDetails(lane); primary != "" || len(paths) != 0 {
		t.Fatalf("expired paths appeared qualified: active=%q paths=%+v", primary, paths)
	}
	if n, err := fns[0](bufs, sizes, eps); !errors.Is(err, io.EOF) || n != 0 {
		t.Fatalf("expired path received data: %d / %v", n, err)
	}
}

func TestBind_WSSCarrierPinsConnectionButLegacyEndpointSurvivesReplacement(t *testing.T) {
	b := NewServer()
	old := newPeer("session", nil, endpoint{id: "session"}, nil)
	old.pingRTT.Store(int64(time.Millisecond))
	b.peers = map[string]*peer{"session": old}
	if got := b.PeerRTT("session"); got != time.Millisecond {
		t.Fatalf("current peer RTT = %s", got)
	}
	pinned, err := b.CarrierEndpoint("session")
	if err != nil {
		t.Fatal(err)
	}
	replacement := newPeer("session", nil, endpoint{id: "session"}, nil)
	b.peers["session"] = replacement
	if got := b.PeerRTT("session"); got != 0 {
		t.Fatalf("replacement inherited stale peer RTT %s", got)
	}
	payload := [][]byte{make([]byte, 32)}
	if err := b.Send(payload, pinned); err == nil {
		t.Fatal("pinned endpoint sent to replacement")
	}
	if err := b.Send(payload, old.endpoint); err != nil {
		t.Fatalf("legacy endpoint could not use replacement: %v", err)
	}
	if len(old.out) != 0 || len(replacement.out) != 1 {
		t.Fatal("unexpected queue state after replacement")
	}
}

func TestBind_WSSOldReceiverStaysClosedAfterReopen(t *testing.T) {
	b := NewServer()
	old, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	current, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	b.packets <- packet{data: []byte{1}}
	bufs, sizes, eps := receiveBatch(1)
	if n, err := old[0](bufs, sizes, eps); !errors.Is(err, net.ErrClosed) || n != 0 {
		t.Fatalf("previous receiver = %d / %v", n, err)
	}
	if n, err := current[0](bufs, sizes, eps); err != nil || n != 1 || bufs[0][0] != 1 {
		t.Fatalf("new receiver = %d / %v", n, err)
	}
}

type adaptiveBlockingBind struct {
	adaptiveTestBind
	entered, closed, retire chan struct{}
}

func (f *adaptiveBlockingBind) Send([][]byte, conn.Endpoint) error {
	close(f.entered)
	<-f.closed
	<-f.retire
	return net.ErrClosed
}

func (f *adaptiveBlockingBind) Close() error {
	close(f.closed)
	return nil
}

func TestAdaptiveBind_CloseWaitsForSendFromOldSocket(t *testing.T) {
	transport := &adaptiveBlockingBind{
		adaptiveTestBind: adaptiveTestBind{batch: 1},
		entered:          make(chan struct{}), closed: make(chan struct{}), retire: make(chan struct{}),
	}
	b := testAdaptiveBind(t, Carrier{Name: "udp", Bind: transport, DatagramMax: 1500})
	lane := registerTestLane(t, b, "anchor")
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	path := testPath("direct", "udp", "192.0.2.1:8443", time.Now().Add(time.Minute))
	if err := b.InstallQualifiedPath(lane, 0, path); err != nil {
		t.Fatal(err)
	}
	if _, err := b.CommitPath(lane, path.ID, 0); err != nil {
		t.Fatal(err)
	}
	sent, closed := make(chan error, 1), make(chan error, 1)
	go func() { sent <- b.Send([][]byte{{1}}, lane) }()
	select {
	case <-transport.entered:
	case <-time.After(time.Second):
		t.Fatal("carrier did not start sending")
	}
	go func() { closed <- b.Close() }()
	<-transport.closed
	select {
	case <-closed:
		close(transport.retire)
		t.Fatal("bind closed while the previous send was still active")
	case <-time.After(20 * time.Millisecond):
	}
	close(transport.retire)
	if err := <-sent; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("send error = %v", err)
	}
	if err := <-closed; err != nil {
		t.Fatalf("close error = %v", err)
	}
}

func BenchmarkAdaptiveBindSendSingle(b *testing.B) {
	for _, mode := range []string{"udp", "adaptive"} {
		b.Run(mode, func(b *testing.B) {
			rx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				b.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				buf := make([]byte, 1500)
				for {
					if _, err := rx.Read(buf); err != nil {
						return
					}
				}
			}()
			b.Cleanup(func() { _ = rx.Close(); <-done })
			udp := NewUDPBind(0, nil)
			outer, err := udp.ParseEndpoint(rx.LocalAddr().String())
			if err != nil {
				b.Fatal(err)
			}
			var writer conn.Bind = udp
			endpoint := outer
			if mode == "adaptive" {
				bind, err := NewAdaptiveBind(1, Carrier{Name: "udp", Bind: udp, DatagramMax: 1500})
				if err != nil {
					b.Fatal(err)
				}
				lane, err := bind.RegisterLane("anchor", 1452)
				if err != nil {
					b.Fatal(err)
				}
				if _, _, err := bind.Open(0); err != nil {
					b.Fatal(err)
				}
				b.Cleanup(func() { _ = bind.Close() })
				if err := bind.InstallQualifiedPath(lane, 0, QualifiedPath{ID: "direct", Carrier: "udp", Endpoint: outer,
					SendMax: 1452, ReceiveMax: 1452, ValidUntil: time.Now().Add(time.Hour)}); err != nil {
					b.Fatal(err)
				}
				if _, err := bind.CommitPath(lane, "direct", 0); err != nil {
					b.Fatal(err)
				}
				writer, endpoint = bind, lane
			} else {
				if _, _, err := udp.Open(0); err != nil {
					b.Fatal(err)
				}
				b.Cleanup(func() { _ = udp.Close() })
			}
			batch := [][]byte{make([]byte, 128)}
			b.ReportAllocs()
			for b.Loop() {
				if err := writer.Send(batch, endpoint); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestAdaptiveBind_QualifiedSourceDoesNotTransferToAnotherSocket(t *testing.T) {
	source := udpEndpoint{addr: netip.MustParseAddrPort("192.0.2.1:51820")}
	receiveOnce := func() conn.ReceiveFunc {
		sent := false
		return func(bufs [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
			if sent {
				return 0, io.EOF
			}
			sent = true
			sizes[0] = copy(bufs[0], []byte{1})
			endpoints[0] = source
			return 1, nil
		}
	}
	a := &adaptiveTestBind{batch: 1, fns: []conn.ReceiveFunc{receiveOnce()}}
	alt := &adaptiveTestBind{batch: 1, fns: []conn.ReceiveFunc{receiveOnce()}}
	b := testAdaptiveBind(t, Carrier{Name: "udp", Bind: a, DatagramMax: 1500},
		Carrier{Name: "alt", Bind: alt, DatagramMax: 1500})
	lane := registerTestLane(t, b, "anchor")
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	path := testPath("primary", "udp", source.DstToString(), time.Now().Add(time.Minute))
	if err := b.InstallQualifiedPath(lane, 0, path); err != nil {
		t.Fatal(err)
	}
	if _, err := b.CommitPath(lane, path.ID, 0); err != nil {
		t.Fatal(err)
	}
	bufs, sizes, eps := receiveBatch(1)
	if n, err := fns[1](bufs, sizes, eps); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("qualified address became active on the alternate socket: %d / %v", n, err)
	}
	if n, err := fns[0](bufs, sizes, eps); n != 1 || err != nil || eps[0] != lane {
		t.Fatalf("qualified socket did not receive on the lane: %d / %v", n, err)
	}
}

func TestAdaptiveBind_OptionalUnavailableCarrierLeavesPrimaryUsable(t *testing.T) {
	wp := &adaptiveTestBind{batch: 1}
	optional := &adaptiveTestBind{batch: 1, openErr: errors.New("unavailable local socket")}
	b := testAdaptiveBind(t, Carrier{Name: "primary", Bind: wp, DatagramMax: 1500},
		Carrier{Name: "udp", Bind: optional, Optional: true, DatagramMax: 1500})
	lane := registerTestLane(t, b, "anchor")
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.CarrierPort("udp"); ok {
		t.Fatal("unavailable optional carrier advertised its socket")
	}
	if err := b.SetMark(42); err != nil || wp.mark != 42 || optional.mark != 0 {
		t.Fatal("socket mark was sent to an unopened carrier")
	}
	until := time.Now().Add(time.Minute)
	if err := b.InstallQualifiedPath(lane, 0, testPath("standby", "udp", "127.0.0.1:443", until)); !errors.Is(err, ErrPathUnqualified) {
		t.Fatalf("unavailable standby was accepted: %v", err)
	}
	if err := b.InstallQualifiedPath(lane, 0, testPath("current", "primary", "127.0.0.1:8443", until)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.CommitPath(lane, "current", 0); err != nil {
		t.Fatal(err)
	}
	if err := b.Send([][]byte{{1}}, lane); err != nil || wp.sendCount != 1 || optional.sendCount != 0 {
		t.Fatal("primary did not retain its send path")
	}
}
