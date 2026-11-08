package wstransport

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// laneHarness connects a lane-capable client Bind to a server Bind through
// an httptest server that routes ?lane=N to ServeLane.
type laneHarness struct {
	server, client *Bind
	recv           conn.ReceiveFunc
	h              *httptest.Server
	disconnects    atomic.Int32
}

func newLaneHarness(t *testing.T, lanes int) *laneHarness {
	t.Helper()
	lh := &laneHarness{server: NewServer()}
	fns, _, err := lh.server.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	lh.recv = fns[0]
	lh.h = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.URL.Query().Get("lane"); v != "" {
			n, _ := strconv.Atoi(v)
			_ = lh.server.ServeLane(w, r, "peer", n)
			return
		}
		_ = lh.server.ServeHTTP(w, r, "peer")
	}))
	lh.client = NewClient("ws"+strings.TrimPrefix(lh.h.URL, "http"), lh.h.Client(), nil)
	lh.client.SetRedialBackoff(time.Millisecond, 5*time.Millisecond, time.Second)
	lh.client.SetLanes(lanes)
	lh.client.OnPeerDisconnected = func(string, conn.Endpoint) { lh.disconnects.Add(1) }
	if _, _, err := lh.client.Open(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = lh.client.Close()
		_ = lh.server.Close()
		lh.h.Close()
	})
	return lh
}

func waitLanes(t *testing.T, b *Bind, id string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if b.LanesUp(id) == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("LanesUp(%q) = %d, want %d", id, b.LanesUp(id), want)
}

func TestLanes_DefaultOpensOneConnection(t *testing.T) {
	lh := newLaneHarness(t, 1)
	waitLanes(t, lh.server, "peer", 1)
	time.Sleep(50 * time.Millisecond)
	if n := lh.server.LanesUp("peer"); n != 1 {
		t.Fatalf("server lanes = %d, want 1", n)
	}
	lh.server.mu.Lock()
	defer lh.server.mu.Unlock()
	if lh.server.lanes != nil {
		t.Fatal("default bind allocated lane state")
	}
}

func TestLanes_ConnectAndCarryTraffic(t *testing.T) {
	lh := newLaneHarness(t, 3)
	waitLanes(t, lh.server, "peer", 3)
	waitLanes(t, lh.client, "remote", 3)
	ep, err := lh.client.ParseEndpoint("127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{7}, 32)
	if err := lh.client.Send([][]byte{payload}, ep); err != nil {
		t.Fatal(err)
	}
	bufs := [][]byte{make([]byte, 128)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	done := make(chan struct{})
	go func() {
		_, _ = lh.recv(bufs, sizes, eps)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not receive datagram")
	}
	if !bytes.Equal(bufs[0][:sizes[0]], payload) || eps[0].DstToString() == "" {
		t.Fatalf("received %x from %v", bufs[0][:sizes[0]], eps[0])
	}
}

// Losing an extra lane must not mark the carrier disconnected; it redials.
func TestLanes_ExtraLaneDropIsNotACarrierFailure(t *testing.T) {
	lh := newLaneHarness(t, 2)
	waitLanes(t, lh.client, "remote", 2)
	lh.client.mu.Lock()
	lane := lh.client.lanes["remote"].extra[1]
	lh.client.mu.Unlock()
	_ = lane.ws.CloseNow()
	time.Sleep(50 * time.Millisecond)
	waitLanes(t, lh.client, "remote", 2)
	if n := lh.disconnects.Load(); n != 0 {
		t.Fatalf("OnPeerDisconnected fired %d times for an extra-lane drop", n)
	}
}

func TestPickLane_StickySpillAndReturn(t *testing.T) {
	b := &Bind{}
	p0 := &peer{id: "x", out: make(chan [][]byte, peerQueueDepth)}
	p1 := &peer{id: "x", lane: 1, out: make(chan [][]byte, peerQueueDepth)}
	b.lanes = map[string]*laneGroup{"x": {extra: map[int]*peer{1: p1}}}
	if got := b.pickLaneLocked("x", p0); got != p0 {
		t.Fatal("idle group did not use lane 0")
	}
	for i := 0; i < laneSpillDepth; i++ {
		p0.out <- nil
	}
	if got := b.pickLaneLocked("x", p0); got != p1 {
		t.Fatal("backed-up lane 0 did not spill to lane 1")
	}
	// Still sticky on lane 1 while lane 0 has a backlog.
	<-p0.out
	if got := b.pickLaneLocked("x", p0); got != p1 {
		t.Fatal("spilled send did not stay on lane 1")
	}
	for len(p0.out) > 0 {
		<-p0.out
	}
	// Drained, but not yet for laneReturnAfter.
	if got := b.pickLaneLocked("x", p0); got != p1 {
		t.Fatal("returned to lane 0 before laneReturnAfter")
	}
	b.lanes["x"].lastSpillAt = time.Now().Add(-2 * laneReturnAfter)
	if got := b.pickLaneLocked("x", p0); got != p0 {
		t.Fatal("did not return to lane 0 after it drained")
	}
}

func TestServeLane_RejectsLaneZeroAndOutOfRange(t *testing.T) {
	b := NewServer()
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for _, lane := range []int{0, MaxWSSLanes, -1} {
		rec := httptest.NewRecorder()
		if err := b.ServeLane(rec, httptest.NewRequest(http.MethodGet, "/v1/wg", nil), "peer", lane); err == nil {
			t.Errorf("ServeLane(lane=%d) accepted", lane)
		}
	}
}

func TestLaneURL(t *testing.T) {
	got, err := laneURL("wss://vpn.example:8443/v1/wg", 2)
	if err != nil || got != "wss://vpn.example:8443/v1/wg?lane=2" {
		t.Fatalf("laneURL = %q, %v", got, err)
	}
}

// Packets that arrive on an extra lane must carry lane 0's endpoint, never
// the lane's own remote address.
func TestLanes_ExtraLanePacketsUseLaneZeroEndpoint(t *testing.T) {
	lh := newLaneHarness(t, 2)
	waitLanes(t, lh.server, "peer", 2)
	lh.server.mu.Lock()
	lane0 := lh.server.peers["peer"].endpoint
	lane1 := lh.server.lanes["peer"].extra[1]
	lh.server.mu.Unlock()
	if lane1.endpoint.DstToString() == lane0.DstToString() {
		t.Skip("lane connections share a source address; cannot distinguish")
	}
	// Force the client's next send onto lane 1.
	lh.client.mu.Lock()
	g := lh.client.lanes["remote"]
	g.active, g.lastSpillAt = 1, time.Now()
	lh.client.mu.Unlock()
	ep, _ := lh.client.ParseEndpoint("127.0.0.1:1")
	if err := lh.client.Send([][]byte{bytes.Repeat([]byte{9}, 32)}, ep); err != nil {
		t.Fatal(err)
	}
	bufs := [][]byte{make([]byte, 128)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	got := make(chan string, 1)
	go func() {
		if _, err := lh.recv(bufs, sizes, eps); err == nil {
			got <- eps[0].DstToString()
		}
	}()
	select {
	case addr := <-got:
		if addr != lane0.DstToString() {
			t.Fatalf("lane-1 packet endpoint = %s, want lane 0's %s", addr, lane0.DstToString())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not receive the lane-1 packet")
	}
}
