package client

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

func TestAdaptiveWindow_RequiresComparablePathAndCounters(t *testing.T) {
	now := time.Unix(100, 0)
	before := adaptiveFeedbackSample{at: now, epoch: 4, local: forwardingCounters{100, 200},
		peer: protocol.CarrierPerformance{AuthGeneration: 2, PathEpoch: 5, Primary: protocol.CarrierWSS, ElapsedUS: 5_000_000, ReceivedBytes: 80, OfferedBytes: 300}}
	after := before
	after.at = now.Add(5 * time.Second)
	after.local = forwardingCounters{1_100, 700}
	after.peer.ElapsedUS, after.peer.ReceivedBytes, after.peer.OfferedBytes = 10_000_000, 580, 1_300
	after.backlogged, after.peer.WSSBacklogged = true, true
	after.queue = wstransport.QueuePerformance{Enabled: true, SampledBatches: 20}
	after.queue.QueueResidence[9], after.queue.QueueResidence[11] = 18, 2

	result, ok := adaptiveWindow(before, after)
	if !ok || result.Upload == nil || result.Download == nil ||
		result.Upload.OfferedBPS != 1600 || result.Upload.DeliveredBPS != 800 ||
		result.Download.OfferedBPS != 1600 || result.Download.DeliveredBPS != 800 ||
		result.WSSQueueP95 != 2048*time.Microsecond || result.PathEpoch != after.epoch ||
		!result.UploadBacklogged || !result.DownloadBacklogged {
		t.Fatalf("unexpected directional window: %+v", result)
	}

	for _, tc := range []struct {
		name   string
		change func(*adaptiveFeedbackSample)
	}{
		{"local path epoch", func(w *adaptiveFeedbackSample) { w.epoch++ }},
		{"peer path epoch", func(w *adaptiveFeedbackSample) { w.peer.PathEpoch++ }},
		{"generation", func(w *adaptiveFeedbackSample) { w.peer.AuthGeneration++ }},
		{"other path", func(w *adaptiveFeedbackSample) { w.peer.Primary = protocol.CarrierQUIC }},
		{"clock stalled", func(w *adaptiveFeedbackSample) { w.peer.ElapsedUS = before.peer.ElapsedUS }},
		{"peer clock discrepancy", func(w *adaptiveFeedbackSample) { w.peer.ElapsedUS += 2_000_000 }},
		{"local traffic reset", func(w *adaptiveFeedbackSample) { w.local.offered = 0 }},
		{"peer traffic reset", func(w *adaptiveFeedbackSample) { w.peer.ReceivedBytes = 0 }},
		{"idle", func(w *adaptiveFeedbackSample) {
			w.local.offered = before.local.offered
			w.peer.OfferedBytes = before.peer.OfferedBytes
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := after
			tc.change(&changed)
			if _, ok := adaptiveWindow(before, changed); ok {
				t.Fatal("incomparable sample entered history")
			}
		})
	}
	after.peer.OfferedBytes = before.peer.OfferedBytes
	if result, ok := adaptiveWindow(before, after); !ok || result.Download != nil {
		t.Fatal("idle download was counted as zero goodput")
	}
}

func TestAdaptivePerformanceHistory_BoundedFreshDirectionalEnvelope(t *testing.T) {
	var h adaptivePerformanceHistory
	now := time.Unix(1000, 0)
	for i := range 30 {
		path := protocol.CarrierWSS
		if i%2 == 0 {
			path = protocol.CarrierQUIC
		}
		h.record(1, AdaptivePerformanceWindow{
			Path: path, End: now.Add(time.Duration(i-30) * time.Second),
			Upload: &DirectionPerformance{OfferedBPS: 100, DeliveredBPS: 80},
		})
	}
	out := h.snapshot(now, 1)
	if out == nil || len(out.Windows) != adaptiveHistoryWindows || out.UploadWindows != adaptiveHistoryWindows ||
		out.DownloadWindows != 0 || out.ObservedUploadBPS < 79.9 || out.ObservedUploadBPS > 80.1 {
		t.Fatalf("history added separate capacities or grew unbounded: %+v", out)
	}
	out.Windows[0].Upload.DeliveredBPS = 0
	if h.snapshot(now, 1).Windows[0].Upload.DeliveredBPS == 0 {
		t.Fatal("status caller changed recorded observations")
	}
	if h.snapshot(now.Add(time.Minute), 1) != nil || h.snapshot(now, 2) != nil {
		t.Fatal("old observations survived time or authorization fencing")
	}
	h.renew(2, true)
	h.record(1, AdaptivePerformanceWindow{Path: "obsolete", End: now})
	h.feedback(1, now, "obsolete feedback")
	if got := h.snapshot(now, 2); got == nil || len(got.Windows) != adaptiveHistoryWindows ||
		got.FeedbackRequests != 0 || got.Windows[len(got.Windows)-1].Path == "obsolete" {
		t.Fatalf("unchanged renewal did not retain only completed windows: %+v", got)
	}
	h.renew(3, false)
	if h.snapshot(now, 3) != nil {
		t.Fatal("history survived a change to the grants")
	}
}

func TestAdaptivePerformance_ObservesAuthorizedLiveTraffic(t *testing.T) {
	var requests atomic.Uint64
	connect := newQUICTestFixture(t, 1280, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/performance") {
				requests.Add(1)
			}
			next.ServeHTTP(w, r)
		})
	})
	c, err := connect(true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	auth, bearer, _ := c.network.adaptive.credentials()
	if !auth.Performance || !protocol.HasCapability(c.Response.TransportCapabilities, protocol.CapabilityAdaptivePerformanceV1) {
		t.Fatal("performance feedback was not negotiated")
	}
	time.Sleep(1300 * time.Millisecond)
	if requests.Load() != 0 {
		t.Fatal("idle connection polled for feedback")
	}
	tcp, err := net.Dial("tcp", c.LocalAddresses[0])
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	payload := bytes.Repeat([]byte("traffic"), 128)
	reply := make([]byte, len(payload))
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		_ = tcp.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := tcp.Write(payload); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(tcp, reply); err != nil || !bytes.Equal(reply, payload) {
			t.Fatalf("echo failed: %v", err)
		}
		if sample := c.TransportDetails().AdaptivePerformance; sample != nil && len(sample.Windows) >= 2 {
			if sample.ObservedUploadBPS <= 0 || sample.ObservedDownloadBPS <= 0 || requests.Load() < 3 ||
				sample.Windows[0].Path != protocol.CarrierWSS {
				t.Fatalf("missing sustained directional evidence: %+v", sample)
			}
			if evidence := sample.Capacity; evidence == nil || evidence.Upload == nil || evidence.Download == nil ||
				evidence.Upload.ObservedFloorBPS <= 0 || evidence.Download.ObservedFloorBPS <= 0 {
				t.Fatalf("live feedback did not expose both directional observations: %+v", sample)
			}
			if c.TransportInfo().AdaptivePerformance != nil {
				t.Fatal("basic transport status included detailed performance history")
			}
			// The poller uses the same bearer as other lane operations.
			// A valid bearer still can't read a different lane.
			var other protocol.CarrierPerformance
			url := c.base + "/v1/transport/lanes/AAAAAAAAAAAAAAAAAAAAAA/performance"
			err := c.network.adaptive.controlRequest(t.Context(), http.MethodGet, url, bearer, nil, &other)
			if denied, ok := err.(*carrierHTTPError); !ok || denied.status != http.StatusNotFound {
				t.Fatalf("cross-lane feedback request: %v", err)
			}
			if err := c.renew(); err != nil {
				t.Fatalf("renewing active lane: %v", err)
			}
			if renewed := c.TransportDetails().AdaptivePerformance; renewed == nil || len(renewed.Windows) == 0 || renewed.Capacity != nil {
				t.Fatal("renewal must retain throughput history and clear current capacity evidence")
			}
			return
		}
		time.Sleep(40 * time.Millisecond)
	}
	t.Fatal("busy lane did not record comparable forwarding windows")
}
