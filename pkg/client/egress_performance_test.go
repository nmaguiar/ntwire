package client

import (
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/egressrouter"
)

func TestEgressPerformanceUsesCurrentPathEvidence(t *testing.T) {
	now := time.Now()
	h := adaptivePerformanceHistory{generation: 2, size: 2, next: 2}
	for i := range 2 {
		h.windows[i] = AdaptivePerformanceWindow{
			Path: "wss", PathEpoch: 3, generation: 2, End: now.Add(time.Duration(i-1) * 5 * time.Second),
			Upload: &DirectionPerformance{OfferedBPS: 12e6, DeliveredBPS: 7e6}, UploadBacklogged: true,
			WSSQueueP95: 23 * time.Millisecond,
		}
	}
	for _, tc := range []struct {
		name       string
		now        time.Time
		generation uint64
		epoch      uint64
		lanes      int
		want       bool
	}{
		{"current", now, 2, 3, 1, true},
		{"stale", now.Add(20 * time.Second), 2, 3, 1, false},
		{"prior generation", now, 1, 3, 1, false},
		{"prior path epoch", now, 2, 4, 1, false},
		{"roster requires shared evidence", now, 2, 3, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got egressrouter.PathPerformance
			h.egressEvidence(&got, tc.now, tc.generation, "wss", tc.epoch, 1, tc.lanes)
			if tc.want {
				if got.Upload.ObservedBPS != 7e6 || !got.Upload.Pressured || got.QueueDelay != 23*time.Millisecond {
					t.Fatalf("current evidence = %+v", got)
				}
			} else if got.Upload != (egressrouter.PathDirection{}) || got.QueueDelay != 0 {
				t.Fatalf("ineligible evidence = %+v", got)
			}
		})
	}
	h.windows[1].Upload = nil
	var queueOnly egressrouter.PathPerformance
	h.egressEvidence(&queueOnly, now, 2, "wss", 3, 1, 1)
	if queueOnly.QueueDelay != 23*time.Millisecond || queueOnly.Upload != (egressrouter.PathDirection{}) {
		t.Fatalf("queue without confirmed directional delivery = %+v", queueOnly)
	}
}
