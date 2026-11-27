package client

import (
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

func pathComparisonWindows(now time.Time) []AdaptivePerformanceWindow {
	var windows []AdaptivePerformanceWindow
	for i := range 4 {
		at := now.Add(-time.Duration(19-5*i) * time.Second)
		windows = append(windows,
			AdaptivePerformanceWindow{Path: protocol.CarrierWSS, End: at,
				Upload: &DirectionPerformance{OfferedBPS: 12e6, DeliveredBPS: 4e6}, RTT: 50 * time.Millisecond, RTTSamples: 2},
			AdaptivePerformanceWindow{Path: protocol.CarrierQUIC, End: at.Add(time.Second),
				Upload: &DirectionPerformance{OfferedBPS: 12e6, DeliveredBPS: 8e6}, RTT: 25 * time.Millisecond, RTTSamples: 2})
	}
	return windows
}

func TestAdaptivePathScore_WaitsForEvidenceAndDwell(t *testing.T) {
	now := time.Unix(100, 0)
	paths := []wstransport.QualifiedCarrier{
		{Name: protocol.CarrierWSS, RTT: 50 * time.Millisecond},
		{Name: protocol.CarrierQUIC, RTT: 25 * time.Millisecond},
	}
	windows := pathComparisonWindows(now)
	events := []wstransport.SwitchEvent{{To: protocol.CarrierWSS, At: now.Add(-time.Minute)}}
	decide := func(at time.Time) AdaptivePathDecision {
		return scoreAdaptivePaths(at, protocol.CarrierWSS, paths, events, windows)
	}
	if got := decide(now); !got.WouldSwitch || got.Candidate != protocol.CarrierQUIC ||
		got.ComparableWindows != 4 || got.ImprovedWindows != 4 || got.Confidence < pathConfidenceFloor {
		t.Fatalf("sustained candidate was not recommended: %+v", got)
	}
	events[0].At = now.Add(-10 * time.Second)
	if got := decide(now); got.WouldSwitch || got.Reason != "minimum active path dwell" {
		t.Fatalf("dwell did not hold the current path: %+v", got)
	}
	events[0].At = now.Add(-time.Minute)
	if got := decide(now.Add(time.Minute)); got.WouldSwitch {
		t.Fatalf("stale measurements drove a recommendation: %+v", got)
	}
	paths[1].RTT = 0
	if got := decide(now); got.WouldSwitch || got.Candidate != "" {
		t.Fatalf("unavailable carrier entered comparison: %+v", got)
	}
	paths[1].RTT = 25 * time.Millisecond
	windows = windows[:4]
	if got := decide(now); got.WouldSwitch || got.Reason != "fewer than six recent RTT observations on one path" {
		t.Fatalf("short observation drove a recommendation: %+v", got)
	}
}

func TestAdaptivePathScore_DemandAndReversalMargins(t *testing.T) {
	now := time.Unix(100, 0)
	windows := pathComparisonWindows(now)
	for i := range windows {
		if windows[i].Path == protocol.CarrierQUIC {
			windows[i].Upload.OfferedBPS = 30e6
		}
	}
	compare := func(reversal bool) AdaptivePathDecision {
		return compareAdaptivePaths(now, protocol.CarrierWSS, protocol.CarrierQUIC, reversal, windows)
	}
	if got := compare(false); got.WouldSwitch || got.ComparableWindows != 0 {
		t.Fatalf("unmatched demand drove a recommendation: %+v", got)
	}
	for i := range windows {
		if windows[i].Path == protocol.CarrierQUIC {
			windows[i].Upload.OfferedBPS = 12e6
			windows[i].Upload.DeliveredBPS = 4.42e6
		}
	}
	if got := compare(false); !got.WouldSwitch || got.MedianGainPercent <= 15 || got.MedianGainPercent >= 20 {
		t.Fatalf("trial did not clear the initial margin: %+v", got)
	}
	if got := compare(true); got.WouldSwitch || got.ImprovedWindows != 0 {
		t.Fatalf("reversal ignored the stricter improvement margin: %+v", got)
	}
}
