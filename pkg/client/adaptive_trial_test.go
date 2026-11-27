package client

import (
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

func TestAdaptiveTrial_RequiresCurrentDemandBeforeExploration(t *testing.T) {
	now := time.Unix(1000, 0)
	start := now.Add(-adaptiveDwell)
	paths := []wstransport.QualifiedCarrier{{Name: protocol.CarrierWSS}, {Name: protocol.CarrierQUIC}}
	windows := []AdaptivePerformanceWindow{
		{Path: protocol.CarrierWSS, End: now.Add(-11 * time.Second), RTTSamples: 2},
		{Path: protocol.CarrierWSS, End: now.Add(-6 * time.Second), RTTSamples: 2},
		{Path: protocol.CarrierWSS, End: now.Add(-time.Second), RTTSamples: 2},
	}
	var trial adaptiveTrial
	candidate := func() string { return trial.candidateFor(now, protocol.CarrierWSS, paths, start, windows) }
	if got := candidate(); got != protocol.CarrierQUIC {
		t.Fatalf("qualified candidate = %q", got)
	}
	windows[2].WSSQueueP95 = 25 * time.Millisecond
	if got := candidate(); got != "" {
		t.Fatalf("queue pressure opened trial on %q", got)
	}
	windows[2].WSSQueueP95 = 0
	start = now.Add(-8 * time.Second)
	if got := candidate(); got != "" {
		t.Fatalf("previous selection drove a trial on %q", got)
	}
	start = now.Add(-adaptiveDwell)
	trial.finish(now, "restored incumbent", "gain below margin")
	if got := candidate(); got != "" || trial.next.Before(now.Add(adaptiveTrialCooldown)) {
		t.Fatalf("cooldown selected %q before %v", got, trial.next)
	}
}

func TestAdaptiveTrial_VerifiesFreshComparableTrialEvidence(t *testing.T) {
	since := time.Unix(100, 0)
	trial := adaptiveTrial{
		incumbent: protocol.CarrierWSS, candidate: protocol.CarrierQUIC,
		baselineSince: since, started: since.Add(30 * time.Second),
	}
	var windows []AdaptivePerformanceWindow
	for _, seconds := range []int{18, 23, 28, 38, 43, 48, 53, 58} {
		isTrial := seconds >= 30
		path, delivery := protocol.CarrierWSS, 4e6
		if isTrial {
			path, delivery = protocol.CarrierQUIC, 8e6
		}
		windows = append(windows, AdaptivePerformanceWindow{
			Path: path, End: since.Add(time.Duration(seconds) * time.Second),
			Upload: &DirectionPerformance{OfferedBPS: 10e6, DeliveredBPS: delivery},
			RTT:    20 * time.Millisecond, RTTSamples: 2,
		})
	}
	verdict := func() AdaptivePathDecision { return trial.verdict(since.Add(60*time.Second), windows, false) }
	if result := verdict(); !result.WouldSwitch || result.ComparableWindows != 3 {
		t.Fatalf("trial did not keep a sustained improvement: %+v", result)
	}
	for i := 3; i < len(windows); i++ {
		windows[i].Upload.DeliveredBPS = 4e6
	}
	if result := verdict(); result.WouldSwitch {
		t.Fatalf("equivalent transport passed the improvement gate: %+v", result)
	}
}

func TestAdaptiveTrial_DefersExplorationDuringQUICSendPressure(t *testing.T) {
	now := time.Unix(1000, 0)
	paths := []wstransport.QualifiedCarrier{{Name: protocol.CarrierWSS}, {Name: protocol.CarrierQUIC}}
	var trial adaptiveTrial
	windows := []AdaptivePerformanceWindow{
		{Path: protocol.CarrierQUIC, End: now.Add(-11 * time.Second), RTTSamples: 2},
		{Path: protocol.CarrierQUIC, End: now.Add(-6 * time.Second), RTTSamples: 2},
		{Path: protocol.CarrierQUIC, End: now.Add(-time.Second), RTTSamples: 2, QUICSent: 750, QUICDropped: 80},
	}
	candidate := func() string {
		return trial.candidateFor(now, protocol.CarrierQUIC, paths, now.Add(-adaptiveDwell), windows)
	}
	if got := candidate(); got != "" {
		t.Fatalf("QUIC send queue pressure opened a trial on %q", got)
	}
	windows[2].QUICDropped = 5
	if got := candidate(); got != protocol.CarrierWSS {
		t.Fatalf("a light burst suppressed the trial on %q", got)
	}
}

const trialRelayID = "AAAAAAAAAAAAAAAAAAAAAQ"

func TestAdaptiveTrial_ExploresQualifiedRelayWithTunnelObservations(t *testing.T) {
	now := time.Unix(1000, 0)
	start := now.Add(-adaptiveDwell)
	paths := []wstransport.QualifiedCarrier{
		{Name: protocol.CarrierWSS, Carrier: protocol.CarrierWSS},
		{Name: protocol.CarrierQUIC, Carrier: protocol.CarrierQUIC},
		{Name: trialRelayID, Carrier: protocol.CarrierRelayUDP},
	}
	var windows []AdaptivePerformanceWindow
	for _, age := range []time.Duration{11, 6, 1} {
		windows = append(windows, AdaptivePerformanceWindow{Path: protocol.CarrierWSS,
			End: now.Add(-age * time.Second), RTTSamples: 2})
	}
	trial := adaptiveTrial{lastCarrier: protocol.CarrierQUIC}
	if got := trial.candidateFor(now, protocol.CarrierWSS, paths, start, windows); got != protocol.CarrierQUIC {
		t.Fatalf("trial without tunnel samples selected %q", got)
	}
	for i := range windows {
		windows[i].TunnelRTTSamples = 2
	}
	if got := trial.candidateFor(now, protocol.CarrierWSS, paths, start, windows); got != trialRelayID {
		t.Fatalf("trial did not rotate to the qualified relay: %q", got)
	}
	trial.lastCarrier = protocol.CarrierRelayUDP
	if got := trial.candidateFor(now, protocol.CarrierWSS, paths, start, windows); got != protocol.CarrierQUIC {
		t.Fatalf("trial did not rotate back to QUIC: %q", got)
	}
}

func TestAdaptiveTrial_OnlyPerformanceSessionsCompareTwoRelays(t *testing.T) {
	now := time.Unix(1000, 0)
	alternate := "AAAAAAAAAAAAAAAAAAAAAg"
	paths := []wstransport.QualifiedCarrier{
		{Name: trialRelayID, Carrier: protocol.CarrierRelayUDP},
		{Name: alternate, Carrier: protocol.CarrierRelayUDP},
	}
	var windows []AdaptivePerformanceWindow
	for _, age := range []time.Duration{11, 6, 1} {
		windows = append(windows, AdaptivePerformanceWindow{Path: trialRelayID,
			End: now.Add(-age * time.Second), TunnelRTTSamples: 2})
	}
	var trial adaptiveTrial
	if got := trial.candidateFor(now, trialRelayID, paths, now.Add(-adaptiveDwell), windows); got != "" {
		t.Fatal("legacy session attempted to compare a second relay")
	}
	trial.parallelRelays = true
	if got := trial.candidateFor(now, trialRelayID, paths, now.Add(-adaptiveDwell), windows); got != alternate {
		t.Fatalf("performance session selected %q, want the qualified alternate", got)
	}
}

func TestAdaptiveTrial_RelayRequiresMeasuredAdvantageAndDirectWinsEquivalence(t *testing.T) {
	now := time.Unix(1000, 0)
	var windows []AdaptivePerformanceWindow
	for i := range 3 {
		windows = append(windows, AdaptivePerformanceWindow{Path: protocol.CarrierWSS, End: now.Add(time.Duration(i-6) * 5 * time.Second),
			Upload: &DirectionPerformance{OfferedBPS: 12e6, DeliveredBPS: 4e6}, RTT: time.Millisecond, RTTSamples: 2,
			TunnelRTT: 30 * time.Millisecond, TunnelRTTSamples: 2})
		windows = append(windows, AdaptivePerformanceWindow{Path: trialRelayID, End: now.Add(time.Duration(i-3) * 5 * time.Second),
			Upload: &DirectionPerformance{OfferedBPS: 12e6, DeliveredBPS: 8e6}, RTT: time.Millisecond, RTTSamples: 2,
			TunnelRTT: 20 * time.Millisecond})
	}
	toRelay := func() AdaptivePathDecision {
		return compareAdaptivePaths(now, protocol.CarrierWSS, trialRelayID, false, windows)
	}
	if decision := toRelay(); decision.WouldSwitch {
		t.Fatalf("relay won from carrier samples alone: %+v", decision)
	}
	for i := 1; i < len(windows); i += 2 {
		windows[i].TunnelRTTSamples = 2
	}
	if decision := toRelay(); !decision.WouldSwitch {
		t.Fatalf("relay did not win after sustained delivery advantage: %+v", decision)
	}
	for i := 1; i < len(windows); i += 2 {
		windows[i].Upload.DeliveredBPS = 4e6
		windows[i].TunnelRTT = 30 * time.Millisecond
	}
	if decision := toRelay(); decision.WouldSwitch {
		t.Fatalf("relay displaced an equivalent direct path: %+v", decision)
	}
	if decision := compareAdaptivePaths(now, trialRelayID, protocol.CarrierWSS, true, windows); !decision.WouldSwitch || decision.Reason != "direct path comparable under demand" {
		t.Fatalf("equivalent direct path was not preferred: %+v", decision)
	}
}
