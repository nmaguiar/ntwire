package client

import (
	"errors"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

func TestAdaptiveCapacityEvidence_SeparatesDirectionsAndPathEpoch(t *testing.T) {
	now := time.Unix(1000, 0)
	windows := []AdaptivePerformanceWindow{
		{Path: protocol.CarrierWSS, PathEpoch: 3, End: now.Add(-6 * time.Second),
			Upload:   &DirectionPerformance{OfferedBPS: 100e6, DeliveredBPS: 98e6},
			Download: &DirectionPerformance{OfferedBPS: 30e6, DeliveredBPS: 18e6}},
		{Path: protocol.CarrierWSS, PathEpoch: 3, End: now.Add(-time.Second),
			Upload:   &DirectionPerformance{OfferedBPS: 90e6, DeliveredBPS: 90e6},
			Download: &DirectionPerformance{OfferedBPS: 30e6, DeliveredBPS: 22e6}},
	}
	evidence := adaptiveCapacityEvidence(now, windows)
	if evidence == nil || evidence.Upload == nil || evidence.Download == nil ||
		evidence.Upload.Pressure || !evidence.Download.Pressure || evidence.Upload.ObservedFloorBPS != 90e6 ||
		evidence.Download.ObservedFloorBPS != 18e6 {
		t.Fatalf("unexpected directional evidence: %+v", evidence)
	}
	if !evidence.blocksTrial(protocol.CarrierWSS, 3) || evidence.blocksTrial(protocol.CarrierWSS, 4) ||
		evidence.blocksTrial(protocol.CarrierQUIC, 3) {
		t.Fatal("trial guard ignored the current path epoch")
	}
	windows[1].Download.DeliveredBPS = 30e6
	if adaptiveCapacityEvidence(now, windows).blocksTrial(protocol.CarrierWSS, 3) {
		t.Fatal("one window of download pressure suppressed the trial")
	}
	windows[0].Download = nil
	if evidence := adaptiveCapacityEvidence(now, windows); evidence == nil || evidence.Download != nil {
		t.Fatalf("missing direction was treated as congestion: %+v", evidence)
	}
	if got := adaptiveCapacityEvidence(now.Add(30*time.Second), windows); got != nil {
		t.Fatal("stale evidence survived its freshness limit")
	}
	windows[1].PathEpoch++
	if got := adaptiveCapacityEvidence(now, windows); got != nil {
		t.Fatal("delivery rates from different path epochs were combined")
	}
}

func TestAdaptiveExploration_OneOperationAndReleasesOnError(t *testing.T) {
	ws := wstransport.NewServer()
	bind, err := wstransport.NewAdaptiveBind(1, wstransport.Carrier{Name: protocol.CarrierWSS, Bind: ws, DatagramMax: 1500})
	if err != nil {
		t.Fatal(err)
	}
	a := &adaptiveCarrierClient{bind: bind, ws: ws}
	now := time.Now()
	failure := errors.New("fixture qualification failed")
	err = a.qualifyStandby(now, func() error {
		if a.beginExploration(now) {
			t.Fatal("another worker acquired the parent link")
		}
		return failure
	})
	if !errors.Is(err, failure) || !a.beginExploration(now) {
		t.Fatalf("failed qualification did not release its slot: %v", err)
	}
}

func TestAdaptiveExploration_RequiresFreshCurrentPressure(t *testing.T) {
	now := time.Unix(1000, 0)
	const path = protocol.CarrierAlternateUDP
	var history adaptivePerformanceHistory
	for _, offset := range []time.Duration{-6 * time.Second, -time.Second} {
		history.record(1, AdaptivePerformanceWindow{Path: path, PathEpoch: 2, End: now.Add(offset),
			Upload: &DirectionPerformance{OfferedBPS: 1e6, DeliveredBPS: 3e5}})
	}
	if !history.explorationPressured(now, 1, path, 2) ||
		history.explorationPressured(now, 1, path, 3) ||
		history.explorationPressured(now.Add(time.Minute), 1, path, 2) {
		t.Fatal("exploration ignored the evidence lifetime or active path")
	}
	history.renew(2, true)
	if history.explorationPressured(now, 2, path, 2) {
		t.Fatal("old generation put pressure on the renewed lane")
	}
}

func TestAdaptiveUDPHealth_BoundsRecoveryAfterOneDemand(t *testing.T) {
	now := time.Unix(1000, 0)
	var demand udpProbeDemand
	if demand.ready(now, 20, false) || !demand.ready(now.Add(time.Second), 0, true) {
		t.Fatal("did not retain demand while another probe was outstanding")
	}
	demand.pending, demand.misses = false, adaptiveUDPMissLimit
	if !demand.needsProbe(now.Add(10 * time.Second)) {
		t.Fatal("temporary failure of the recovery path stopped retries")
	}
	if demand.needsProbe(now.Add(adaptiveUDPHealthWindow)) {
		t.Fatal("recovery probes continued after the demand budget expired")
	}
	if !demand.ready(now.Add(time.Minute), 20, true) || demand.misses != 0 {
		t.Fatal("new traffic did not begin a separate observation window")
	}
}

func TestAdaptiveTrial_LeavesTimeToRestoreDemotedUDP(t *testing.T) {
	now := time.Unix(1000, 0)
	trial := adaptiveTrial{incumbent: protocol.CarrierAlternateUDP, started: now}
	if trial.elapsed(now.Add(19*time.Second)) || !trial.elapsed(now.Add(20*time.Second)) {
		t.Fatal("datagram trial did not leave time to restore the incumbent proof")
	}
	trial.incumbent = protocol.CarrierWSS
	if trial.elapsed(now.Add(20*time.Second)) || !trial.elapsed(now.Add(30*time.Second)) {
		t.Fatal("stream incumbent lost its normal evaluation window")
	}
}

func TestAdaptiveCapacityEvidence_RenewalNeedsNewWindows(t *testing.T) {
	now := time.Unix(1000, 0)
	makeWindow := func(age time.Duration) AdaptivePerformanceWindow {
		return AdaptivePerformanceWindow{Path: protocol.CarrierWSS, PathEpoch: 3, End: now.Add(-age),
			Upload: &DirectionPerformance{OfferedBPS: 10e6, DeliveredBPS: 10e6}, UploadBacklogged: true}
	}
	var history adaptivePerformanceHistory
	history.record(1, makeWindow(16*time.Second))
	history.record(1, makeWindow(11*time.Second))
	history.renew(2, true)
	history.record(2, makeWindow(6*time.Second))
	if got := history.snapshot(now, 2); got == nil || got.Capacity != nil || len(got.Windows) != 3 {
		t.Fatalf("prior throughput history affected new-generation pressure: %+v", got)
	}
	history.record(2, makeWindow(time.Second))
	if got := history.snapshot(now, 2); got == nil || !got.Capacity.blocksTrial(protocol.CarrierWSS, 3) {
		t.Fatalf("current queue observations did not register pressure: %+v", got)
	}
}
