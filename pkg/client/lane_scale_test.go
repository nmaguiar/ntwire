package client

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/server"
)

// Each synthetic sample has interval-aligned counters and clock epochs.
// Quantities are bytes per five-second interval.
func advanceLaneSample(s laneScaleSample, upload, uploadDelivered, download, downloadDelivered,
	childUpload, childDownload uint64) laneScaleSample {
	s.parent.anchor.at = s.parent.anchor.at.Add(adaptiveFeedbackInterval)
	s.parent.anchor.epoch = 1
	s.parent.anchor.local.offered += upload
	s.parent.anchor.local.received += downloadDelivered
	s.parent.anchor.peer.AuthGeneration = 1
	s.parent.anchor.peer.PathEpoch = 1
	s.parent.anchor.peer.Primary = protocol.CarrierWSS
	s.parent.anchor.peer.ElapsedUS += uint64(adaptiveFeedbackInterval.Microseconds())
	s.parent.anchor.peer.ReceivedBytes += uploadDelivered - childUpload
	s.parent.anchor.peer.OfferedBytes += download - childDownload
	s.parent.anchor.peer.WSSBacklogged = s.pressure
	if len(s.parent.children) != 0 {
		s.parent.children = slices.Clone(s.parent.children)
		for i := range s.parent.children {
			child := &s.parent.children[i]
			child.peer.AuthGeneration = 1
			child.peer.PathEpoch = 1
			child.peer.Primary = protocol.CarrierWSS
			child.peer.ElapsedUS += uint64(adaptiveFeedbackInterval.Microseconds())
			if i == len(s.parent.children)-1 {
				child.peer.ReceivedBytes += childUpload
				child.peer.OfferedBytes += childDownload
			}
		}
	}
	return s
}

func (s *laneScaleSample) addTestChild(id string) {
	lane := &connectionNetwork{response: protocol.AuthResponse{Adaptive: &protocol.AdaptiveSession{LaneID: id}}}
	s.parent.children = append(slices.Clone(s.parent.children), adaptiveChildFeedback{lane: lane, epoch: 1})
	s.parent.revision++
}

func laneConnected(string) bool    { return true }
func laneDisconnected(string) bool { return false }

func laneScaleBaseline(t *testing.T) (*laneScaleGovernor, laneScaleSample) {
	t.Helper()
	g := &laneScaleGovernor{maxLanes: 4, state: LaneScalingStatus{State: "observing"}}
	s := laneScaleSample{parent: adaptiveParentSample{anchor: adaptiveFeedbackSample{at: time.Unix(1, 0)}}, flows: 4, pressure: true}
	for i := 0; i <= 6; i++ {
		s = advanceLaneSample(s, 1_000_000, 500_000, 1_000_000, 500_000, 0, 0)
		if got := g.observe(s); got != (i == 6) {
			t.Fatalf("sample %d triggered %t", i, got)
		}
	}
	return g, s
}

func TestLaneScaleGovernor_RequiresComparableGain(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		upload, delivered          uint64
		downloadDelivered          uint64
		childUpload, childDownload uint64
		want                       string
	}{
		{"keeps measured upload gain", 1_000_000, 650_000, 500_000, 200_000, 0, "keeping"},
		{"keeps measured download gain", 1_000_000, 500_000, 650_000, 0, 200_000, "keeping"},
		{"same bottleneck", 1_000_000, 500_000, 500_000, 200_000, 0, "draining"},
		{"more offered demand", 1_400_000, 750_000, 500_000, 200_000, 0, "draining"},
		{"opposite direction regressed", 1_000_000, 650_000, 400_000, 200_000, 0, "draining"},
		{"child remained unused", 1_000_000, 650_000, 500_000, 0, 0, "draining"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, s := laneScaleBaseline(t)
			g.startChild("canary", s.parent.anchor.at)
			s.addTestChild("canary")
			for range 7 {
				s = advanceLaneSample(s, tc.upload, tc.delivered, 1_000_000, tc.downloadDelivered, tc.childUpload, tc.childDownload)
				if g.observe(s) {
					t.Fatal("opened another lane during a canary")
				}
			}
			if g.state.State != tc.want {
				t.Fatalf("got %v, want %s", g.state, tc.want)
			}
		})
	}
}

func TestLaneScaleGovernor_MeasuresOneExtraLaneAgainstEntireCohort(t *testing.T) {
	g, s := laneScaleBaseline(t)
	g.maxLanes = 3
	g.startChild("first", s.parent.anchor.at)
	s.addTestChild("first")
	for range 7 {
		s = advanceLaneSample(s, 1_000_000, 650_000, 1_000_000, 500_000, 200_000, 0)
		g.observe(s)
	}
	// The first lane was qualified with active demand in both directions.
	// Repeat a new comparable baseline on the full two-peer cohort.
	if g.state.State != "keeping" || !slices.Equal(g.kept, []string{"first"}) {
		t.Fatalf("the first child was not kept: %+v", g.state)
	}
	for i := range 6 {
		s = advanceLaneSample(s, 1_000_000, 650_000, 1_000_000, 500_000, 200_000, 0)
		if got := g.observe(s); got != (i == 5) {
			t.Fatalf("two-lane baseline sample %d triggered %t", i, got)
		}
	}
	g.startChild("second", s.parent.anchor.at)
	s.addTestChild("second")
	for range 7 {
		// Keep the existing child's delivery and add a qualifying share
		// from the newly added third peer.
		prior := s.parent.children[0].peer.ReceivedBytes
		s = advanceLaneSample(s, 1_000_000, 620_000, 1_000_000, 500_000, 180_000, 0)
		s.parent.children[0].peer.ReceivedBytes = prior + 200_000
		if g.observe(s) {
			t.Fatal("opened a concurrent trial")
		}
	}
	if g.state.State != "keeping" || !slices.Equal(g.kept, []string{"first", "second"}) {
		t.Fatalf("did not keep measured cohort gain: %+v", g.state)
	}
	for range 7 {
		s = advanceLaneSample(s, 1_000_000, 850_000, 1_000_000, 500_000, 180_000, 0)
		if g.observe(s) {
			t.Fatal("exceeded negotiated lane count")
		}
	}
	g.tick(s.parent.anchor.at.Add(laneScaleIdle), false, laneConnected)
	if g.child != "second" || g.state.State != "draining" {
		t.Fatalf("idle lanes did not start draining in reverse order: %+v", g.state)
	}
}

func TestLaneScaleGovernor_TransientPressureLossAndCooldown(t *testing.T) {
	_, s := laneScaleBaseline(t)
	g := laneScaleGovernor{maxLanes: 4, state: LaneScalingStatus{State: "observing"}}
	for i := 0; i < 14; i++ {
		s.pressure = i%3 != 1
		s = advanceLaneSample(s, 1_000_000, 500_000, 0, 0, 0, 0)
		if g.observe(s) {
			t.Fatal("transient pressure started a trial")
		}
	}
	qualified, s := laneScaleBaseline(t)
	qualified.startChild("canary", s.parent.anchor.at)
	qualified.tick(s.parent.anchor.at.Add(laneScaleTrialLimit), true, laneConnected)
	if qualified.state.State != "draining" {
		t.Fatalf("expired trial = %v", qualified.state)
	}
	qualified.cooldown(s.parent.anchor.at, "failed")
	now := s.parent.anchor.at
	for range 7 {
		s = advanceLaneSample(s, 1_000_000, 500_000, 0, 0, 0, 0)
		if qualified.observe(s) {
			t.Fatal("pressure bypassed cooldown")
		}
	}
	qualified.tick(now.Add(laneScaleCooldown), false, laneConnected)
	if qualified.state.State != "observing" {
		t.Fatalf("cooldown did not end: %v", qualified.state)
	}
	qualified.state.State, qualified.lastDemand = "keeping", now
	qualified.kept = []string{"canary"}
	qualified.tick(now.Add(laneScaleIdle-time.Second), false, laneConnected)
	if qualified.state.State != "keeping" {
		t.Fatal("lane drained before the idle window elapsed")
	}
	qualified.tick(now.Add(laneScaleIdle), false, laneConnected)
	if qualified.state.State != "draining" {
		t.Fatalf("idle trial = %v", qualified.state)
	}
}

func TestLaneScaleGovernor_AllowsChildToReconnect(t *testing.T) {
	now := time.Unix(1, 0)
	g := laneScaleGovernor{state: LaneScalingStatus{State: "keeping"}, lastDemand: now, kept: []string{"canary"}}
	g.tick(now, true, laneDisconnected)
	g.tick(now.Add(laneScaleObservation-time.Second), true, laneConnected)
	g.tick(now.Add(laneScaleObservation), true, laneDisconnected)
	if g.state.State != "keeping" {
		t.Fatal("temporary WebSocket loss discarded a qualified lane")
	}
	g.tick(now.Add(2*laneScaleObservation), true, laneDisconnected)
	if g.state.State != "draining" {
		t.Fatal("sustained WebSocket loss did not start drain")
	}
}

func TestLaneScaleGovernor_StaleSamplesFenceTrial(t *testing.T) {
	g, s := laneScaleBaseline(t)
	g.startChild("canary", s.parent.anchor.at)
	s.addTestChild("canary")
	first := advanceLaneSample(s, 1_000_000, 650_000, 0, 0, 200_000, 0)
	second := advanceLaneSample(first, 1_000_000, 650_000, 0, 0, 200_000, 0)
	second.parent.children[0].epoch++
	if _, _, _, ok := laneScaleComparison(first.parent, second.parent, "canary"); ok {
		t.Fatal("rebound child contributed a mismatched window")
	}
	g.invalidate()
	if g.state.State != "draining" {
		t.Fatalf("authorization change left a trial running: %v", g.state)
	}
}

func TestLaneScaleCanary_AllocatesAndDrainsThroughRealSession(t *testing.T) {
	f := newReconnectFixture(t)
	cfg := f.serverConfig("100.77.3.0/24", 18240, true, server.TransportConfig{Adaptive: true, AdaptiveMaxLanes: 4})
	c, _ := connectMultiLaneFixture(t, f, cfg)
	anchor := c.network
	g := newLaneScaleGovernor(anchor)
	if g == nil {
		t.Fatal("two-lane WSS pilot is unavailable")
	}
	control, _, _ := anchor.adaptive.credentials()
	if _, err := c.openAdaptiveLaneFor(t.Context(), anchor, control.AuthGeneration+1, c.laneRosterRevision); err == nil {
		t.Fatal("a stale governor created a lane with a different authorization generation")
	}
	first := dialLaneTest(t, "tcp", c.LocalAddresses[0])
	second := dialLaneTest(t, "tcp", c.LocalAddresses[0])
	echoLaneTest(t, first, "anchor flow 1")
	echoLaneTest(t, second, "anchor flow 2")
	// Inject the sustained-pressure observations. Reservation, peer
	// qualification, placement, drain and DELETE all use the real server.
	s := laneScaleSample{parent: adaptiveParentSample{anchor: adaptiveFeedbackSample{at: time.Now()}}, pressure: true}
	for range 7 {
		s = advanceLaneSample(s, 1_000_000, 500_000, 0, 0, 0, 0)
		c.measureLaneScale(t.Context(), anchor, g, s.parent, control)
	}
	if g.state.State != "trial" {
		t.Fatalf("did not qualify canary: %v", g.state)
	}
	if !anchor.adaptive.exploration.Load() {
		t.Fatal("canary did not reserve the parent's exploration budget")
	}
	c.mu.Lock()
	child := c.childLanes[g.child]
	c.mu.Unlock()
	if child == nil {
		t.Fatal("qualified child is missing")
	}
	if _, err := c.openAdaptiveLaneFor(t.Context(), anchor, control.AuthGeneration, s.parent.revision); err == nil {
		t.Fatal("a stale baseline opened a second automatic child")
	}
	out := dialLaneTest(t, "tcp", c.LocalAddresses[0])
	echoLaneTest(t, out, "new flow on canary")
	assertLaneFlows(t, c, child, 2, 1)
	c.tickLaneScale(t.Context(), anchor, g, g.trialStarted.Add(laneScaleTrialLimit), true)
	if err := c.retireAdaptiveLane(t.Context(), g.child); !errors.Is(err, errLaneDraining) {
		t.Fatalf("canary did not retain its existing lease: %v", err)
	}
	echoLaneTest(t, out, "flow survives rejected canary")
	_ = out.Close()
	waitLaneIdle(t, c, child)
	c.tickLaneScale(t.Context(), anchor, g, time.Now(), true)
	c.mu.Lock()
	remaining := len(c.childLanes)
	c.mu.Unlock()
	if remaining != 0 || g.state.State != "cooldown" {
		t.Fatalf("child not retired: %v", g.state)
	}
	if anchor.adaptive.exploration.Load() {
		t.Fatal("canary retained the parent's exploration budget after retirement")
	}
	echoLaneTest(t, first, "anchor survives")
}
