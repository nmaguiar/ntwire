package client

import (
	"math"
	"net"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/server"
)

func TestAdaptiveSharedWindow_CombinesDirectionalRatesAtEachLaneClock(t *testing.T) {
	start := time.Unix(100, 0)
	peer := protocol.CarrierPerformance{AuthGeneration: 2, PathEpoch: 5, Primary: protocol.CarrierWSS, ElapsedUS: 10_000_000}
	a := adaptiveParentSample{anchor: adaptiveFeedbackSample{at: start, epoch: 4, peer: peer}, revision: 3,
		children: []adaptiveChildFeedback{{lane: new(connectionNetwork), epoch: 1, peer: peer},
			{lane: new(connectionNetwork), epoch: 2, peer: peer}}}
	b := a
	b.children = append([]adaptiveChildFeedback(nil), a.children...)
	b.anchor.at = start.Add(5 * time.Second)
	b.anchor.local = forwardingCounters{offered: 1000, received: 900}
	b.anchor.peer.ElapsedUS, b.anchor.peer.ReceivedBytes, b.anchor.peer.OfferedBytes = 15_000_000, 100, 200
	b.children[0].peer.ElapsedUS, b.children[0].peer.ReceivedBytes, b.children[0].peer.OfferedBytes = 14_500_000, 300, 400
	b.children[1].peer.ElapsedUS, b.children[1].peer.ReceivedBytes, b.children[1].peer.OfferedBytes = 15_500_000, 200, 700
	w, ok := adaptiveSharedWindow(a, b)
	up := 8 * (100/5.0 + 300/4.5 + 200/5.5)
	down := 8 * (200/5.0 + 400/4.5 + 700/5.5)
	if !ok || w.Upload == nil || w.Download == nil || w.Upload.OfferedBPS != 1600 || w.Download.DeliveredBPS != 1440 ||
		math.Abs(w.Upload.DeliveredBPS-up) > 0.00001 || math.Abs(w.Download.OfferedBPS-down) > 0.00001 {
		t.Fatalf("per-lane clocks were not normalized: %+v %+v", w.Upload, w.Download)
	}
	for _, tc := range []struct {
		name   string
		change func(*adaptiveParentSample)
	}{
		{"roster changed", func(p *adaptiveParentSample) { p.revision++ }},
		{"child rebound", func(p *adaptiveParentSample) { p.children[0].epoch++ }},
		{"peer rebound", func(p *adaptiveParentSample) { p.children[0].peer.PathEpoch++ }},
		{"old child authorization", func(p *adaptiveParentSample) { p.children[0].peer.AuthGeneration-- }},
		{"desynchronized child clock", func(p *adaptiveParentSample) { p.children[1].peer.ElapsedUS += 2_000_000 }},
		{"missing child", func(p *adaptiveParentSample) { p.children = p.children[:1] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := b
			changed.children = append([]adaptiveChildFeedback(nil), b.children...)
			tc.change(&changed)
			if _, ok := adaptiveSharedWindow(a, changed); ok {
				t.Fatal("incomparable child was accepted into parent feedback")
			}
		})
	}
}

func TestAdaptiveSharedCapacity_LiveThreePeersAndRetirementFence(t *testing.T) {
	f := newReconnectFixture(t)
	cfg := f.serverConfig("100.77.4.0/24", 18250, true, server.TransportConfig{Adaptive: true, AdaptiveMaxLanes: 3})
	c, _ := connectMultiLaneFixture(t, f, cfg)
	var child *connectionNetwork
	for range 2 {
		var err error
		child, err = c.openAdaptiveLane(t.Context())
		if err != nil {
			t.Fatal(err)
		}
	}
	var flows [3]net.Conn
	for i := range flows {
		flows[i] = dialLaneTest(t, "tcp", c.LocalAddresses[0])
		echoLaneTest(t, flows[i], "activate all managed lanes")
	}
	for _, lane := range c.TransportDetails().Lanes {
		if lane.ActiveFlows != 1 {
			t.Fatalf("fixture did not open a flow on each lane: %+v", lane)
		}
	}
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		for _, flow := range flows {
			echoLaneTest(t, flow, "measure aggregate parent delivery")
		}
		if perf := c.TransportDetails().AdaptivePerformance; perf != nil && perf.SharedCapacity != nil {
			shared := perf.SharedCapacity
			if shared.Lanes != 3 || shared.Upload == nil || shared.Download == nil ||
				shared.Upload.ObservedFloorBPS <= 0 || shared.Download.ObservedFloorBPS <= 0 || len(perf.Windows) != 0 {
				t.Fatalf("incorrect live parent-only evidence: %+v", perf)
			}
			for _, flow := range flows {
				_ = flow.Close()
			}
			waitLaneIdle(t, c, child)
			if err := c.retireAdaptiveLane(t.Context(), child.response.Adaptive.LaneID); err != nil {
				t.Fatal(err)
			}
			if after := c.TransportDetails().AdaptivePerformance; after != nil && after.SharedCapacity != nil {
				t.Fatalf("old roster contributed after retirement: %+v", after.SharedCapacity)
			}
			return
		}
		time.Sleep(40 * time.Millisecond)
	}
	t.Fatalf("three active lanes did not produce shared feedback: %+v", c.TransportDetails().AdaptivePerformance)
}
