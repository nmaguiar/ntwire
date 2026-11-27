package egressrouter

import (
	"fmt"
	"testing"
	"time"
)

func TestAdaptiveRankingBalancesSetupAndTransfer(t *testing.T) {
	now := time.Now()
	cfg := testConfig(t)
	cfg.Egress.Selection = "adaptive"
	cfg, err := cfg.Normalized()
	if err != nil {
		t.Fatal(err)
	}
	var path *PathPerformance
	r := New(func(m Member) Candidate {
		c := Candidate{Generation: "ready", Dialer: dialFunc(nil)}
		if m.ProfileID == "a" {
			c.Performance = path
		}
		return c
	})
	defer r.Close()
	r.now = func() time.Time { return now }
	state := &routeState{config: cfg, health: make(map[MemberID]*memberHealth)}
	r.state = state
	dst := Destination{Host: "echo.invalid", Port: 443}
	for i, candidate := range r.candidates(state) {
		h := r.healthFor(state, candidate)
		for range 3 {
			h.measurements.observe(now, time.Duration(10+50*i)*time.Millisecond)
		}
		h.transfer = transferEstimate{samples: 3, updated: now,
			down: transferDirection{rateBPS: float64(1+9*i) * 10e6, rateSamples: 3}}
	}
	pick := func(want string, decision Decision) {
		t.Helper()
		order := r.rankDecision(state, dst, decision)
		if len(order) == 0 || order[0].ProfileID != want {
			t.Fatalf("ranking = %v, want %s first", order, want)
		}
	}
	pick("a", Decision{Action: Proxy})
	state.destinations = map[observationKey]destinationObservation{
		destinationKey(cfg.Egress.Members[0].ID(), dst): {generation: "ready",
			transfer: transferEstimate{samples: 3, updated: now, down: transferDirection{bytes: 2 << 20}}},
	}
	pick("b", Decision{Action: Proxy})
	pick("a", Decision{Action: Proxy, Members: []MemberID{cfg.Egress.Members[0].ID()}})
	clear(state.destinations)
	path = &PathPerformance{ObservedAt: now, QueueDelay: 200 * time.Millisecond}
	pick("b", Decision{Action: Proxy})
	path.ObservedAt = now.Add(-pathPerformanceTTL - time.Second)
	pick("a", Decision{Action: Proxy})
}

func BenchmarkSmartProxyPerformanceRanking(b *testing.B) {
	for _, count := range []int{2, 8, 32, 64} {
		for _, selection := range []string{"destination-aware", "adaptive"} {
			b.Run(fmt.Sprintf("%d/%s", count, selection), func(b *testing.B) {
				members := make([]Member, count)
				for i := range members {
					members[i] = Member{ProfileID: fmt.Sprintf("profile%d", i), Tunnel: "internet",
						ExpectedServer: "https://fixture.invalid", Priority: i}
				}
				r := New(func(Member) Candidate { return Candidate{Generation: "ready", Dialer: dialFunc(nil)} })
				defer r.Close()
				state := &routeState{config: Config{Enabled: true, Egress: Membership{Selection: selection, Members: members}},
					health: make(map[MemberID]*memberHealth)}
				r.state = state
				dst := Destination{Host: "echo.invalid", Port: 443}
				b.ReportAllocs()
				for b.Loop() {
					_ = r.rankDecision(state, dst, Decision{Action: Proxy})
				}
			})
		}
	}
}
