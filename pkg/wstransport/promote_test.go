package wstransport

import (
	"errors"
	"testing"
	"time"
)

// promoteScheduler returns a scheduler with a healthy WSS incumbent and the
// given UDP candidate after n healthy probes at rtt.
func promoteScheduler(t *testing.T, kind PathKind, n int, rtt time.Duration) *Scheduler {
	t.Helper()
	s := NewScheduler()
	now := time.Now()
	s.Register("wss", PathWSS)
	s.ActivateCarrier("wss", now)
	name := string(kind)
	s.Register(name, kind)
	for i := 0; i < n; i++ {
		s.ProbeResult(name, rtt, true, now)
	}
	return s
}

func TestPromotionCandidate_Qualification(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*Scheduler)
		n     int
		want  string
	}{
		{"not enough probes", nil, promoteQualifyingProbes - 1, ""},
		{"qualified direct", nil, promoteQualifyingProbes, "direct-udp"},
		{"lossy window", func(s *Scheduler) { s.ProbeResult("direct-udp", 0, false, time.Now()) }, promoteQualifyingProbes, ""},
		{"mtu limited", func(s *Scheduler) { s.SetMTUState("direct-udp", MTUStateLimited) }, promoteQualifyingProbes, ""},
		{"mtu still probing", func(s *Scheduler) { s.SetMTUState("direct-udp", MTUStateProbing) }, promoteQualifyingProbes, ""},
		{"mtu ok", func(s *Scheduler) { s.SetMTUState("direct-udp", MTUStateOK) }, promoteQualifyingProbes, "direct-udp"},
		{"forced", func(s *Scheduler) { s.SetForced("wss") }, promoteQualifyingProbes, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := promoteScheduler(t, PathDirect, tt.n, 5*time.Millisecond)
			if tt.setup != nil {
				tt.setup(s)
			}
			got, _ := s.promotionCandidate(promoteQualifyingProbes)
			if got != tt.want {
				t.Fatalf("promotionCandidate() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPromotionBetter_SameKindNeedsClearRTTWin(t *testing.T) {
	inc := &candidate{PathStatus: PathStatus{Kind: PathUDPRelay, RTT: 100 * time.Millisecond}}
	for _, tt := range []struct {
		rtt  time.Duration
		want bool
	}{
		{90 * time.Millisecond, false}, // 10% better: noise
		{75 * time.Millisecond, true},  // 25% and 25ms better
	} {
		c := &candidate{PathStatus: PathStatus{Kind: PathUDPRelay, RTT: tt.rtt}}
		if got := promotionBetter(c, inc); got != tt.want {
			t.Errorf("promotionBetter(rtt=%v) = %v, want %v", tt.rtt, got, tt.want)
		}
	}
	small := &candidate{PathStatus: PathStatus{Kind: PathUDPRelay, RTT: 20 * time.Millisecond}}
	if promotionBetter(&candidate{PathStatus: PathStatus{Kind: PathUDPRelay, RTT: 10 * time.Millisecond}}, small) {
		t.Error("a 10ms gain promoted despite the 15ms floor")
	}
	if !promotionBetter(&candidate{PathStatus: PathStatus{Kind: PathDirect, RTT: 200 * time.Millisecond}}, inc) {
		t.Error("direct-udp did not outrank udp-relay")
	}
}

func TestSchedulerPromote_ErrorsAndEvent(t *testing.T) {
	s := promoteScheduler(t, PathDirect, 1, time.Millisecond)
	s.Register("udp-relay", PathUDPRelay)
	if err := s.Promote("udp-relay", time.Now()); !errors.Is(err, ErrPromoteUnhealthy) {
		t.Fatalf("Promote(unhealthy) = %v", err)
	}
	if err := s.Promote("nope", time.Now()); !errors.Is(err, ErrPromoteUnknownPath) {
		t.Fatalf("Promote(unknown) = %v", err)
	}
	s.SetForced("wss")
	if err := s.Promote("direct-udp", time.Now()); !errors.Is(err, ErrPromoteForced) {
		t.Fatalf("Promote(while forced) = %v", err)
	}
	s.SetForced("")
	if err := s.Promote("direct-udp", time.Now()); err != nil {
		t.Fatalf("Promote() = %v", err)
	}
	if primary, _, _ := s.Select(); primary != "direct-udp" {
		t.Fatalf("primary after promote = %q", primary)
	}
	events := s.SwitchEvents()
	if last := events[len(events)-1]; last.Reason != SwitchPromoted || last.From != "wss" || last.To != "direct-udp" {
		t.Fatalf("last event = %+v, want wss -> direct-udp promoted", last)
	}
	// Sticky afterwards: WSS being healthy does not move it back.
	if primary, _, _ := s.Select(); primary != "direct-udp" {
		t.Fatalf("promoted primary not sticky: %q", primary)
	}
}

func TestPromoter_CommitsOnlyAfterServerAccepts(t *testing.T) {
	for _, accept := range []bool{true, false} {
		s := promoteScheduler(t, PathDirect, promoteQualifyingProbes, time.Millisecond)
		var asked string
		p := &promoter{request: func(path string) error {
			asked = path
			if !accept {
				return errors.New("409")
			}
			return nil
		}, done: make(chan struct{}, 1)}
		p.evaluate(s, time.Now())
		select {
		case <-p.done:
		case <-time.After(2 * time.Second):
			t.Fatal("promotion attempt did not run")
		}
		primary, _, _ := s.Select()
		if asked != "direct-udp" {
			t.Fatalf("server asked for %q", asked)
		}
		if accept && primary != "direct-udp" {
			t.Fatalf("accepted promotion not committed: %q", primary)
		}
		if !accept {
			if primary != "wss" {
				t.Fatalf("rejected promotion committed locally: %q", primary)
			}
			if p.failures != 1 || p.required() != 2*promoteQualifyingProbes {
				t.Fatalf("failures=%d required=%d, want backoff to %d", p.failures, p.required(), 2*promoteQualifyingProbes)
			}
		}
	}
}

func TestPromoter_DwellAndFlapBackoff(t *testing.T) {
	s := promoteScheduler(t, PathDirect, promoteQualifyingProbes, time.Millisecond)
	p := &promoter{request: func(string) error { return nil }, done: make(chan struct{}, 4)}
	start := time.Now()
	p.evaluate(s, start)
	<-p.done
	// The promoted path fails right away: a flap.
	s.CarrierFailure("direct-udp")
	if primary, _, _ := s.Select(); primary != "wss" {
		t.Fatalf("failover primary = %q, want wss", primary)
	}
	for i := 0; i < 4*promoteQualifyingProbes; i++ {
		s.ProbeResult("direct-udp", time.Millisecond, true, start)
	}
	// Inside the dwell window nothing happens, but the flap is counted.
	p.evaluate(s, time.Now())
	if p.failures != 1 {
		t.Fatalf("failures after flap = %d, want 1", p.failures)
	}
	if p.inFlight {
		t.Fatal("promotion attempted inside the dwell window")
	}
	// After the dwell it promotes again with the doubled requirement met.
	p.evaluate(s, time.Now().Add(promoteDwell+time.Second))
	select {
	case <-p.done:
	case <-time.After(2 * time.Second):
		t.Fatal("no promotion after dwell")
	}
	if primary, _, _ := s.Select(); primary != "direct-udp" {
		t.Fatalf("primary = %q, want direct-udp after re-promotion", primary)
	}
}

func TestMultipathBind_PromotionDisabledByDefault(t *testing.T) {
	m := NewMultipathBind(&fakeBind{}, "server", false, MultipathOptions{})
	defer m.Close()
	if m.promo.Load() != nil {
		t.Fatal("promotion enabled without EnablePromotion")
	}
}
