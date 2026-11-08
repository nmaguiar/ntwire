package wstransport

import (
	"fmt"
	"testing"
	"time"
)

func TestSwitchLog_BoundedOldestFirst(t *testing.T) {
	var l switchLog
	for i := 0; i < switchLogLimit+5; i++ {
		l.record(SwitchEvent{To: fmt.Sprint(i)})
	}
	got := l.snapshot()
	if len(got) != switchLogLimit {
		t.Fatalf("len = %d, want %d", len(got), switchLogLimit)
	}
	if got[0].To != "5" || got[len(got)-1].To != fmt.Sprint(switchLogLimit+4) {
		t.Fatalf("order = %q..%q, want 5..%d", got[0].To, got[len(got)-1].To, switchLogLimit+4)
	}
}

func TestScheduler_SwitchEventsRecordedOncePerChange(t *testing.T) {
	s := NewScheduler()
	var observed []SwitchEvent
	s.SetSwitchObserver(func(e SwitchEvent) { observed = append(observed, e) })
	now := time.Now()
	s.Register("wss", PathWSS)
	s.ActivateCarrier("wss", now)
	s.Register("direct-udp", PathDirect)
	for i := 0; i < 3; i++ {
		s.ProbeResult("direct-udp", time.Millisecond, true, now)
	}
	for i := 0; i < 10; i++ {
		s.Select()
		s.Status()
	}
	s.CarrierFailure("wss")
	for i := 0; i < 10; i++ {
		s.Select()
	}
	events := s.SwitchEvents()
	want := []SwitchEvent{
		{From: "", To: "wss", Reason: SwitchInitial},
		{From: "wss", To: "direct-udp", Reason: SwitchCarrierFailure},
	}
	if len(events) != len(want) {
		t.Fatalf("events = %+v, want %d entries", events, len(want))
	}
	for i := range want {
		if events[i].From != want[i].From || events[i].To != want[i].To || events[i].Reason != want[i].Reason {
			t.Fatalf("event %d = %+v, want %+v", i, events[i], want[i])
		}
	}
	if len(observed) != len(want) {
		t.Fatalf("observer saw %d events, want %d", len(observed), len(want))
	}
}

func TestScheduler_SwitchReasonProbeMissesAndForced(t *testing.T) {
	s := NewScheduler()
	now := time.Now()
	s.Register("direct-udp", PathDirect)
	s.Register("udp-relay", PathUDPRelay)
	s.ProbeResult("direct-udp", time.Millisecond, true, now)
	s.Select()
	s.ProbeResult("udp-relay", 5*time.Millisecond, true, now)
	for i := 0; i < 3; i++ {
		s.ProbeResult("direct-udp", 0, false, now)
	}
	s.Select()
	s.ProbeResult("direct-udp", time.Millisecond, true, now)
	s.SetForced("direct-udp")
	s.Select()
	events := s.SwitchEvents()
	reasons := make([]SwitchReason, 0, len(events))
	for _, e := range events {
		reasons = append(reasons, e.Reason)
	}
	want := []SwitchReason{SwitchInitial, SwitchProbeMisses, SwitchForced}
	if fmt.Sprint(reasons) != fmt.Sprint(want) {
		t.Fatalf("reasons = %v, want %v", reasons, want)
	}
}
