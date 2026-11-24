package egressrouter

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestAutoLimits_DemandAndDegradation(t *testing.T) {
	a := newAdmission(Limits{Auto: true, Connections: 630, ConcurrentAttempts: 38})
	var connections, attempts atomic.Int64
	now := time.Now()
	connections.Store(511)
	attempts.Store(31)
	if !a.take(&connections, false, now) || a.take(&connections, false, now) || !a.take(&attempts, true, now) {
		t.Fatal("initial admission bounds")
	}
	for range 8 {
		a.observe(time.Now().Add(-time.Millisecond), nil)
	}
	a.adjust(now.Add(2 * time.Second))
	if a.current.Connections != 630 || a.current.ConcurrentAttempts != 38 {
		t.Fatalf("growth and ceilings: %+v", a.current)
	}
	for range 8 {
		a.observe(time.Now().Add(-time.Second), nil)
	}
	a.adjust(now.Add(4 * time.Second))
	if a.current.ConcurrentAttempts >= 38 {
		t.Fatalf("slow setups: %+v", a.current)
	}
	before := a.current.ConcurrentAttempts
	for range 8 {
		a.observe(time.Now(), &Failure{Class: "policy_denied"})
	}
	a.adjust(now.Add(6 * time.Second))
	if a.current.ConcurrentAttempts != before {
		t.Fatal("destination policy changed limit")
	}
	for range 8 {
		a.observe(time.Now(), &Failure{Class: "timeout"})
	}
	a.adjust(now.Add(8 * time.Second))
	if a.current.ConcurrentAttempts >= before {
		t.Fatal("failed setups did not reduce limit")
	}
}

func TestAutoLimits_SharedHeadroomAndRecovery(t *testing.T) {
	limit := 3
	b := resourceBudget{sample: func(int) (int, string) { return limit, "Available file descriptors" }}
	a := newAdmission(Limits{Auto: true, Connections: 512, ConcurrentAttempts: 32})
	now := time.Now()
	if !b.acquire(false, now) || !b.acquire(true, now) || !b.acquire(true, now) || b.acquire(true, now) {
		t.Fatal("shared process capacity")
	}
	if s := a.status(1, &b, now); s.Connections != 1 || s.Reason != "Available file descriptors" {
		t.Fatalf("effective group limit %+v", s)
	}
	limit = 1
	if b.acquire(true, now.Add(3*time.Second)) || b.active != 3 {
		t.Fatal("existing connections should drain")
	}
	b.release()
	b.release()
	if b.acquire(true, now.Add(3*time.Second)) {
		t.Fatal("fixed group still occupies the only slot")
	}
	limit = 4
	if !b.acquire(true, now.Add(6*time.Second)) {
		t.Fatal("capacity did not recover")
	}
}

func TestAutoLimits_ReloadAndFixedMode(t *testing.T) {
	cfg := testConfig(t)
	cfg.Limits.Auto = true
	r := New(func(Member) Candidate { return Candidate{} })
	defer r.Close()
	if err := r.Apply(cfg, nil); err != nil {
		t.Fatal(err)
	}
	controller := r.state.admission
	if s := r.Status().Limits; !s.Auto || s.ConcurrentAttempts != 32 || controller.ceilings.ConcurrentAttempts != 128 {
		t.Fatalf("initial limits %+v", s)
	}
	if err := r.Apply(cfg, nil); err != nil || r.state.admission != controller {
		t.Fatal("equivalent reload reset measurements", err)
	}
	cfg.Limits = Limits{Connections: 256, ConcurrentAttempts: 7}
	if err := r.Apply(cfg, nil); err != nil {
		t.Fatal(err)
	}
	if s := r.Status().Limits; s.Auto || s.Connections != 256 || s.ConcurrentAttempts != 7 {
		t.Fatalf("fixed limits %+v", s)
	}
}
