package egressrouter

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type warmFixture struct {
	opened   atomic.Int32
	requests atomic.Int32
	reject   atomic.Int32
	closed   atomic.Int32
}

func (f *warmFixture) Prepare(context.Context) (PreparedEgress, error) {
	f.opened.Add(1)
	return &warmFixtureSocket{owner: f}, nil
}

func (f *warmFixture) DialDestination(ctx context.Context, dst Destination) (net.Conn, error) {
	prepared, _ := f.Prepare(ctx)
	defer prepared.Close()
	return prepared.DialDestination(ctx, dst)
}

type warmFixtureSocket struct{ owner *warmFixture }

func (s *warmFixtureSocket) Close() error {
	s.owner.closed.Add(1)
	return nil
}

func (s *warmFixtureSocket) DialDestination(context.Context, Destination) (net.Conn, error) {
	s.owner.requests.Add(1)
	switch s.owner.reject.Load() {
	case 1:
		return nil, &Failure{Class: "policy_denied", Code: 2}
	case 2:
		return nil, &Failure{Class: "ambiguous"}
	default:
		local, remote := net.Pipe()
		_ = remote.Close()
		return local, nil
	}
}

func TestWarmServiceSubmitsOnlyTheChosenRequest(t *testing.T) {
	for i, name := range []string{"success", "policy_denied", "ambiguous"} {
		t.Run(name, func(t *testing.T) {
			var main, backup warmFixture
			cfg := testConfig(t)
			cfg.Egress.Selection = "adaptive"
			cfg.Failover.WarmService = true
			r := New(func(m Member) Candidate {
				if m.ProfileID == "b" {
					return Candidate{Generation: "backup", Dialer: &backup}
				}
				return Candidate{Generation: "anchor", NumericDomain: true, Preparation: true, Dialer: &main}
			})
			defer r.Close()
			if err := r.Apply(cfg, nil); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				conn, err := r.dial(t.Context(), "tcp", "echo.invalid:443")
				if err != nil {
					t.Fatal(err)
				}
				_ = conn.Close()
			}
			state := r.state
			first := r.candidates(state)[0]
			deadline := time.Now().Add(time.Second)
			for !r.warmReady(state, first) && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if !r.warmReady(state, first) || main.opened.Load() != 3 || main.requests.Load() != 2 {
				t.Fatalf("preparation = %v, opened=%d submitted=%d", r.warmReady(state, first), main.opened.Load(), main.requests.Load())
			}
			stale := first
			stale.Generation = "replacement"
			if r.warmReady(state, stale) {
				t.Fatal("old service connection was reused after generation change")
			}
			main.reject.Store(int32(i))
			conn, err := r.dial(t.Context(), "tcp", "echo.invalid:443")
			if i == 0 {
				if err != nil {
					t.Fatal(err)
				}
				_ = conn.Close()
			} else {
				var failure *Failure
				if !errors.As(err, &failure) || failure.Class != name {
					t.Fatalf("failure = %v, want %s", err, name)
				}
			}
			r.Close()
			if main.opened.Load() != 3 || main.closed.Load() != 3 || main.requests.Load() != 3 ||
				backup.requests.Load() != 0 || r.warming.Load() != 0 || r.attempts.Load() != 0 {
				t.Fatalf("opened=%d closed=%d submitted=%d backup=%d", main.opened.Load(), main.closed.Load(), main.requests.Load(), backup.requests.Load())
			}
		})
	}
}

func TestWarmServiceRequiresAdaptiveSelection(t *testing.T) {
	cfg := testConfig(t)
	cfg.Failover.WarmService = true
	if _, err := cfg.Normalized(); err == nil {
		t.Fatal("legacy strategy accepted warm service")
	}
	cfg.Egress.Selection = "adaptive"
	cfg.Routing.AffinityScope = "group"
	if _, err := cfg.Normalized(); err == nil {
		t.Fatal("adaptive strategy accepted whole-group affinity")
	}
}

func TestWarmServiceCancelsPreparationOnReload(t *testing.T) {
	var live warmFixture
	started := make(chan struct{})
	stopped := make(chan struct{})
	cfg := testConfig(t)
	cfg.Egress.Selection = "adaptive"
	cfg.Failover.WarmService = true
	cfg.Egress.Members = cfg.Egress.Members[:1]
	r := New(func(Member) Candidate {
		return Candidate{Generation: "anchor", Preparation: true, Dialer: reloadWarmFixture{&live, started, stopped}}
	})
	defer r.Close()
	if err := r.Apply(cfg, nil); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		conn, err := r.dial(t.Context(), "tcp", "echo.invalid:443")
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("warm preparation did not start")
	}
	cfg.Failover.WarmService = false
	if err := r.Apply(cfg, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("warm preparation survived reload")
	}
	r.Close()
	if r.warming.Load() != 0 || r.attempts.Load() != 0 || live.requests.Load() != 2 {
		t.Fatalf("reservations=%d setups=%d requests=%d", r.warming.Load(), r.attempts.Load(), live.requests.Load())
	}
}

type reloadWarmFixture struct {
	*warmFixture
	started, stopped chan struct{}
}

func (f reloadWarmFixture) Prepare(ctx context.Context) (PreparedEgress, error) {
	close(f.started)
	<-ctx.Done()
	close(f.stopped)
	return nil, ctx.Err()
}
