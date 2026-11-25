package egressrouter

import (
	"context"
	"errors"
	"io"
	"time"
)

// PreparedEgress owns a service connection until either DialDestination
// transfers it to the caller or Close discards it.
type PreparedEgress interface {
	Egress
	io.Closer
}

// PreparableEgress establishes the virtual service TCP connection without
// sending a SOCKS negotiation, destination or application payload.
type PreparableEgress interface {
	Prepare(context.Context) (PreparedEgress, error)
}

type preparation struct {
	candidate ranked
	stream    PreparedEgress
	failure   *Failure
	deadline  time.Time
	elapsed   time.Duration
}

func (r *Router) raceService(ctx context.Context, state *routeState, candidates []ranked) (preparation, int, []*Failure) {
	ctx, cancel := context.WithCancel(ctx)
	results := make(chan preparation, 2)
	launch := func(c ranked) {
		r.raceAttempts.Add(1)
		go func() {
			started := time.Now()
			deadline := started.Add(state.config.Failover.AttemptTimeout)
			setup, done := context.WithDeadline(ctx, deadline)
			stream, err := c.Dialer.(PreparableEgress).Prepare(setup)
			defer done()
			var f *Failure
			if err != nil && !errors.As(err, &f) {
				f = &Failure{Class: "ambiguous", Stage: "virtual_service"}
			}
			if f == nil && stream == nil {
				f = &Failure{Class: "ambiguous", Stage: "virtual_service"}
			}
			results <- preparation{candidate: c, stream: stream, failure: f, deadline: deadline, elapsed: time.Since(started)}
		}()
	}
	pending, launched := 1, 1
	launch(candidates[0])
	defer func() {
		cancel()
		for range pending {
			loser := <-results
			if loser.stream != nil {
				_ = loser.stream.Close()
			}
		}
	}()
	timer := time.NewTimer(state.config.Failover.RaceDelay)
	defer timer.Stop()
	var failures []*Failure
	for pending != 0 {
		select {
		case <-timer.C:
			if launched == 1 {
				launch(candidates[1])
				launched++
				pending++
			}
		case result := <-results:
			pending--
			if result.failure == nil {
				if launched == 2 && result.candidate.ID() == candidates[1].ID() {
					r.raceBackups.Add(1)
				}
				return result, launched, failures
			}
			if result.stream != nil {
				_ = result.stream.Close()
			}
			failures = append(failures, result.failure)
			if !result.failure.Retry {
				return preparation{}, launched, failures
			}
			if launched == 1 {
				launch(candidates[1])
				launched++
				pending++
			}
		case <-ctx.Done():
			return preparation{}, launched, failures
		}
	}
	return preparation{}, launched, failures
}

func (r *Router) canRace(state *routeState, pair []ranked) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != state {
		return false
	}
	for _, c := range pair {
		h := state.health[c.ID()]
		if h == nil || h.testing || !h.openUntil.IsZero() || h.quarantined || r.excluded[c.ID()] {
			return false
		}
		if _, ok := c.Dialer.(PreparableEgress); !ok || !c.Preparation {
			return false
		}
	}
	return true
}
