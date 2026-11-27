package egressrouter

import (
	"context"
	"sync/atomic"
	"time"
)

const (
	warmGroupLimit     = 2
	warmProcessLimit   = 16
	warmIdleLimit      = 2 * time.Second
	warmSetupHeadroom  = 250 * time.Millisecond
	warmMemberInterval = 250 * time.Millisecond
)

var warmReservations atomic.Int64

type warmService struct {
	generation string
	prepared   preparation
	expires    time.Time
	consumed   chan struct{}
}

func (r *Router) startWarm(state *routeState, candidate ranked, health *memberHealth) {
	if !state.config.Failover.WarmService || !candidate.Preparation || candidate.Generation == "" {
		return
	}
	backend, ok := candidate.Dialer.(PreparableEgress)
	if !ok {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if r.state != state || r.ctx.Err() != nil || r.excluded[candidate.ID()] ||
		health != state.health[candidate.ID()] || health.testing || health.quarantined || !health.openUntil.IsZero() {
		return
	}
	previous := health.warmDemand
	health.warmDemand = now
	if previous.IsZero() || now.Sub(previous) > warmIdleLimit || now.Sub(health.lastWarm) < warmMemberInterval ||
		r.warming.Load() >= warmGroupLimit || state.warm[candidate.ID()] != nil ||
		state.config.Failover.AttemptTimeout <= warmSetupHeadroom ||
		!claim(&warmReservations, warmProcessLimit) {
		return
	}
	if !processBudget.acquire(true, now) {
		warmReservations.Add(-1)
		return
	}
	if !state.admission.takeSpareSetup(&r.attempts, now) {
		processBudget.release()
		warmReservations.Add(-1)
		return
	}
	health.lastWarm = now
	r.warming.Add(1)
	entry := &warmService{generation: candidate.Generation, consumed: make(chan struct{})}
	if state.warm == nil {
		state.warm = make(map[MemberID]*warmService)
	}
	state.warm[candidate.ID()] = entry
	r.wg.Go(func() { r.prepareWarm(state, candidate, backend, entry) })
}

func (r *Router) prepareWarm(state *routeState, candidate ranked, backend PreparableEgress, entry *warmService) {
	defer warmReservations.Add(-1)
	defer processBudget.release()
	defer r.warming.Add(-1)
	defer func() {
		r.mu.Lock()
		if state.warm[candidate.ID()] == entry {
			delete(state.warm, candidate.ID())
		}
		stream := entry.prepared.stream
		r.mu.Unlock()
		if stream != nil {
			_ = stream.Close()
		}
	}()

	start := time.Now()
	timeout := state.config.Failover.AttemptTimeout
	deadline := start.Add(timeout)
	ctx, cancel := context.WithDeadline(state.probeCtx, deadline)
	defer cancel()
	stream, err := backend.Prepare(ctx)
	r.attempts.Add(-1)
	if stream == nil {
		return
	}
	elapsed := time.Since(start)
	headroom := max(warmSetupHeadroom, timeout/2)
	now := time.Now()
	expires := now.Add(min(warmIdleLimit, deadline.Add(-headroom).Sub(now)))
	r.mu.Lock()
	entry.prepared.stream = stream
	valid := err == nil && r.state == state && !r.excluded[candidate.ID()] && time.Now().Before(expires)
	if valid {
		entry.prepared = preparation{candidate: candidate, stream: stream, deadline: deadline, elapsed: elapsed}
		entry.expires = expires
	}
	r.mu.Unlock()
	if !valid {
		return
	}
	timer := time.NewTimer(time.Until(expires))
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-entry.consumed:
	case <-timer.C:
	}
}

func (r *Router) warmReady(state *routeState, candidate ranked) bool {
	if !state.config.Failover.WarmService {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.availableWarm(state, candidate) != nil
}

// Caller holds r.mu. Generation changes invalidate old preparations even if
// the approved member record stays the same.
func (r *Router) availableWarm(state *routeState, candidate ranked) *warmService {
	entry := state.warm[candidate.ID()]
	if r.state == state && entry != nil && entry.generation == candidate.Generation && candidate.Preparation &&
		!r.excluded[candidate.ID()] && time.Now().Before(entry.expires) {
		return entry
	}
	return nil
}

func (r *Router) takeWarm(state *routeState, candidate ranked) preparation {
	if !state.config.Failover.WarmService {
		return preparation{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.availableWarm(state, candidate)
	if entry == nil {
		return preparation{}
	}
	prepared := entry.prepared
	entry.prepared.stream = nil
	delete(state.warm, candidate.ID())
	close(entry.consumed)
	r.warmHits.Add(1)
	return prepared
}
