package egressrouter

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ranked struct {
	Member
	Candidate
}
type memberHealth struct {
	failureStage string
	probing      bool
	timing       SetupTiming
	overhead     time.Duration
	httpsTTFB    time.Duration
	quarantined  bool
	generation   string
	measurements
	lastProbe      time.Time
	healthWindow   outcomeWindow
	passiveWindow  outcomeWindow
	consecutive    int
	openUntil      time.Time
	testing        bool
	attempts       uint64
	failureClass   string
	active         atomic.Int64
	routed         atomic.Uint64
	sent, received atomic.Uint64
}
type affinity struct {
	id                                    MemberID
	expires, used                         time.Time
	challenger                            MemberID
	comparisons                           int
	comparedA, comparedB                  uint64
	priorGeneration, challengerGeneration string
}

func loopbackEndpoint(address string) (netip.AddrPort, bool) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return netip.AddrPort{}, false
	}
	if name := strings.TrimSuffix(strings.ToLower(host), "."); name == "localhost" || strings.HasSuffix(name, ".localhost") {
		host = "127.0.0.1"
	}
	addr, err := netip.ParseAddrPort(net.JoinHostPort(host, port))
	if err != nil || !addr.Addr().Unmap().IsLoopback() {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port()), true
}
func sameEndpoint(a, b string) bool {
	pa, ok := loopbackEndpoint(a)
	pb, other := loopbackEndpoint(b)
	return ok && other && pa.Port() == pb.Port()
}
func (r *Router) candidate(state *routeState, m Member) Candidate {
	c := r.source(m)
	if c.Dialer != nil && sameEndpoint(state.config.Listen, c.ControlProxy) {
		c.Dialer = nil
		c.Reason = "recursive_control_proxy"
	}
	return c
}
func (r *Router) candidates(state *routeState) []ranked {
	members := state.config.resolvedMembers(r.discover)
	out := make([]ranked, 0, len(members))
	for _, m := range members {
		out = append(out, ranked{m, r.candidate(state, m)})
	}
	for i := range out {
		if out[i].Dialer == nil || out[i].ControlProxy == "" {
			continue
		}
		for _, other := range out {
			if sameEndpoint(out[i].ControlProxy, other.LocalAddress) {
				out[i].Dialer = nil
				out[i].Reason = "recursive_control_proxy"
				break
			}
		}
	}
	return out
}

func (r *Router) healthFor(state *routeState, c ranked) *memberHealth {
	h := state.health[c.ID()]
	if h == nil || h.generation != c.Generation {
		if h == nil && len(state.health) >= 128 {
			var disposable MemberID
			for id, old := range state.health {
				disposable = id
				if old.active.Load() == 0 && !old.testing && !old.probing {
					break
				}
			}
			delete(state.health, disposable)
		}
		h = &memberHealth{generation: c.Generation}
		state.health[c.ID()] = h
	}
	return h
}
func (r *Router) rank(state *routeState, dst Destination) []ranked {
	return r.rankDecision(state, dst, state.decide(dst, dst.IP(), r.now()))
}

func (r *Router) rankDecision(state *routeState, dst Destination, decision Decision) []ranked {
	if decision.Action != Proxy {
		return nil
	}
	candidates := r.candidates(state)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != state {
		return nil
	}
	now := r.now()
	memberIDs := decision.Members
	strategy := state.config.Egress.Selection
	measured := strategy == "sticky-fastest" || strategy == "fastest-healthy" || strategy == "destination-aware"
	filtered := candidates[:0]
	inputs := make([]RankedCandidate, 0, len(candidates))
	byID := make(map[MemberID]ranked, len(candidates))
	for _, c := range candidates {
		id := c.ID()
		if c.Dialer == nil || r.excluded[id] || len(memberIDs) > 0 && !slices.Contains(memberIDs, id) {
			continue
		}
		h := r.healthFor(state, c)
		if now.Before(h.openUntil) || h.testing || h.quarantined {
			continue
		}
		var latency time.Duration
		var hasScore bool
		if measured {
			latency, hasScore = score(now, h.measurements, h.healthWindow, state.config.Failover.AttemptTimeout)
		}
		if strategy == "destination-aware" {
			timeout := state.config.Failover.AttemptTimeout
			if !hasScore {
				latency = timeout / 4
			}
			hasScore = true
			item := state.destinations[destinationKey(id, dst)]
			if item.generation == c.Generation {
				if local, ok := score(now, item.measurements, item.outcomes, timeout); ok {
					latency = local
				} else if count, successes := item.outcomes.recent(now); count > 0 {
					latency += time.Duration(float64(timeout) * float64(count-successes) / float64(count))
				}
			}
		}
		filtered = append(filtered, c)
		inputs = append(inputs, RankedCandidate{Member: c.Member, Score: latency, Measured: hasScore})
		byID[id] = c
	}
	if len(filtered) == 0 {
		return nil
	}
	state.sequence++
	selector := r.selector
	if selector == nil {
		selector = builtinSelector{strategy: strategy, sequence: state.sequence}
	}
	candidates = make([]ranked, 0, len(filtered))
	for _, id := range selector.Rank(now, dst, inputs) {
		if c, ok := byID[id]; ok {
			candidates = append(candidates, c)
			delete(byID, id)
		}
	}
	for _, c := range filtered {
		if _, ok := byID[c.ID()]; ok {
			candidates = append(candidates, c)
		}
	}
	memberScore := func(c ranked) (time.Duration, bool) {
		h := state.health[c.ID()]
		return score(now, h.measurements, h.healthWindow, state.config.Failover.AttemptTimeout)
	}
	moveFirst := func(id MemberID) {
		for i, c := range candidates {
			if c.ID() == id {
				copy(candidates[1:i+1], candidates[:i])
				candidates[0] = c
				return
			}
		}
	}
	key := affinityKey(state.config.Routing, dst)
	affinity, sticky := state.affinity[key]
	sticky = sticky && strategy == "sticky-fastest" && now.Before(affinity.expires)
	if sticky {
		challenger := candidates[0]
		current := false
		for _, c := range candidates {
			if c.ID() != affinity.id {
				continue
			}
			current = true
			top, tm := memberScore(challenger)
			old, om := memberScore(c)
			if state.config.Routing.AffinityScope != "group" && tm && om && challenger.ID() != c.ID() && float64(top) < float64(old)*(1-float64(state.config.Routing.HysteresisPercent)/100) {
				incumbent, alternative := state.health[c.ID()], state.health[challenger.ID()]
				if affinity.challenger != challenger.ID() || affinity.priorGeneration != c.Generation || affinity.challengerGeneration != challenger.Generation {
					affinity.comparisons = 0
					affinity.comparedA, affinity.comparedB = 0, 0
				}
				affinity.challenger = challenger.ID()
				affinity.priorGeneration, affinity.challengerGeneration = c.Generation, challenger.Generation
				// Each comparison must include a new measurement since the last one.
				if affinity.comparedA != incumbent.revision || affinity.comparedB != alternative.revision {
					affinity.comparisons++
					affinity.comparedA, affinity.comparedB = incumbent.revision, alternative.revision
				}
			} else {
				affinity.comparisons = 0
			}
			if affinity.comparisons < 3 {
				moveFirst(c.ID())
			}
			state.affinity[key] = affinity
			break
		}
		sticky = current
	}
	if measured && !sticky && state.sequence%20 == 0 {
		for _, c := range candidates {
			if _, ok := memberScore(c); !ok {
				moveFirst(c.ID())
				break
			}
		}
	}
	moveFirst(r.preferred)
	return candidates
}

func (r *Router) remember(state *routeState, dst Destination, id MemberID) {
	if state.config.Egress.Selection != "sticky-fastest" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	key := affinityKey(state.config.Routing, dst)
	existing, ok := state.affinity[key]
	if ok && now.Before(existing.expires) && state.config.Routing.AffinityScope == "group" &&
		dst.Port != 0 && !state.decide(dst, dst.IP(), now).permits(existing.id) {
		return
	}
	if ok && existing.id == id && now.Before(existing.expires) {
		existing.used = now
		if state.config.Routing.AffinityScope == "group" {
			existing.expires = now.Add(state.config.Routing.AffinityTTL)
		}
		state.affinity[key] = existing
		return
	}
	if !ok && len(state.affinity) >= 1024 {
		oldest := key
		for k, a := range state.affinity {
			if oldest == key || a.used.Before(state.affinity[oldest].used) {
				oldest = k
			}
		}
		delete(state.affinity, oldest)
	}
	state.affinity[key] = affinity{id: id, expires: now.Add(state.config.Routing.AffinityTTL), used: now}
}

func (r *Router) admit(state *routeState, c ranked, probe bool) (*memberHealth, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != state || r.excluded[c.ID()] || c.Dialer == nil {
		return nil, false
	}
	h := r.healthFor(state, c)
	if h.testing || h.quarantined || (probe && h.probing) || r.now().Before(h.openUntil) {
		return nil, false
	}
	if probe {
		h.probing = true
	}
	halfOpen := !h.openUntil.IsZero()
	h.testing = halfOpen
	return h, halfOpen
}
func (r *Router) try(ctx context.Context, state *routeState, c ranked, h *memberHealth, dst Destination, probe, halfOpen bool, preflight time.Duration, priorDeadline time.Time) (net.Conn, *Failure) {
	limit := state.config.Failover.AttemptTimeout
	if !priorDeadline.IsZero() {
		limit = min(limit, time.Until(priorDeadline))
	}
	setup, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	started := r.now()
	conn, err := c.Dialer.DialDestination(setup, dst)
	var failure *Failure
	if err != nil && !errors.As(err, &failure) {
		failure = &Failure{Class: "ambiguous"}
	}
	if ctx.Err() != nil {
		failure = &Failure{Class: "canceled"}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			failure = &Failure{Class: "timeout", Code: 6}
		}
	} else if failure == nil && (conn == nil || setup.Err() != nil) {
		failure = &Failure{Class: "ambiguous"}
	}
	if failure != nil && conn != nil {
		_ = conn.Close()
		conn = nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if halfOpen {
		h.testing = false
	}
	if probe {
		h.probing = false
	}
	now := r.now()
	elapsed := now.Sub(started) + preflight
	if failure == nil || failure.Class != "canceled" {
		h.attempts++
		if !probe {
			h.passiveWindow.observe(now, failure == nil)
		}
	}
	if !probe {
		state.observeDestination(now, c, dst, elapsed, failure)
	}
	if failure == nil {
		if c, ok := conn.(TimedConn); ok {
			h.timing = c.SetupTiming()
			h.overhead = max(0, elapsed-h.timing.Service-h.timing.SOCKS)
		}
		h.observe(now, elapsed)
		h.consecutive = 0
		h.openUntil = time.Time{}
		h.healthWindow.observe(now, true)
	} else {
		h.failureClass = failure.Class
		h.failureStage = failure.Stage
		if failure.Class == "upstream_authentication" || failure.Class == "attachment_identity" {
			h.quarantined = true
		}
		if failure.Retry && (failure.Class == "transport" || failure.Class == "timeout") {
			h.consecutive++
			h.healthWindow.observe(now, false)
			if !h.openUntil.IsZero() || h.consecutive >= state.config.Health.FailureThreshold {
				h.openUntil = now.Add(state.config.Health.RecoveryInterval)
			}
		}
	}
	return conn, failure
}

func (r *Router) probeLoop() {
	round := 0
	for {
		r.mu.Lock()
		state := r.state
		r.mu.Unlock()
		delay := time.Second
		if state != nil && len(state.config.Health.ProbeTargets) > 0 {
			delay = time.Duration(float64(state.config.Health.Interval) * (.8 + rand.Float64()*.4))
		}
		timer := time.NewTimer(delay)
		var updated <-chan struct{}
		if state != nil {
			updated = state.probeCtx.Done()
		}
		select {
		case <-updated:
			timer.Stop()
			continue
		case <-r.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if state == nil || !state.config.Enabled || len(state.config.Health.ProbeTargets) == 0 ||
			r.now().Sub(time.Unix(0, r.lastActive.Load())) > 5*time.Minute {
			continue
		}
		parallel := make(chan struct{}, 2)
		var probes sync.WaitGroup
		target, _ := parseProbe(state.config.Health.ProbeTargets[round%len(state.config.Health.ProbeTargets)])
		round++
		for _, c := range r.candidates(state) {
			select {
			case parallel <- struct{}{}:
			case <-r.ctx.Done():
				probes.Wait()
				return
			}
			if !state.decide(target.destination, target.destination.IP(), r.now()).permits(c.ID()) {
				<-parallel
				continue
			}
			h, halfOpen := r.admit(state, c, true)
			if h == nil {
				<-parallel
				continue
			}
			probes.Go(func() {
				defer func() { <-parallel }()
				conn, _ := r.try(state.probeCtx, state, c, h, target.destination, true, halfOpen, 0, time.Time{})
				if conn == nil {
					return
				}
				defer conn.Close()
				if target.https == nil {
					r.mu.Lock()
					h.lastProbe = r.now()
					r.mu.Unlock()
					return
				}
				elapsed, err := measureHTTPS(state.probeCtx, conn, target.https, state.config.Failover.AttemptTimeout)
				if err == nil {
					r.mu.Lock()
					h.httpsTTFB = elapsed
					h.lastProbe = r.now()
					r.mu.Unlock()
				}
			})
		}
		probes.Wait()
	}
}

func affinityKey(r Routing, d Destination) string {
	if r.AffinityScope == "group" {
		return ""
	}
	return hostKey(d)
}
