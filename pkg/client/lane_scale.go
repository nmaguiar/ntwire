package client

import (
	"context"
	"errors"
	"math"
	"math/rand/v2"
	"slices"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

const (
	laneScaleObservation = 30 * time.Second
	laneScaleTrialLimit  = 2 * laneScaleObservation
	laneScaleIdle        = 2 * time.Minute
	laneScaleCooldown    = 5 * time.Minute
	laneScaleMinBPS      = 128 * 1024
	laneScaleMinWindows  = 5
)

type LaneScalingStatus struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

type laneScaleSample struct {
	parent   adaptiveParentSample
	flows    int
	pressure bool
}

type laneScaleRun struct {
	duration           time.Duration
	windows            int
	flows              float64
	up, down           DirectionPerformance
	childUp, childDown uint64
}

// Accumulate time-weighted rates from the same set of authorized peers.
func (r *laneScaleRun) add(elapsed time.Duration, flows int, window AdaptivePerformanceWindow, childUp, childDown uint64) {
	seconds := elapsed.Seconds()
	r.duration += elapsed
	r.windows++
	r.flows += float64(flows) * seconds
	if d := window.Upload; d != nil {
		r.up.OfferedBPS += d.OfferedBPS * seconds
		r.up.DeliveredBPS += d.DeliveredBPS * seconds
	}
	if d := window.Download; d != nil {
		r.down.OfferedBPS += d.OfferedBPS * seconds
		r.down.DeliveredBPS += d.DeliveredBPS * seconds
	}
	r.childUp += childUp
	r.childDown += childDown
}

func (r laneScaleRun) observed() bool {
	return r.duration >= laneScaleObservation && r.windows >= laneScaleMinWindows
}

func (r laneScaleRun) qualifiesAgainst(base laneScaleRun) bool {
	if !r.observed() || !base.observed() {
		return false
	}
	seconds, baseSeconds := r.duration.Seconds(), base.duration.Seconds()
	flows := base.flows / baseSeconds
	if math.Abs(r.flows/seconds-flows) > math.Max(1, 0.2*flows) {
		return false
	}
	check := func(before, after DirectionPerformance, childBytes uint64) (compatible, improved bool) {
		offered, previous := after.OfferedBPS/seconds, before.OfferedBPS/baseSeconds
		if max(offered, previous) < laneScaleMinBPS {
			return true, false
		}
		// Comparable offered load protects against mistaking a change in
		// application demand for a gain from an additional peer.
		if offered < previous*0.85 || offered > previous*1.15 {
			return false, false
		}
		delivered, old := after.DeliveredBPS/seconds, before.DeliveredBPS/baseSeconds
		childBPS := 8 * float64(childBytes) / seconds
		return delivered >= old*0.95, childBPS >= laneScaleMinBPS && old >= laneScaleMinBPS && delivered >= old*1.15
	}
	upOK, upGain := check(base.up, r.up, r.childUp)
	downOK, downGain := check(base.down, r.down, r.childDown)
	return upOK && downOK && (upGain || downGain)
}

type laneScaleGovernor struct {
	before          laneScaleSample
	baselineCohort  adaptiveParentSample
	baseline, trial laneScaleRun
	state           LaneScalingStatus
	child           string
	kept            []string
	maxLanes        int
	trialStarted    time.Time
	lastDemand      time.Time
	unavailable     map[string]time.Time
	retryAt         time.Time
	releaseTrial    func()
}

func newLaneScaleGovernor(n *connectionNetwork) *laneScaleGovernor {
	info := n.response.Adaptive
	if info == nil || info.MaxLanes < 2 || !info.Performance {
		return nil
	}
	return &laneScaleGovernor{maxLanes: info.MaxLanes, state: LaneScalingStatus{State: "observing", Reason: "waiting for sustained WSS pressure"}}
}

func laneScaleComparison(before, after adaptiveParentSample, trial string) (window AdaptivePerformanceWindow, childUp, childDown uint64, ok bool) {
	if len(after.children) == 0 {
		if len(before.children) != 0 || before.revision != after.revision || trial != "" {
			return window, 0, 0, false
		}
		window, ok = adaptiveWindow(before.anchor, after.anchor)
		return window, 0, 0, ok
	}
	window, ok = adaptiveSharedWindow(before, after)
	if !ok || trial == "" {
		return window, 0, 0, ok
	}
	for i, next := range after.children {
		if next.lane.response.Adaptive.LaneID == trial {
			prior := before.children[i].peer
			return window, next.peer.ReceivedBytes - prior.ReceivedBytes, next.peer.OfferedBytes - prior.OfferedBytes, true
		}
	}
	return window, 0, 0, false
}

func sameLaneScaleCohort(baseline, next adaptiveParentSample, trial string) bool {
	if baseline.anchor.epoch != next.anchor.epoch || baseline.anchor.peer.PathEpoch != next.anchor.peer.PathEpoch ||
		baseline.anchor.peer.Primary != next.anchor.peer.Primary || baseline.anchor.peer.AuthGeneration != next.anchor.peer.AuthGeneration ||
		len(baseline.children)+1 != len(next.children) {
		return false
	}
	i := 0
	for _, lane := range next.children {
		if lane.lane.response.Adaptive.LaneID == trial {
			continue
		}
		if i >= len(baseline.children) {
			return false
		}
		previous := baseline.children[i]
		if previous.lane != lane.lane || previous.epoch != lane.epoch || previous.peer.Primary != lane.peer.Primary ||
			previous.peer.PathEpoch != lane.peer.PathEpoch {
			return false
		}
		i++
	}
	return i == len(baseline.children)
}

// observe returns whether to open a canary. A child is kept only after
// matched directional delivery measurements over both observation periods.
func (g *laneScaleGovernor) observe(s laneScaleSample) bool {
	previous := g.before
	g.before = s
	window, childUp, childDown, ok := laneScaleComparison(previous.parent, s.parent, g.child)
	now := s.parent.anchor.at
	if g.state.State == "trial" {
		if !sameLaneScaleCohort(g.baselineCohort, s.parent, g.child) {
			g.drain("an existing lane changed during the canary")
			return false
		}
		if !ok {
			g.trial = laneScaleRun{}
			return false
		}
		g.trial.add(now.Sub(previous.parent.anchor.at), s.flows, window, childUp, childDown)
		if g.trial.observed() {
			if g.trial.qualifiesAgainst(g.baseline) {
				g.releaseExploration()
				g.kept = append(g.kept, g.child)
				g.child = ""
				g.baseline = laneScaleRun{}
				g.baselineCohort = adaptiveParentSample{}
				g.state = LaneScalingStatus{State: "keeping", Reason: "aggregate delivered goodput improved at comparable demand"}
				g.lastDemand = now
			} else {
				g.drain("canary did not demonstrate a comparable delivery gain")
			}
		}
		return false
	}
	demand := window.Upload != nil && window.Upload.OfferedBPS >= laneScaleMinBPS ||
		window.Download != nil && window.Download.OfferedBPS >= laneScaleMinBPS
	if !ok || !s.pressure || !previous.pressure || !demand || s.flows < 2 || previous.flows < 2 ||
		len(s.parent.children) != len(g.kept) || len(g.kept)+1 >= g.maxLanes ||
		g.child != "" || now.Before(g.retryAt) {
		g.baseline = laneScaleRun{}
		return false
	}
	g.baseline.add(now.Sub(previous.parent.anchor.at), s.flows, window, 0, 0)
	return g.baseline.observed()
}

func (g *laneScaleGovernor) invalidate() {
	g.gap()
	if g.state.State == "trial" {
		g.drain("authorization or carrier changed during the canary")
	}
}

func (g *laneScaleGovernor) gap() {
	g.before, g.trial = laneScaleSample{}, laneScaleRun{}
	if g.state.State != "trial" {
		g.baseline = laneScaleRun{}
		g.baselineCohort = adaptiveParentSample{}
	}
}

func (g *laneScaleGovernor) startChild(id string, now time.Time) {
	g.child = id
	g.trialStarted, g.lastDemand = now, now
	g.baselineCohort = g.before.parent
	g.trial, g.before = laneScaleRun{}, laneScaleSample{}
	g.state = LaneScalingStatus{State: "trial", Reason: "measuring aggregate delivery with one additional lane"}
}

func (g *laneScaleGovernor) drain(reason string) {
	g.releaseExploration()
	g.state = LaneScalingStatus{State: "draining", Reason: reason}
	g.before, g.baseline, g.trial = laneScaleSample{}, laneScaleRun{}, laneScaleRun{}
	g.baselineCohort = adaptiveParentSample{}
	g.retryAt = time.Time{}
}

func (g *laneScaleGovernor) cooldown(now time.Time, reason string) {
	g.releaseExploration()
	g.child = ""
	g.gap()
	g.state = LaneScalingStatus{State: "cooldown", Reason: reason}
	g.retryAt = now.Add(laneScaleCooldown)
}

func (g *laneScaleGovernor) releaseExploration() {
	if g.releaseTrial != nil {
		g.releaseTrial()
		g.releaseTrial = nil
	}
}

func (g *laneScaleGovernor) tick(now time.Time, busy bool, connected func(string) bool) {
	if busy {
		g.lastDemand = now
	}
	switch g.state.State {
	case "trial":
		if now.Sub(g.trialStarted) >= laneScaleTrialLimit {
			g.drain("canary expired without comparable observations")
		}
	case "cooldown":
		if !now.Before(g.retryAt) {
			g.state = LaneScalingStatus{State: "observing", Reason: "waiting for sustained WSS pressure"}
		}
	}
	if g.child != "" || len(g.kept) == 0 {
		return
	}
	if now.Sub(g.lastDemand) >= laneScaleIdle {
		g.child = g.kept[len(g.kept)-1]
		g.drain("low demand persisted")
		return
	}
	for _, id := range g.kept {
		if connected(id) {
			delete(g.unavailable, id)
		} else if started, ok := g.unavailable[id]; !ok {
			if g.unavailable == nil {
				g.unavailable = make(map[string]time.Time)
			}
			g.unavailable[id] = now
		} else if now.Sub(started) >= laneScaleObservation {
			g.child = id
			g.drain("child carrier remained unavailable")
			return
		}
	}
}

func (c *Connection) laneScaleFlowCount(n *connectionNetwork) (flows int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.network != n {
		return 0
	}
	flows = n.activeFlows
	for _, lane := range c.childLanes {
		flows += lane.activeFlows
	}
	return
}

func (c *Connection) publishLaneScaling(n *connectionNetwork, status LaneScalingStatus) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed && c.network == n {
		n.laneScaling = status
	}
}

func (c *Connection) tickLaneScale(ctx context.Context, n *connectionNetwork, g *laneScaleGovernor, now time.Time, busy bool) {
	c.mu.Lock()
	g.tick(now, busy, func(id string) bool {
		child := c.childLanes[id]
		return c.network == n && child != nil && child.adaptive.laneReady(false)
	})
	c.mu.Unlock()
	if g.state.State == "draining" && !now.Before(g.retryAt) {
		err := c.retireAdaptiveLaneFor(ctx, n, g.child)
		switch {
		case err == nil || errors.Is(err, errChildUnavailable):
			g.kept = slices.DeleteFunc(g.kept, func(id string) bool { return id == g.child })
			delete(g.unavailable, g.child)
			g.cooldown(time.Now(), "child drained")
			g.retryAt = g.retryAt.Add(time.Duration(rand.Int64N(int64(30 * time.Second))))
		case errors.Is(err, errLaneDraining):
			// A socket already owns the lane. No remote request was sent.
		default:
			g.retryAt = time.Now().Add(adaptiveFeedbackInterval)
		}
	}
	c.publishLaneScaling(n, g.state)
}

func (c *Connection) measureLaneScale(ctx context.Context, n *connectionNetwork, g *laneScaleGovernor,
	parent adaptiveParentSample, info protocol.AdaptiveSession) {
	flows := c.laneScaleFlowCount(n)
	pressure, connected := n.adaptive.ws.PeerQueuePressure("remote")
	observation := laneScaleSample{parent: parent, flows: flows,
		pressure: parent.anchor.peer.Primary == protocol.CarrierWSS && connected && (pressure || parent.anchor.peer.WSSBacklogged)}
	for _, lane := range parent.children {
		id := lane.lane.response.Adaptive.LaneID
		if !slices.Contains(g.kept, id) && id != g.child {
			g.gap()
			return
		}
	}
	if g.observe(observation) && n.adaptive.exploration.CompareAndSwap(false, true) {
		g.releaseTrial = func() { n.adaptive.exploration.Store(false) }
		c.publishLaneScaling(n, LaneScalingStatus{State: "qualifying", Reason: "sustained WSS pressure with concurrent demand"})
		next, err := c.openAdaptiveLaneFor(ctx, n, info.AuthGeneration, parent.revision)
		if err == nil {
			g.startChild(next.response.Adaptive.LaneID, time.Now())
		} else {
			g.cooldown(time.Now(), "child did not qualify")
			g.retryAt = g.retryAt.Add(time.Duration(rand.Int64N(int64(30 * time.Second))))
		}
	}
	if g.state.State == "draining" {
		c.tickLaneScale(ctx, n, g, time.Now(), true)
		return
	}
	c.publishLaneScaling(n, g.state)
}
