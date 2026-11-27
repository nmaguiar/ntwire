package client

import (
	"context"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

const relayTrialFocusLimit = 60 * time.Second

// One parent observer chooses a lane to measure at a time. All lanes still
// contribute passive forwarding counters to the shared capacity estimate.
type relayTrialCoordinator struct {
	lanes     map[*connectionNetwork]*relayTrialLane
	focus     *relayTrialLane
	cursor    int
	revision  uint64
	probe     chan relayTrialProbe
	pending   bool
	nextProbe time.Time
}

type relayTrialLane struct {
	network        *connectionNetwork
	trial          adaptiveTrial
	prior          adaptiveFeedbackSample
	local          forwardingCounters
	demand         bool
	credit         uint64
	focusedAt      time.Time
	lastDemand     time.Time
	rtt            time.Duration
	samples        int
	probes         int
	carrierRTT     time.Duration
	carrierSamples int
	lastRTT        time.Duration
}

type relayTrialProbe struct {
	lane              *relayTrialLane
	path              string
	epoch, generation uint64
	started           time.Time
	rtt               time.Duration
}

func newRelayTrialCoordinator() *relayTrialCoordinator {
	return &relayTrialCoordinator{
		lanes: make(map[*connectionNetwork]*relayTrialLane),
		probe: make(chan relayTrialProbe, 1),
	}
}

func (o *relayTrialCoordinator) close() {
	if o.focus != nil && o.focus.trial.release != nil {
		o.focus.trial.release()
		o.focus.trial.release = nil
	}
}

func (o *relayTrialCoordinator) gap() {
	if o.focus != nil {
		o.focus.prior = adaptiveFeedbackSample{}
		o.focus.clearSamples()
	}
}

func (o *relayTrialCoordinator) tick(ctx context.Context, parent *connectionNetwork, now time.Time) {
	select {
	case sample := <-o.probe:
		o.pending = false
		if f := o.focus; f == sample.lane && !f.prior.at.IsZero() && !sample.started.Before(f.prior.at) &&
			f.prior.peer.Primary == sample.path && f.prior.epoch == sample.epoch && f.prior.peer.AuthGeneration == sample.generation {
			f.probes++
			if sample.rtt > 0 {
				f.rtt += sample.rtt
				f.samples++
			}
		}
	default:
	}
	f := o.focus
	if f == nil || ctx.Err() != nil {
		return
	}
	a := f.network.adaptive
	current := a.laneTraffic()
	if current.offered >= f.local.offered && current.received >= f.local.received && current != f.local {
		f.lastDemand = now
		delta := current.offered - f.local.offered + current.received - f.local.received
		f.credit = min(adaptiveTunnelProbeBytes, f.credit+min(delta, adaptiveTunnelProbeBytes))
	}
	f.local = current
	if now.Sub(f.lastDemand) >= 2*adaptiveFeedbackInterval {
		o.finishFocus(ctx, parent, now, true)
		return
	}
	path, epoch, _ := a.bind.LaneState(a.lane)
	info, _, _ := a.credentials()
	if f.prior.epoch == epoch && f.prior.peer.Primary == path && f.prior.peer.AuthGeneration == info.AuthGeneration {
		if rtt := a.carrierRTT(info.LaneID, path); rtt > 0 && rtt != f.lastRTT {
			f.lastRTT = rtt
			f.carrierRTT += rtt
			f.carrierSamples++
		}
	}
	if o.pending || now.Before(o.nextProbe) || f.credit < adaptiveTunnelProbeBytes || !a.laneReady(true) {
		return
	}
	if !parent.adaptive.tunnelProbe.CompareAndSwap(false, true) {
		return
	}
	f.credit = 0
	if path == protocol.CarrierWSS {
		a.ws.RequestPeerRTT()
	}
	o.pending = true
	o.nextProbe = now.Add(adaptiveTunnelProbeInterval)
	go func(sample relayTrialProbe) {
		sample.rtt = f.network.tunnelRTT(ctx)
		parent.adaptive.tunnelProbe.Store(false)
		o.probe <- sample
	}(relayTrialProbe{lane: f, path: path, epoch: epoch, generation: info.AuthGeneration, started: now})
}

func (o *relayTrialCoordinator) finishFocus(ctx context.Context, parent *connectionNetwork, now time.Time, restore bool) {
	if f := o.focus; f != nil {
		if restore && !f.trial.started.IsZero() {
			f.network.adaptive.advanceTrialOn(ctx, &f.trial, now, true, parent.adaptive)
		}
		o.close()
		f.prior = adaptiveFeedbackSample{}
		f.clearSamples()
		f.lastRTT, f.credit = 0, 0
		o.focus = nil
	}
}

func (f *relayTrialLane) clearSamples() {
	f.rtt, f.samples, f.probes = 0, 0, 0
	f.carrierRTT, f.carrierSamples = 0, 0
}

func (o *relayTrialCoordinator) observe(ctx context.Context, parent *connectionNetwork, p adaptiveParentSample) {
	now := p.anchor.at
	if o.revision != p.revision {
		// Roster changes invalidate any comparison measured across them.
		stillOwned := o.focus != nil && o.focus.network == parent
		for _, child := range p.children {
			stillOwned = stillOwned || (o.focus != nil && o.focus.network == child.lane)
		}
		o.finishFocus(ctx, parent, now, stillOwned)
		o.revision = p.revision
	}
	samples := make(map[*connectionNetwork]adaptiveFeedbackSample, 1+len(p.children))
	order := make([]*connectionNetwork, 0, 1+len(p.children))
	anchor := p.anchor
	anchor.local = p.anchorLocal
	samples[parent], order = anchor, append(order, parent)
	for _, child := range p.children {
		s := adaptiveFeedbackSample{at: now, epoch: child.epoch, local: child.local, peer: child.peer}
		a := child.lane.adaptive
		if child.primary == protocol.CarrierWSS {
			s.queue, s.backlogged = a.ws.QueuePerformance(), a.ws.PeerBacklogged("remote")
		} else if a.quic != nil && child.primary == protocol.CarrierQUIC {
			s.quic = a.quic.bind.Stats()
		}
		samples[child.lane], order = s, append(order, child.lane)
	}
	for n := range o.lanes {
		if _, live := samples[n]; !live {
			delete(o.lanes, n)
		}
	}
	for _, n := range order {
		s := samples[n]
		f := o.lanes[n]
		if f == nil {
			o.lanes[n] = &relayTrialLane{network: n, local: s.local, trial: adaptiveTrial{parallelRelays: true}}
		} else if f != o.focus {
			f.demand = s.local != f.local
			f.local = s.local
		}
	}
	if o.focus == nil {
		for range len(order) {
			i := o.cursor % len(order)
			o.cursor = (i + 1) % len(order)
			f := o.lanes[order[i]]
			a := f.network.adaptive
			if f.demand && !now.Before(f.trial.next) && a.wssLost != nil && a.laneReady(true) {
				f.lastDemand, f.focusedAt = now, now
				o.focus = f
				break
			}
		}
	}
	f := o.focus
	if f == nil {
		return
	}
	s := samples[f.network]
	a := f.network.adaptive
	if !f.prior.at.IsZero() && f.prior.peer.AuthGeneration != s.peer.AuthGeneration && !f.trial.started.IsZero() {
		o.finishFocus(ctx, parent, now, true)
		return
	}
	if w, ok := adaptiveWindow(f.prior, s); ok {
		w.TunnelRTTProbes = f.probes
		if f.samples != 0 {
			w.TunnelRTT, w.TunnelRTTSamples = f.rtt/time.Duration(f.samples), f.samples
		}
		if f.carrierSamples != 0 {
			w.RTT, w.RTTSamples = f.carrierRTT/time.Duration(f.carrierSamples), f.carrierSamples
		}
		a.measurements.record(s.peer.AuthGeneration, w)
	}
	f.prior = s
	f.clearSamples()
	active := !f.trial.started.IsZero()
	a.advanceTrialOn(ctx, &f.trial, now, false, parent.adaptive)
	if (active && f.trial.started.IsZero()) ||
		(f.trial.started.IsZero() && now.Sub(f.focusedAt) >= relayTrialFocusLimit) {
		o.finishFocus(ctx, parent, now, false)
	}
}
