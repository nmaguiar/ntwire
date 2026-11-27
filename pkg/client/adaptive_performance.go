package client

import (
	"context"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nmaguiar/ntwire/internal/localproxy"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

const (
	adaptiveFeedbackInterval = 5 * time.Second
	adaptiveFeedbackTimeout  = 2 * time.Second
	adaptiveHistoryLifetime  = 60 * time.Second
	adaptiveHistoryWindows   = 12
)

// DirectionPerformance describes bytes accepted at each end of one tunnel
// direction during a busy measurement window.
type DirectionPerformance struct {
	OfferedBPS   float64 `json:"offered_bps"`
	DeliveredBPS float64 `json:"delivered_bps"`
}

type AdaptivePerformanceWindow struct {
	Path               string                `json:"path"`
	PathEpoch          uint64                `json:"path_epoch,omitempty"`
	End                time.Time             `json:"end"`
	Upload             *DirectionPerformance `json:"upload,omitempty"`
	Download           *DirectionPerformance `json:"download,omitempty"`
	RTT                time.Duration         `json:"carrier_rtt,omitempty"`
	RTTSamples         int                   `json:"rtt_samples,omitempty"`
	TunnelRTT          time.Duration         `json:"tunnel_rtt,omitempty"`
	TunnelRTTSamples   int                   `json:"tunnel_rtt_samples,omitempty"`
	TunnelRTTProbes    int                   `json:"tunnel_rtt_probes,omitempty"`
	WSSQueueP95        time.Duration         `json:"wss_queue_p95,omitempty"`
	UploadBacklogged   bool                  `json:"upload_backlogged,omitempty"`
	DownloadBacklogged bool                  `json:"download_backlogged,omitempty"`
	QUICSent           uint64                `json:"quic_sent,omitempty"`
	QUICDropped        uint64                `json:"quic_send_queue_drops,omitempty"`
	generation         uint64
}

type AdaptivePerformance struct {
	FeedbackRequests    int                             `json:"feedback_requests"`
	FeedbackStatus      string                          `json:"feedback_status"`
	Decision            *AdaptivePathDecision           `json:"observe_only_decision,omitempty"`
	Trial               *AdaptiveTrialStatus            `json:"carrier_trial,omitempty"`
	Windows             []AdaptivePerformanceWindow     `json:"windows,omitempty"`
	ObservedUploadBPS   float64                         `json:"observed_upload_bps,omitempty"`
	ObservedDownloadBPS float64                         `json:"observed_download_bps,omitempty"`
	UploadWindows       int                             `json:"upload_windows,omitempty"`
	DownloadWindows     int                             `json:"download_windows,omitempty"`
	Capacity            *AdaptiveCapacityEvidence       `json:"capacity_evidence,omitempty"`
	SharedCapacity      *AdaptiveSharedCapacityEvidence `json:"shared_capacity_evidence,omitempty"`
}

type adaptiveTraffic struct {
	offered, received atomic.Uint64
}

type trackedAdaptiveConn struct {
	net.Conn
	traffic *adaptiveTraffic
}

func trackAdaptiveTraffic(conn net.Conn, traffic *adaptiveTraffic) net.Conn {
	if traffic == nil {
		return conn
	}
	return &trackedAdaptiveConn{Conn: conn, traffic: traffic}
}

func (c *trackedAdaptiveConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.traffic.received.Add(uint64(n))
	}
	return n, err
}

func (c *trackedAdaptiveConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.traffic.offered.Add(uint64(n))
	}
	return n, err
}

func (c *trackedAdaptiveConn) CloseWrite() error {
	return localproxy.CloseWrite(c.Conn)
}

type forwardingCounters struct {
	offered, received uint64
}

// Adaptive peers consume one shared delivery history. Adding a route does
// not give it a separate capacity budget.
type adaptivePerformanceHistory struct {
	mu               sync.Mutex
	generation       uint64
	windows          [adaptiveHistoryWindows]AdaptivePerformanceWindow
	next, size       int
	feedbackRequests int
	feedbackStatus   string
	feedbackAt       time.Time
	trial            AdaptiveTrialStatus
	shared           adaptiveSharedHistory
}

func (h *adaptivePerformanceHistory) setTrial(status AdaptiveTrialStatus) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.trial = status
}

func (h *adaptivePerformanceHistory) trialReason() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.trial.Reason != "" {
		return h.trial.Reason
	}
	return h.trial.State
}

func (h *adaptivePerformanceHistory) renew(generation uint64, sameGrants bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.generation = generation
	h.shared = adaptiveSharedHistory{}
	if !sameGrants {
		h.next, h.size = 0, 0
		h.feedbackRequests, h.feedbackStatus, h.feedbackAt = 0, "", time.Time{}
		h.trial = AdaptiveTrialStatus{}
		clear(h.windows[:])
	}
}

// Called under mu. An observation started before renewal cannot add to the
// new generation's history, even if its request completed successfully.
func (h *adaptivePerformanceHistory) accepts(generation uint64) bool {
	if h.generation == 0 {
		h.generation = generation
	}
	return h.generation == generation
}

func (h *adaptivePerformanceHistory) feedback(generation uint64, now time.Time, reason string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.accepts(generation) {
		return
	}
	h.feedbackRequests++
	h.feedbackStatus, h.feedbackAt = reason, now
}

func (h *adaptivePerformanceHistory) record(generation uint64, w AdaptivePerformanceWindow) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.accepts(generation) {
		return
	}
	w.generation = generation
	h.windows[h.next] = w
	h.next = (h.next + 1) % len(h.windows)
	h.size = min(h.size+1, len(h.windows))
}

func (h *adaptivePerformanceHistory) snapshot(now time.Time, generation uint64) *AdaptivePerformance {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.generation != generation {
		return nil
	}
	var out AdaptivePerformance
	if h.trial.State != "" {
		trial := h.trial
		out.Trial = &trial
	}
	if age := now.Sub(h.feedbackAt); age >= 0 && age < adaptiveHistoryLifetime {
		out.FeedbackRequests, out.FeedbackStatus = h.feedbackRequests, h.feedbackStatus
	}
	var uploadWeight, downloadWeight float64
	for i := range h.size {
		w := h.windows[(h.next-h.size+len(h.windows)+i)%len(h.windows)]
		age := now.Sub(w.End)
		if age < 0 || age >= adaptiveHistoryLifetime {
			continue
		}
		weight := math.Exp2(-age.Seconds() / 15)
		if w.Upload != nil {
			out.ObservedUploadBPS += w.Upload.DeliveredBPS * weight
			uploadWeight += weight
			out.UploadWindows++
			direction := *w.Upload
			w.Upload = &direction
		}
		if w.Download != nil {
			out.ObservedDownloadBPS += w.Download.DeliveredBPS * weight
			downloadWeight += weight
			out.DownloadWindows++
			direction := *w.Download
			w.Download = &direction
		}
		out.Windows = append(out.Windows, w)
	}
	out.SharedCapacity = h.shared.evidence(now)
	if len(out.Windows) == 0 && out.FeedbackRequests == 0 && out.Trial == nil && out.SharedCapacity == nil {
		return nil
	}
	if uploadWeight > 0 {
		out.ObservedUploadBPS /= uploadWeight
	}
	if downloadWeight > 0 {
		out.ObservedDownloadBPS /= downloadWeight
	}
	if len(out.Windows) > 0 {
		latest := out.Windows[len(out.Windows)-1]
		if latest.generation == generation {
			out.Capacity = adaptiveCapacityEvidence(now, out.Windows)
		}
	}
	return &out
}

type adaptiveFeedbackSample struct {
	at         time.Time
	epoch      uint64
	local      forwardingCounters
	peer       protocol.CarrierPerformance
	queue      wstransport.QueuePerformance
	quic       wstransport.QUICStats
	backlogged bool
}

func adaptiveWindow(before, after adaptiveFeedbackSample) (AdaptivePerformanceWindow, bool) {
	if before.at.IsZero() || before.epoch != after.epoch ||
		after.local.offered < before.local.offered ||
		after.local.received < before.local.received {
		return AdaptivePerformanceWindow{}, false
	}
	localSeconds := after.at.Sub(before.at).Seconds()
	rates, ok := adaptivePeerRates(before.peer, after.peer, localSeconds)
	if !ok {
		return AdaptivePerformanceWindow{}, false
	}
	result := adaptiveDeliveryWindow(before, after, rates, localSeconds)
	if result.Path == protocol.CarrierWSS {
		result.WSSQueueP95 = queueP95(after.queue.Delta(before.queue))
		result.UploadBacklogged = after.backlogged
		result.DownloadBacklogged = after.peer.WSSBacklogged
	} else if result.Path == protocol.CarrierQUIC {
		delta := after.quic.Delta(before.quic)
		result.QUICSent, result.QUICDropped = delta.Sent, delta.SendDrops
	}
	return result, result.Upload != nil || result.Download != nil
}

type forwardingRates struct {
	offered, received float64
}

func adaptivePeerRates(before, after protocol.CarrierPerformance, localSeconds float64) (forwardingRates, bool) {
	if before.PathEpoch != after.PathEpoch || before.AuthGeneration != after.AuthGeneration ||
		after.Primary == "" || before.Primary != after.Primary || after.ElapsedUS <= before.ElapsedUS ||
		after.ReceivedBytes < before.ReceivedBytes || after.OfferedBytes < before.OfferedBytes {
		return forwardingRates{}, false
	}
	peerSeconds := float64(after.ElapsedUS-before.ElapsedUS) / 1e6
	// A control stall or suspended worker makes the two deltas incomparable.
	if localSeconds < 4 || localSeconds > 8 || math.Abs(localSeconds-peerSeconds) > 1 {
		return forwardingRates{}, false
	}
	return forwardingRates{
		offered:  8 * float64(after.OfferedBytes-before.OfferedBytes) / peerSeconds,
		received: 8 * float64(after.ReceivedBytes-before.ReceivedBytes) / peerSeconds,
	}, true
}

func adaptiveDeliveryWindow(before, after adaptiveFeedbackSample, peer forwardingRates, localSeconds float64) AdaptivePerformanceWindow {
	result := AdaptivePerformanceWindow{Path: after.peer.Primary, PathEpoch: after.epoch, End: after.at}
	if offered := after.local.offered - before.local.offered; offered > 0 {
		result.Upload = &DirectionPerformance{OfferedBPS: 8 * float64(offered) / localSeconds, DeliveredBPS: peer.received}
	}
	if peer.offered > 0 {
		result.Download = &DirectionPerformance{OfferedBPS: peer.offered,
			DeliveredBPS: 8 * float64(after.local.received-before.local.received) / localSeconds}
	}
	return result
}

func queueP95(q *wstransport.QueuePerformance) time.Duration {
	if q == nil || q.SampledBatches == 0 {
		return 0
	}
	// The last bin is an overflow bin. Its lower edge is the available
	// bound when a sample exceeds the histogram.
	top := q.SampledBatches - q.SampledBatches/20
	var count uint64
	for i, n := range q.QueueResidence {
		count += n
		if count >= top {
			return time.Duration(1<<i) * time.Microsecond
		}
	}
	return 0
}

// The same set of local listeners and Smart Proxy grants contribute to the
// counters. Track the current stack before using listener counters which can
// outlive a reauthentication.
func (c *Connection) adaptiveTrafficSnapshot(n *connectionNetwork) (forwardingCounters, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.network != n {
		return forwardingCounters{}, false
	}
	return c.adaptiveTrafficLocked(n), true
}

func (c *Connection) adaptiveTrafficLocked(n *connectionNetwork) forwardingCounters {
	if n.response.Adaptive.RelayPerformance {
		total := n.adaptive.laneTraffic()
		for _, child := range c.childLanes {
			current := child.adaptive.laneTraffic()
			total.offered += current.offered
			total.received += current.received
		}
		return total
	}
	total := forwardingCounters{
		offered: n.adaptive.traffic.offered.Load(), received: n.adaptive.traffic.received.Load(),
	}
	for _, child := range c.childLanes {
		total.offered += child.adaptive.traffic.offered.Load()
		total.received += child.adaptive.traffic.received.Load()
	}
	for _, tunnel := range c.tunnels {
		total.offered += tunnel.toTunnel.Load()
		total.received += tunnel.fromTunnel.Load()
	}
	return total
}

func (a *adaptiveCarrierClient) laneTraffic() forwardingCounters {
	return forwardingCounters{
		offered:  a.traffic.offered.Load() + a.localTraffic.offered.Load(),
		received: a.traffic.received.Load() + a.localTraffic.received.Load(),
	}
}

func (c *Connection) observeAdaptivePerformance(n *connectionNetwork, stop <-chan struct{}) {
	a := n.adaptive
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	prior, current := adaptiveFeedbackSample{}, forwardingCounters{}
	var priorShared adaptiveParentSample
	var observedRoster uint64
	lastActive, nextPoll := time.Time{}, time.Time{}
	var lastRTT, rttTotal, tunnelRTTTotal time.Duration
	var rttSamples, tunnelRTTCount, tunnelProbeCount int
	var observedPath string
	var observedEpoch uint64
	var observedGeneration uint64
	var trial adaptiveTrial
	defer func() {
		if trial.release != nil {
			trial.release()
		}
	}()
	type tunnelObservation struct {
		path              string
		epoch, generation uint64
		started           time.Time
		rtt               time.Duration
	}
	probeResults := make(chan tunnelObservation, 1)
	var probePending bool
	var tunnelProbeCredit uint64
	var nextTunnelProbe time.Time
	var udpDemand udpProbeDemand
	feedbackEnabled := n.response.Adaptive.Performance
	trialEnabled := feedbackEnabled && a.wssLost != nil && !c.options.AdaptiveQUICDiagnostic
	var relayTrials *relayTrialCoordinator
	if trialEnabled && a.relay != nil && a.relay.performance {
		relayTrials = newRelayTrialCoordinator()
		defer relayTrials.close()
		trialEnabled = false
	}
	governor := newLaneScaleGovernor(n)
	if governor != nil {
		defer governor.releaseExploration()
	}
	ctx, cancelWorker := context.WithCancel(context.Background())
	defer cancelWorker()
	if feedbackEnabled || a.wssLost != nil {
		go func() {
			select {
			case <-stop:
			case <-c.stop:
			case <-ctx.Done():
			}
			cancelWorker()
		}()
	}
	var nextRecovery time.Time
	recoverUDP := func(path string, epoch uint64) {
		current, currentEpoch, _ := a.bind.LaneState(a.lane)
		if current != path || currentEpoch != epoch || time.Now().Before(nextRecovery) || ctx.Err() != nil {
			return
		}
		if a.recoverAdaptiveUDP(ctx, path) {
			if u := a.nativeUDP(path); u != nil && u.closed.Load() {
				a.bind.RemovePath(a.lane, path)
			}
			c.log.Info("adaptive lane recovered from native UDP failure", "carrier", path)
			trial.next = time.Now().Add(adaptiveTrialCooldown)
		}
		nextRecovery = time.Now().Add(adaptiveRecoveryCooldown)
	}
	var wssLossUntil time.Time
	retryWSS := func(now time.Time) {
		if !now.Before(wssLossUntil) || ctx.Err() != nil {
			wssLossUntil = time.Time{}
			return
		}
		if now.Before(nextRecovery) {
			return
		}
		active, _, _ := a.bind.LaneState(a.lane)
		if _, err := a.ws.CarrierEndpoint("remote"); active != protocol.CarrierWSS || err == nil {
			wssLossUntil = time.Time{}
			return
		}
		if attempted, err := c.recoverAdaptiveWSS(ctx, a); attempted {
			nextRecovery = time.Now().Add(adaptiveRecoveryCooldown)
			if carrierControlDenied(err) {
				wssLossUntil = time.Time{}
				return
			}
			if active, _, _ := a.bind.LaneState(a.lane); active != "" && active != protocol.CarrierWSS {
				wssLossUntil = time.Time{}
				if until := nextRecovery.Add(adaptiveTrialCooldown); trial.next.Before(until) {
					trial.next = until
				}
			}
		}
	}
	for {
		select {
		case <-stop:
			return
		case <-c.stop:
			return
		case sample := <-probeResults:
			probePending = false
			if sample.path != observedPath || sample.epoch != observedEpoch || sample.generation != observedGeneration {
				continue
			}
			if !prior.at.IsZero() && !sample.started.Before(prior.at) {
				tunnelProbeCount++
				if sample.rtt > 0 {
					tunnelRTTTotal += sample.rtt
					tunnelRTTCount++
				}
			}
			if protocol.IsNativeUDPCarrier(sample.path) && ctx.Err() == nil {
				path, epoch, _ := a.bind.LaneState(a.lane)
				info, _, _ := a.credentials()
				if path != sample.path || epoch != sample.epoch || info.AuthGeneration != sample.generation {
					continue
				}
				if sample.rtt > 0 {
					udpDemand.misses = 0
					continue
				}
				udpDemand.misses = min(udpDemand.misses+1, adaptiveUDPMissLimit)
				if udpDemand.misses == adaptiveUDPMissLimit {
					recoverUDP(sample.path, sample.epoch)
				}
			}
		case loss := <-a.udpLost:
			recoverUDP(loss.path, loss.epoch)
		case lostAt := <-a.wssLost:
			wssLossUntil = lostAt.Add(adaptiveWSSHealthWindow)
			retryWSS(time.Now())
		case <-ticker.C:
			if !wssLossUntil.IsZero() {
				retryWSS(time.Now())
			}
			if !feedbackEnabled {
				continue
			}
			if relayTrials != nil {
				relayTrials.tick(ctx, n, time.Now())
			}
			observed, ok := c.adaptiveObservation(n)
			if !ok {
				return
			}
			if observedRoster != observed.revision {
				observedRoster = observed.revision
				prior, priorShared = adaptiveFeedbackSample{}, adaptiveParentSample{}
				info, _, _ := a.credentials()
				a.measurements.clearShared(info.AuthGeneration)
				if governor != nil {
					governor.gap()
				}
			}
			local := observed.local
			// Use the actual observation time if the worker missed a tick.
			now := time.Now()
			var traffic uint64
			if local.offered >= current.offered && local.received >= current.received {
				traffic = local.offered - current.offered + local.received - current.received
			}
			if local.offered > current.offered || local.received > current.received {
				lastActive = now
			}
			current = local
			idle := now.Sub(lastActive) >= adaptiveFeedbackInterval
			if governor != nil && trial.started.IsZero() {
				flows := c.laneScaleFlowCount(n)
				c.tickLaneScale(ctx, n, governor, now, !idle && flows >= 2)
			}
			trialIdle := idle || observed.children != 0
			if idle && prior.at.IsZero() && priorShared.anchor.at.IsZero() && !udpDemand.needsProbe(now) {
				if trialEnabled && !trial.started.IsZero() {
					a.advanceTrial(ctx, &trial, now, true)
				}
				rttTotal, rttSamples = 0, 0
				tunnelRTTTotal, tunnelRTTCount, tunnelProbeCount, tunnelProbeCredit = 0, 0, 0, 0
				continue
			}
			primary, epoch, ok := a.bind.LaneState(a.lane)
			if !ok || primary == "" {
				if trialEnabled && !trial.started.IsZero() {
					a.advanceTrial(ctx, &trial, now, trialIdle)
				}
				prior, priorShared = adaptiveFeedbackSample{}, adaptiveParentSample{}
				udpDemand = udpProbeDemand{}
				if governor != nil {
					governor.invalidate()
				}
				continue
			}
			if observedPath != primary || observedEpoch != epoch {
				if governor != nil {
					governor.invalidate()
				}
				prior, priorShared = adaptiveFeedbackSample{}, adaptiveParentSample{}
				observedPath, observedEpoch = primary, epoch
				udpDemand = udpProbeDemand{}
				lastRTT, rttTotal, rttSamples = 0, 0, 0
				tunnelRTTTotal, tunnelRTTCount, tunnelProbeCount, tunnelProbeCredit = 0, 0, 0, 0
			}
			info, bearer, _ := a.credentials()
			if observedGeneration != info.AuthGeneration {
				if governor != nil {
					governor.invalidate()
				}
				observedGeneration = info.AuthGeneration
				udpDemand = udpProbeDemand{}
				prior, priorShared, nextPoll = adaptiveFeedbackSample{}, adaptiveParentSample{}, time.Time{}
				lastRTT, rttTotal, rttSamples = 0, 0, 0
				tunnelRTTTotal, tunnelRTTCount, tunnelProbeCount, tunnelProbeCredit = 0, 0, 0, 0
			}
			if trialEnabled && primary == protocol.CarrierWSS && traffic >= 16<<10 && !a.ws.PeerBacklogged("remote") {
				a.ws.RequestPeerRTT()
			}
			if rtt := a.carrierRTT(info.LaneID, primary); rtt > 0 && rtt != lastRTT {
				lastRTT = rtt
				rttTotal += rtt
				rttSamples++
			}
			if trialIdle {
				tunnelProbeCredit = 0
			} else if trialEnabled && (info.RelaySelect || info.UDPSelect) {
				// Carry at most one probe's credit between busy ticks.
				tunnelProbeCredit = min(adaptiveTunnelProbeBytes, tunnelProbeCredit+min(traffic, adaptiveTunnelProbeBytes))
			}
			direct := protocol.IsNativeUDPCarrier(primary) && info.UDPSelect
			probeAvailable := !probePending && !now.Before(nextTunnelProbe) &&
				(primary != protocol.CarrierWSS || !a.ws.PeerBacklogged("remote"))
			healthProbe := direct && udpDemand.ready(now, traffic, probeAvailable)
			if probeAvailable && (tunnelProbeCredit == adaptiveTunnelProbeBytes || healthProbe) && a.tunnelProbe.CompareAndSwap(false, true) {
				probePending = true
				if direct {
					udpDemand.pending = false
				}
				tunnelProbeCredit = 0
				nextTunnelProbe = now.Add(adaptiveTunnelProbeInterval)
				go func(sample tunnelObservation) {
					sample.rtt = n.tunnelRTT(ctx)
					a.tunnelProbe.Store(false)
					probeResults <- sample
				}(tunnelObservation{path: primary, epoch: epoch, generation: info.AuthGeneration, started: now})
			}
			if now.Before(nextPoll) {
				if trialEnabled && !trial.started.IsZero() && (trialIdle || trial.elapsed(now)) {
					a.advanceTrial(ctx, &trial, now, trialIdle)
				}
				continue
			}
			nextPoll = now.Add(adaptiveFeedbackInterval)
			sample := adaptiveFeedbackSample{at: now, epoch: epoch, local: local}
			if primary == protocol.CarrierWSS {
				sample.queue = a.ws.QueuePerformance()
				sample.backlogged = a.ws.PeerBacklogged("remote")
			} else if primary == protocol.CarrierQUIC && a.quic != nil {
				sample.quic = a.quic.bind.Stats()
			}
			parent, err := c.pollAdaptiveParent(ctx, n, observed, sample, info, primary, bearer)
			sample = parent.anchor
			var feedbackStatus string
			switch {
			case err == errAdaptiveFeedbackChanged:
				feedbackStatus = "lane roster, path or authorization changed"
				prior, priorShared = adaptiveFeedbackSample{}, adaptiveParentSample{}
				a.measurements.clearShared(info.AuthGeneration)
				if governor != nil {
					governor.invalidate()
				}
			case err != nil:
				feedbackStatus = "peer feedback unavailable"
				prior, priorShared = adaptiveFeedbackSample{}, adaptiveParentSample{}
				a.measurements.clearShared(info.AuthGeneration)
				if governor != nil {
					governor.gap()
				}
			case len(parent.children) != 0:
				prior = adaptiveFeedbackSample{}
				feedbackStatus = "awaiting a comparable parent delivery window"
				if window, ok := adaptiveSharedWindow(priorShared, parent); ok {
					feedbackStatus = "recorded shared directional delivery"
					a.measurements.recordShared(info.AuthGeneration, parent, window)
					if window.Download != nil {
						idle, lastActive = false, now
					}
				} else {
					a.measurements.clearShared(info.AuthGeneration)
				}
				priorShared = adaptiveParentSample{}
				if !idle {
					priorShared = parent
				}
			default:
				priorShared = adaptiveParentSample{}
				a.measurements.clearShared(info.AuthGeneration)
				feedbackStatus = "awaiting a comparable demand window"
				if window, ok := adaptiveWindow(prior, sample); ok {
					feedbackStatus = "recorded directional delivery"
					if rttSamples > 0 {
						window.RTT, window.RTTSamples = rttTotal/time.Duration(rttSamples), rttSamples
					}
					if tunnelRTTCount > 0 {
						window.TunnelRTT, window.TunnelRTTSamples = tunnelRTTTotal/time.Duration(tunnelRTTCount), tunnelRTTCount
					}
					window.TunnelRTTProbes = tunnelProbeCount
					if relayTrials == nil {
						a.measurements.record(info.AuthGeneration, window)
					}
					if window.Download != nil {
						// Observe the sender's activity even if some of its
						// bytes have not reached the local application yet.
						idle = false
						lastActive = now
					}
				}
				if idle {
					prior = adaptiveFeedbackSample{}
				} else {
					prior = sample
				}
			}
			a.measurements.feedback(info.AuthGeneration, now, feedbackStatus)
			if relayTrials != nil {
				if err == nil {
					relayTrials.observe(ctx, n, parent)
				} else {
					relayTrials.gap()
				}
			}
			if governor != nil && err == nil {
				c.measureLaneScale(ctx, n, governor, parent, info)
			}
			if trialEnabled {
				a.advanceTrial(ctx, &trial, now, idle || observed.children != 0)
			}
			rttTotal, rttSamples = 0, 0
			tunnelRTTTotal, tunnelRTTCount, tunnelProbeCount = 0, 0, 0
		}
	}
}

// carrierRTT reads the existing carrier's RTT observation.
func (a *adaptiveCarrierClient) carrierRTT(lane, path string) time.Duration {
	switch path {
	case protocol.CarrierWSS:
		return a.ws.PeerRTT("remote")
	case protocol.CarrierQUIC:
		if a.quic != nil {
			return a.quic.bind.PeerRTT(lane)
		}
	case protocol.CarrierDirectUDP, protocol.CarrierAlternateUDP:
		if u := a.nativeUDP(path); u != nil {
			if qualified, rtt := u.state(); qualified {
				return rtt
			}
		}
	}
	if a.relay != nil {
		relay := a.relay.path(path)
		if (relay.id == path || path == protocol.CarrierRelayUDP) && time.Now().Before(relay.expires) {
			return relay.rtt
		}
	}
	return 0
}
