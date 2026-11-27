package egressrouter

import (
	"math"
	"net"
	"net/netip"
	"sync/atomic"
	"time"
)

const (
	pathPerformanceTTL = 15 * time.Second
	defaultRateBPS     = 8 * (8 << 20)
	defaultFlowBytes   = 16 << 10
	transferLimit      = 16 << 20
	asnTransferLimit   = 256
)

// PathPerformance carries coarse, advisory evidence for an already authorized
// connection. Observed rates describe delivery under demand.
type PathPerformance struct {
	ObservedAt  time.Time     `json:"observed_at"`
	QueueDelay  time.Duration `json:"queue_delay,omitempty"`
	ReadyLanes  int           `json:"ready_lanes,omitempty"`
	ActiveFlows int           `json:"active_flows,omitempty"`
	Upload      PathDirection `json:"upload,omitempty"`
	Download    PathDirection `json:"download,omitempty"`
}

type PathDirection struct {
	ObservedBPS float64 `json:"observed_bps,omitempty"`
	Pressured   bool    `json:"pressured,omitempty"`
}

type transferProfile struct {
	up, down float64
	asn      uint32
}

type transferEstimate struct {
	updated  time.Time
	samples  int
	up, down transferDirection
	response measurements
}

type transferDirection struct {
	bytes, rateBPS float64
	rateSamples    int
}

type asnTransferKey struct {
	member     MemberID
	generation string
	asn        uint32
}

func (e transferEstimate) fresh(now time.Time) bool {
	return e.samples >= 3 && !now.Before(e.updated) && now.Sub(e.updated) <= measurementTTL
}

func (d *transferDirection) observe(bytes uint64, elapsed time.Duration, initial bool) {
	size := float64(min(bytes, transferLimit))
	if initial {
		d.bytes = size
	} else {
		d.bytes += .2 * (size - d.bytes)
	}
	if bytes < 64<<10 || elapsed < 20*time.Millisecond {
		return
	}
	rate := min(8*float64(bytes)/elapsed.Seconds(), 10e9)
	if d.rateSamples == 0 {
		d.rateBPS = rate
	} else {
		d.rateBPS += .2 * (rate - d.rateBPS)
	}
	d.rateSamples = min(d.rateSamples+1, 32)
}

func (s *routeState) adaptiveProfile(now time.Time, decision Decision, dst Destination, candidates []ranked, excluded map[MemberID]bool) transferProfile {
	var p transferProfile
	if ip := dst.IP(); ip.IsValid() {
		p.asn, _ = s.lookupASN(ip, now)
	}
	var count float64
	for _, c := range candidates {
		if c.Dialer == nil || excluded[c.ID()] || !decision.permits(c.ID()) {
			continue
		}
		item := s.destinations[destinationKey(c.ID(), dst)]
		e := item.transfer
		if item.generation != c.Generation || !e.fresh(now) {
			e = s.asnTransfers[asnTransferKey{c.ID(), c.Generation, p.asn}]
		}
		if e.fresh(now) {
			p.up += e.up.bytes
			p.down += e.down.bytes
			count++
		}
	}
	if count != 0 {
		p.up /= count
		p.down /= count
	} else if s.transfers.fresh(now) {
		p.up, p.down = min(s.transfers.up.bytes, 64<<10), min(s.transfers.down.bytes, 64<<10)
	} else {
		p.up, p.down = defaultFlowBytes, defaultFlowBytes
	}
	return p
}

func (s *routeState) adaptiveScore(now time.Time, c ranked, h *memberHealth, dst Destination, profile transferProfile, setup time.Duration, measured bool) time.Duration {
	timeout := s.config.Failover.AttemptTimeout
	if !measured {
		setup = max(10*time.Millisecond, min(timeout/4, 150*time.Millisecond))
	}
	item := s.destinations[destinationKey(c.ID(), dst)]
	if item.generation != c.Generation {
		item = destinationObservation{}
	}
	if local, ok := score(now, item.measurements, item.outcomes, timeout); ok {
		setup = local
	} else if count, successes := item.outcomes.recent(now); count > 0 {
		setup += time.Duration(float64(timeout) * float64(count-successes) / float64(count))
	}
	asn := s.asnTransfers[asnTransferKey{c.ID(), c.Generation, profile.asn}]
	estimates := [...]transferEstimate{item.transfer, asn, h.transfer}
	p := PathPerformance{}
	if hint := c.Performance; hint != nil && !now.Before(hint.ObservedAt) && now.Sub(hint.ObservedAt) <= pathPerformanceTTL {
		p = *hint
	}
	lanes := max(1, min(p.ReadyLanes, 8))
	load := max(int(h.active.Load()), min(p.ActiveFlows, MaxConnections))
	pressure := min(time.Duration(load/lanes)*time.Millisecond, 150*time.Millisecond)
	if p.Upload.Pressured || p.Download.Pressured {
		pressure += 15 * time.Millisecond
	}
	transfer := max(
		transferTime(now, profile.up, estimates[:], p.Upload, false),
		transferTime(now, profile.down, estimates[:], p.Download, true),
	)
	response, _ := score(now, item.transfer.response, outcomeWindow{}, 0)
	return setup + min(response/2, 250*time.Millisecond) + min(max(p.QueueDelay, 0), 500*time.Millisecond) + pressure + transfer
}

func transferTime(now time.Time, bytes float64, estimates []transferEstimate, path PathDirection, download bool) time.Duration {
	rate := float64(defaultRateBPS)
	for _, estimate := range estimates {
		dir := estimate.up
		if download {
			dir = estimate.down
		}
		if estimate.fresh(now) && dir.rateSamples >= 3 {
			rate = dir.rateBPS
			break
		}
	}
	// A delivered floor becomes a conservative service estimate only while
	// the same path has sustained pressure. Idle delivery reveals no capacity.
	if path.Pressured && !math.IsNaN(path.ObservedBPS) && path.ObservedBPS > 0 {
		rate = min(rate, path.ObservedBPS)
	}
	seconds := min(8*bytes/max(rate, 64<<10), 5)
	return time.Duration(seconds * float64(time.Second))
}

type routedFlowDirection struct {
	start       time.Time
	first, last atomic.Int64
	bytes       atomic.Uint64
}

func (d *routedFlowDirection) note(n int) {
	elapsed := time.Since(d.start).Nanoseconds() + 1
	d.first.CompareAndSwap(0, elapsed)
	for old := d.last.Load(); elapsed > old && !d.last.CompareAndSwap(old, elapsed); old = d.last.Load() {
	}
	d.bytes.Add(uint64(n))
}

type routedFlowPerformance struct {
	router   *Router
	asn      uint32
	up, down routedFlowDirection
}

func (r *Router) trackRoutedFlow(conn *routedConn, resolved netip.Addr) net.Conn {
	if conn.state.config.Egress.Selection == "adaptive" {
		p := &routedFlowPerformance{router: r}
		if resolved.IsValid() && conn.asn != nil {
			p.asn, _ = conn.state.lookupASNData(conn.asn, resolved, r.now())
		}
		start := time.Now()
		p.up.start, p.down.start = start, start
		conn.performance = p
	}
	return conn
}

func (p *routedFlowPerformance) finish(conn *routedConn) {
	up, down := p.up.bytes.Load(), p.down.bytes.Load()
	if up == 0 && down == 0 {
		return
	}
	r := p.router
	r.mu.Lock()
	defer r.mu.Unlock()
	s := conn.state
	if r.state != s || s.health[conn.member.ID()] != conn.health {
		return
	}
	now := r.now()
	observe := func(e *transferEstimate) {
		if now.Sub(e.updated) > measurementTTL {
			*e = transferEstimate{}
		}
		e.up.observe(up, time.Duration(p.up.last.Load()-p.up.first.Load()), e.samples == 0)
		e.down.observe(down, time.Duration(p.down.last.Load()-p.down.first.Load()), e.samples == 0)
		e.samples = min(e.samples+1, 32)
		e.updated = now
		if first := p.up.first.Load(); first > 0 && p.down.first.Load() > first {
			e.response.observe(now, min(time.Duration(p.down.first.Load()-first), time.Second))
		}
	}
	observe(&s.transfers)
	observe(&conn.health.transfer)
	key := destinationKey(conn.member.ID(), conn.destination)
	item := s.destinationEntry(key, now, conn.generation)
	observe(&item.transfer)
	s.destinations[key] = item
	if p.asn == 0 || conn.asn != s.asnSnapshot(now) {
		return
	}
	if s.asnTransfers == nil {
		s.asnTransfers = make(map[asnTransferKey]transferEstimate)
	}
	ak := asnTransferKey{conn.member.ID(), conn.generation, p.asn}
	e, exists := s.asnTransfers[ak]
	if !exists && len(s.asnTransfers) >= asnTransferLimit {
		var oldest asnTransferKey
		var updated time.Time
		for k, entry := range s.asnTransfers {
			if updated.IsZero() || entry.updated.Before(updated) {
				oldest, updated = k, entry.updated
			}
		}
		delete(s.asnTransfers, oldest)
	}
	observe(&e)
	s.asnTransfers[ak] = e
}
