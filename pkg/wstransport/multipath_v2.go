package wstransport

import (
	"encoding/binary"
	"sort"
	"sync"
	"time"
)

// recvCounter accumulates one candidate's mirrored-traffic byte/packet
// counts between report ticks (see MultipathBind.countMirroredName/reportLoop
// and ServerMultipathBind's equivalents).
type recvCounter struct {
	bytes   uint32
	packets uint32
}

// ThroughputReport is FrameThroughputReport's fixed-size payload: a
// receiver-local rolling-window snapshot of how much traffic arrived on one
// candidate, not a cumulative counter -- safe to lose or duplicate exactly
// like a probe/ack, and requiring no clock sync between peers since
// WindowMillis is measured purely by the reporting side. It is sent back
// over the same candidate path it describes; the endpoint it arrives on
// already identifies which candidate, so (unlike this repo's other typed
// protocol messages) it carries no name/ID field of its own.
type ThroughputReport struct {
	BytesReceived   uint32
	PacketsReceived uint32
	WindowMillis    uint32
}

const throughputReportSize = 12

// EncodeThroughputReport encodes r as FrameThroughputReport's fixed payload.
func EncodeThroughputReport(r ThroughputReport) []byte {
	b := make([]byte, throughputReportSize)
	binary.LittleEndian.PutUint32(b[0:4], r.BytesReceived)
	binary.LittleEndian.PutUint32(b[4:8], r.PacketsReceived)
	binary.LittleEndian.PutUint32(b[8:12], r.WindowMillis)
	return b
}

// DecodeThroughputReport reverses EncodeThroughputReport, rejecting any
// payload not exactly throughputReportSize bytes.
func DecodeThroughputReport(payload []byte) (ThroughputReport, bool) {
	if len(payload) != throughputReportSize {
		return ThroughputReport{}, false
	}
	return ThroughputReport{
		BytesReceived:   binary.LittleEndian.Uint32(payload[0:4]),
		PacketsReceived: binary.LittleEndian.Uint32(payload[4:8]),
		WindowMillis:    binary.LittleEndian.Uint32(payload[8:12]),
	}, true
}

// ValidThroughputReport reports whether payload has the fixed shape
// EncodeThroughputReport produces.
func ValidThroughputReport(payload []byte) bool { return len(payload) == throughputReportSize }

// V2Options bundles multipath-v2's tuning knobs. A zero-value V2Options
// means "use every production default" -- see resolveV2Options, which
// callers (pkg/client, pkg/server) apply once to their own caller-supplied
// config before passing the result down into this package, so a config
// field left at its YAML/Options zero value reliably means "default" all the
// way through, the same convention pkg/client's DirectUpgradeTiming already
// uses.
type V2Options struct {
	// MirrorRateBytesPerSec bounds how much real traffic per second is
	// opportunistically mirrored to each standby candidate -- the mechanism
	// that gives multipath-v2 something to sample without synthesizing new
	// bandwidth-eating test transfers. Applies per peer server-side (each
	// authenticated client gets its own budget), and to the single peer
	// client-side.
	MirrorRateBytesPerSec int
	// MinDeliveryRatio is the minimum fraction (0,1] of mirrored bytes a
	// candidate must be reported as actually delivering before
	// Scheduler.score adds a capped penalty. Deliberately loose by default:
	// a small mirrored trickle competing with real traffic for buffer/queue
	// space can legitimately drop some packets for reasons unrelated to the
	// candidate's underlying health, so this should tolerate normal noise,
	// not chase a perfect ratio.
	MinDeliveryRatio float64
	// SwitchMargin is how much better a challenger's score must be than the
	// incumbent's before a delivery-ratio-influenced switch is even
	// considered (see Scheduler.selectLocked).
	SwitchMargin time.Duration
	// MinDwell is the minimum time an incumbent must have held the primary
	// role before a delivery-ratio-influenced switch away from it is
	// allowed.
	MinDwell time.Duration
	// ReportInterval paces how often a receiver summarizes each candidate's
	// mirrored-traffic counters into an outgoing FrameThroughputReport, and
	// how often a sender rolls its own attempted-mirror-bytes window that
	// an incoming report is compared against (see mirrorAccounting). Both
	// sides must use the same interval for the comparison to mean anything,
	// so this is the one v2 setting that only makes sense set identically
	// on both client and server.
	ReportInterval time.Duration
	// DuplicateRateBytesPerSec bounds how much primary WireGuard traffic per
	// second may be reactively duplicated to the alternate candidate (see
	// Scheduler.selectLocked's duplicate return and MultipathBind.Send).
	// Unlike MirrorRateBytesPerSec this budget applies regardless of
	// whether the session negotiated v2, since duplication is a v1
	// behavior too. It exists so duplication -- triggered by the very loss
	// congestion causes -- cannot itself become an unbounded second stream
	// competing for the same congested bandwidth.
	DuplicateRateBytesPerSec int
}

const (
	defaultMirrorRateBytesPerSec = 16384 // 16 KB/s
	defaultMinDeliveryRatio      = 0.85
	defaultMaxThroughputPenalty  = 500 * time.Millisecond
	defaultSwitchMargin          = 30 * time.Millisecond
	defaultMinDwell              = 5 * time.Second
	defaultReportInterval        = time.Second
	// defaultDuplicateRateBytesPerSec is deliberately far above
	// defaultMirrorRateBytesPerSec: duplication is reactive (only while a
	// candidate is actually degraded) rather than continuous background
	// sampling, so it can afford a budget close to what a real primary
	// stream needs while still bounding worst case.
	defaultDuplicateRateBytesPerSec = 262144 // 256 KB/s
)

// resolveV2Options fills every zero field of o with its production default.
func resolveV2Options(o V2Options) V2Options {
	if o.MirrorRateBytesPerSec <= 0 {
		o.MirrorRateBytesPerSec = defaultMirrorRateBytesPerSec
	}
	if o.MinDeliveryRatio <= 0 {
		o.MinDeliveryRatio = defaultMinDeliveryRatio
	}
	if o.SwitchMargin <= 0 {
		o.SwitchMargin = defaultSwitchMargin
	}
	if o.MinDwell <= 0 {
		o.MinDwell = defaultMinDwell
	}
	if o.ReportInterval <= 0 {
		o.ReportInterval = defaultReportInterval
	}
	if o.DuplicateRateBytesPerSec <= 0 {
		o.DuplicateRateBytesPerSec = defaultDuplicateRateBytesPerSec
	}
	return o
}

// mirrorLimiter is a small byte-rate token bucket bounding how much real
// traffic gets opportunistically duplicated to a standby candidate: the
// mechanism that keeps passive throughput sampling's cost bounded and
// configurable instead of an unbounded continuous 2x-bandwidth mirror.
type mirrorLimiter struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  float64
	refillRate float64 // bytes per second
	last       time.Time
}

func newMirrorLimiter(bytesPerSecond int) *mirrorLimiter {
	if bytesPerSecond <= 0 {
		bytesPerSecond = defaultMirrorRateBytesPerSec
	}
	rate := float64(bytesPerSecond)
	return &mirrorLimiter{tokens: rate, maxTokens: rate, refillRate: rate, last: time.Now()}
}

// Allow reports whether n bytes may be sent now, deducting them from the
// bucket if so.
func (l *mirrorLimiter) Allow(n int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.tokens += now.Sub(l.last).Seconds() * l.refillRate
	if l.tokens > l.maxTokens {
		l.tokens = l.maxTokens
	}
	l.last = now
	if l.tokens < float64(n) {
		return false
	}
	l.tokens -= float64(n)
	return true
}

// MirrorCandidate returns the best healthy candidate other than the current
// primary, for multipath-v2's continuous opportunistic mirroring -- deliberately
// independent of Select's duplicate decision, since mirroring exists to
// gather throughput data on a standby candidate *before* it's degraded
// enough to warrant Select's own reactive WireGuard-level duplication.
func (s *Scheduler) MirrorCandidate() (name string, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var paths []*candidate
	for _, p := range s.candidates {
		if p.Healthy {
			paths = append(paths, p)
		}
	}
	if len(paths) < 2 {
		return "", false
	}
	sort.Slice(paths, func(i, j int) bool { return s.score(paths[i]) < s.score(paths[j]) })
	primaryName := ""
	if cur := s.primary.Load(); cur != nil {
		primaryName = cur.name
	}
	for _, c := range paths {
		if c.Name != primaryName {
			return c.Name, true
		}
	}
	return "", false
}

// countMirroredName attributes n bytes of recognized mirrored traffic to a
// candidate for reportLoop to summarize.
func (m *MultipathBind) countMirroredName(name string, n int) {
	m.recvMu.Lock()
	c := m.recvCounters[name]
	if c == nil {
		c = &recvCounter{}
		m.recvCounters[name] = c
	}
	c.bytes += uint32(n)
	c.packets++
	m.recvMu.Unlock()
}

// reportLoop periodically summarizes each candidate's accumulated
// countMirroredName totals into an outgoing FrameThroughputReport, then resets
// them for the next window. Only ever started when v2 is set (see
// NewMultipathBind).
func (m *MultipathBind) reportLoop(stop <-chan struct{}) {
	ticker := time.NewTicker(m.opts.ReportInterval)
	defer ticker.Stop()
	last := time.Now()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			m.sendReports(uint32(now.Sub(last).Milliseconds()))
			m.attempts.rollWindow()
			last = now
		case <-stop:
			return
		}
	}
}

func (m *MultipathBind) sendReports(windowMillis uint32) {
	if windowMillis == 0 {
		return
	}
	m.recvMu.Lock()
	counters := m.recvCounters
	m.recvCounters = make(map[string]*recvCounter)
	m.recvMu.Unlock()
	for name, c := range counters {
		if c.bytes == 0 {
			continue
		}
		m.mu.RLock()
		ep, ok := m.paths[name]
		m.mu.RUnlock()
		if !ok {
			continue
		}
		payload := EncodeThroughputReport(ThroughputReport{BytesReceived: c.bytes, PacketsReceived: c.packets, WindowMillis: windowMillis})
		_ = m.base.Send([][]byte{EncodeControlFrame(FrameThroughputReport, payload)}, ep)
	}
}

// mirrorAccounting tracks, per candidate, how many bytes were mirrored to it
// recently -- so an incoming FrameThroughputReport (which describes the
// peer's own most recent window) can be compared against a roughly
// same-length window of what was actually attempted, without the sender and
// receiver needing synchronized clocks or their windows needing to be
// exactly aligned (see attemptedLastWindow's doc comment for why it reads
// both the completed and in-progress window, not just the completed one).
// Deliberately not folded into recvCounter: that type accumulates *inbound*
// bytes for outgoing reports; this accumulates *outbound* mirror-send bytes
// for interpreting incoming ones -- opposite directions, rolled by the same
// ticker (see reportLoop) but otherwise independent.
type mirrorAccounting struct {
	mu      sync.Mutex
	current map[string]uint32
	last    map[string]uint32
}

func newMirrorAccounting() *mirrorAccounting {
	return &mirrorAccounting{current: map[string]uint32{}, last: map[string]uint32{}}
}

func (a *mirrorAccounting) recordAttempt(name string, n int) {
	a.mu.Lock()
	a.current[name] += uint32(n)
	a.mu.Unlock()
}

// rollWindow freezes the current window as "last" (what an incoming report
// will be compared against) and starts a fresh one.
func (a *mirrorAccounting) rollWindow() {
	a.mu.Lock()
	a.last, a.current = a.current, map[string]uint32{}
	a.mu.Unlock()
}

// attemptedLastWindow returns how many bytes were mirrored to name across
// the most recently completed window plus whatever has accumulated in the
// window since, and whether that count is meaningful. Summing both matters
// because the two sides' report tickers are phase-independent (each starts
// its own time.Ticker at its own connection-open time, with no handshake to
// align them): a report describing the peer's window [T, T+interval] can
// arrive on this side at any point in its own ticker's cycle, including
// just after this side's own roll -- at which point "last" alone would
// reflect only the window that just ended, understating what's actually
// been attempted and inflating the resulting ratio. Including "current"
// only ever grows the denominator, so the bias this introduces runs
// conservative (ratio same or lower), never optimistic. Zero/not-found means
// "nothing comparable was attempted" -- the neutral case a caller must skip
// rather than compute a ratio from (see
// MultipathBind.handlePathControl's FrameThroughputReport case).
func (a *mirrorAccounting) attemptedLastWindow(name string) (uint32, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := a.last[name] + a.current[name]
	return n, n > 0
}
