package wstransport

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// MultipathSentinel is the stable endpoint configured in WireGuard for a
// relay peer. Unlike WSSentinel it is never replaced as candidates appear.
const MultipathSentinel = "mp:relay"

// MultipathBind is the relay-only conn.Bind adapter. It keeps WireGuard's
// endpoint identity stable while dispatching outbound packets over registered
// carrier endpoints. It deliberately accepts a single logical peer: clients
// have one server peer, while servers create one instance per authenticated
// peer/session.
type MultipathBind struct {
	base      conn.Bind
	scheduler *Scheduler
	cache     *DuplicateCache
	mu        sync.RWMutex
	paths     map[string]conn.Endpoint
	endpoint  multipathEndpoint
	onOpen    func() error

	// probeMu guards probes, kept separate from mu (which guards paths) so
	// the receive-path handling a FramePathAck never has to take the same
	// lock a concurrent RegisterPath/Send might be holding.
	probeMu   sync.Mutex
	probes    map[string]outstandingProbe
	stop      chan struct{}
	closeOnce sync.Once

	// v2 is true iff this session negotiated CapabilityMultipathV2, gating
	// the passive throughput-sampling subsystem. Constant for the bind's
	// whole life, set once at construction.
	v2   bool
	opts V2Options

	// mirror bounds how much real primary traffic gets opportunistically
	// duplicated to the standby candidate purely to sample it (see Send);
	// nil unless v2. recvMu/recvCounters accumulate what actually arrived
	// per candidate between report ticks (see wrapReceive/reportLoop).
	// attempts tracks the send side of the same exchange -- how much this
	// bind itself mirrored -- so an incoming report can be turned into a
	// delivery ratio (see handlePathControl).
	mirror       *mirrorLimiter
	recvMu       sync.Mutex
	recvCounters map[string]*recvCounter
	attempts     *mirrorAccounting
}

// outstandingProbe is one in-flight FramePathProbe this side is waiting on an
// ack for, keyed by candidate name in both MultipathBind and
// serverMultipathPeer.
type outstandingProbe struct {
	nonce  [pathProbeSize]byte
	sentAt time.Time
}

// probeInterval/probeTimeout pace the health-probing every registered
// candidate gets on both sides of a multipath session (see RegisterPath and
// probeLoop): a probe goes out at most once every probeInterval per
// candidate, and one still outstanding after probeTimeout counts as a miss
// (ProbeResult(name, 0, false, now)), the same "miss" semantics a candidate
// that simply never answers already has.
const (
	probeInterval = time.Second
	probeTimeout  = 2 * time.Second
)

type multipathEndpoint struct{ id string }

func (e multipathEndpoint) ClearSrc()           {}
func (e multipathEndpoint) SrcToString() string { return e.id }
func (e multipathEndpoint) DstToString() string { return e.id }
func (e multipathEndpoint) DstToBytes() []byte  { return []byte(e.id) }
func (e multipathEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (e multipathEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

func NewMultipathBind(base conn.Bind, id string, v2 bool, opts V2Options) *MultipathBind {
	opts = resolveV2Options(opts)
	m := &MultipathBind{
		base: base, scheduler: NewScheduler(), cache: NewDuplicateCache(4096, 10*time.Second),
		paths: make(map[string]conn.Endpoint), endpoint: multipathEndpoint{id: id},
		probes: make(map[string]outstandingProbe), stop: make(chan struct{}),
		v2: v2, opts: opts,
	}
	if v2 {
		m.scheduler.SetV2Options(opts)
		m.scheduler.SetV2(true)
		m.mirror = newMirrorLimiter(opts.MirrorRateBytesPerSec)
		m.recvCounters = make(map[string]*recvCounter)
		m.attempts = newMirrorAccounting()
		go m.reportLoop()
	}
	go m.probeLoop()
	return m
}

// RegisterPath adds or refreshes a candidate. endpoint must be produced by
// the underlying carrier bind, not by this bind. It also fires one immediate,
// out-of-band probe for the new candidate rather than waiting for the next
// probeLoop tick: Select only ever returns a Healthy candidate, so without
// this a freshly registered path would sit unusable for up to a full
// probeInterval.
func (m *MultipathBind) RegisterPath(name string, kind PathKind, endpoint conn.Endpoint) {
	m.mu.Lock()
	m.paths[name] = endpoint
	m.mu.Unlock()
	m.scheduler.Register(name, kind)
	m.sendProbe(name, time.Now())
}
func (m *MultipathBind) Scheduler() *Scheduler { return m.scheduler }
func (m *MultipathBind) Paths() []PathStatus   { return m.scheduler.Status() }
func (m *MultipathBind) SetForced(name string) { m.scheduler.SetForced(name) }
func (m *MultipathBind) Forced() string        { return m.scheduler.Forced() }

func (m *MultipathBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := m.base.Open(port)
	if err != nil {
		return nil, 0, err
	}
	if m.onOpen != nil {
		if err := m.onOpen(); err != nil {
			_ = m.base.Close()
			return nil, 0, err
		}
	}
	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		wrapped[i] = m.wrapReceive(fn)
	}
	return wrapped, actual, nil
}

func (m *MultipathBind) wrapReceive(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			n, err := fn(bufs, sizes, eps)
			if err != nil {
				return n, err
			}
			out := 0
			for i := 0; i < n; i++ {
				b := bufs[i][:sizes[i]]
				// A UDP-carried control frame never reaches here -- FilterBind
				// already strips it out before this receive func sees it (see
				// SetProbeHandler). Only the WSS carrier has no such
				// interception of its own, since it has no notion of control
				// frames at all, so this is what catches a probe/ack arriving
				// over WSS.
				if typ, payload, ok := DecodeControlFrame(b); ok {
					m.handlePathControl(typ, payload, eps[i])
					continue
				}
				seen := m.cache.Seen(b, time.Now())
				if seen && m.v2 {
					// A packet DuplicateCache recognizes as a repeat is
					// exactly what mirroring produces: the same encrypted
					// packet arriving twice, once via primary and once via
					// the mirrored copy. Count it here (attributed to
					// whichever candidate this specific copy arrived on)
					// before it's dropped below, so reportLoop can summarize
					// what each candidate is actually delivering. This is a
					// heuristic signal, not an exact measurement: dedup
					// doesn't track which copy is "the" mirror, so on the
					// rare packet where the primary's own copy happens to
					// arrive second, it gets counted as if it were mirrored
					// traffic -- EWMA smoothing in ReportDeliveryRatio absorbs
					// that noise rather than needing it prevented here.
					m.countMirrored(eps[i], len(b))
				}
				if seen {
					continue
				}
				eps[out] = m.endpoint
				if out != i {
					bufs[out], sizes[out] = bufs[i], sizes[i]
				}
				out++
			}
			if out > 0 {
				return out, nil
			}
		}
	}
}

func (m *MultipathBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if _, ok := ep.(multipathEndpoint); !ok {
		return m.base.Send(bufs, ep)
	}
	primary, alternate, duplicate := m.scheduler.Select()
	if primary == "" {
		return errors.New("no healthy multipath candidate")
	}
	m.mu.RLock()
	first, second := m.paths[primary], m.paths[alternate]
	m.mu.RUnlock()
	if first == nil {
		return errors.New("selected multipath candidate is not registered")
	}
	if err := m.base.Send(bufs, first); err != nil {
		return err
	}
	// Type 4 is WireGuard transport. All handshake/control types remain
	// single-path even when the scheduler asks for duplication or mirroring.
	if !(len(bufs) > 0 && len(bufs[0]) >= 4 && binary.LittleEndian.Uint32(bufs[0][:4]) == 4) {
		return nil
	}
	if duplicate {
		if second != nil {
			return m.base.Send(bufs, second)
		}
		return nil
	}
	if m.v2 {
		// Select only returns alternate alongside duplicate=true; v2's
		// continuous (not just reactive) mirroring asks the scheduler
		// directly for a standby candidate to sample instead, rate-capped
		// and strictly best-effort -- a mirror failure must never fail the
		// primary send above.
		if name, ok := m.scheduler.MirrorCandidate(); ok {
			m.mu.RLock()
			mirrorEP := m.paths[name]
			m.mu.RUnlock()
			if mirrorEP != nil && m.mirror.Allow(len(bufs[0])) {
				_ = m.base.Send(bufs, mirrorEP)
				m.attempts.recordAttempt(name, len(bufs[0]))
			}
		}
	}
	return nil
}
func (m *MultipathBind) Close() error {
	m.closeOnce.Do(func() { close(m.stop) })
	return m.base.Close()
}
func (m *MultipathBind) SetMark(mark uint32) error { return m.base.SetMark(mark) }
func (m *MultipathBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if s == MultipathSentinel {
		return m.endpoint, nil
	}
	return m.base.ParseEndpoint(s)
}
func (m *MultipathBind) BatchSize() int { return m.base.BatchSize() }

// handlePathControl is the single entry point for a FramePathProbe/
// FramePathAck this side received, whether it arrived over WSS (dispatched
// from wrapReceive, since Bind has no control-frame concept of its own) or
// over UDP (dispatched from FilterBind's probe handler, registered via
// SetProbeHandler -- see NewMultipathHybridClient). A probe is answered
// immediately, on the same path/endpoint it arrived on; an ack completes the
// matching outstanding probe, if any, and feeds a real RTT into the
// scheduler.
func (m *MultipathBind) handlePathControl(typ byte, payload []byte, ep conn.Endpoint) {
	switch typ {
	case FramePathProbe, FramePathAck:
		if !ValidPathControl(typ, payload) {
			return
		}
	case FrameThroughputReport:
		// m.attempts/m.mirror/m.recvCounters are only ever initialized when
		// v2 is set (see NewMultipathBind); a peer sending this frame to a
		// non-v2 session -- buggy, or the relay/peer being less than fully
		// trusted per docs/SECURITY.md -- must be rejected here rather than
		// reaching those nil fields below.
		if !m.v2 || !ValidThroughputReport(payload) {
			return
		}
	default:
		return
	}
	switch typ {
	case FramePathProbe:
		ack := EncodeControlFrame(FramePathAck, payload)
		_ = m.base.Send([][]byte{ack}, ep)
	case FramePathAck:
		name, ok := m.nameForEndpoint(ep)
		if !ok {
			return
		}
		now := time.Now()
		m.probeMu.Lock()
		outstanding, found := m.probes[name]
		if found && bytes.Equal(outstanding.nonce[:], payload) {
			delete(m.probes, name)
		} else {
			found = false
		}
		m.probeMu.Unlock()
		if found {
			m.scheduler.ProbeResult(name, now.Sub(outstanding.sentAt), true, now)
		}
	case FrameThroughputReport:
		name, ok := m.nameForEndpoint(ep)
		if !ok {
			return
		}
		report, ok := DecodeThroughputReport(payload)
		if !ok {
			return
		}
		// Compare against what this side itself attempted to mirror in the
		// comparable window; if nothing was attempted, there is nothing
		// meaningful to compute a ratio from -- skip rather than manufacture
		// one (see mirrorAccounting.attemptedLastWindow's doc comment).
		if attempted, ok := m.attempts.attemptedLastWindow(name); ok {
			m.scheduler.ReportDeliveryRatio(name, float64(report.BytesReceived)/float64(attempted))
		}
	}
}

// nameForEndpoint reverse-looks-up which registered candidate ep belongs to,
// by comparing its endpoint identity string. paths is small (a handful of
// candidates at most), so a linear scan is simplest.
func (m *MultipathBind) nameForEndpoint(ep conn.Endpoint) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	target := ep.DstToString()
	for name, e := range m.paths {
		if e.DstToString() == target {
			return name, true
		}
	}
	return "", false
}

func (m *MultipathBind) probeLoop() {
	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.probeAll()
		case <-m.stop:
			return
		}
	}
}

func (m *MultipathBind) probeAll() {
	now := time.Now()
	m.mu.RLock()
	names := make([]string, 0, len(m.paths))
	for name := range m.paths {
		names = append(names, name)
	}
	m.mu.RUnlock()
	for _, name := range names {
		m.probeOne(name, now)
	}
}

// probeOne sends a fresh probe for name unless one is already outstanding
// and not yet timed out; a timed-out probe is scored as a miss before a new
// one goes out, the same as an ack that never arrives at all.
func (m *MultipathBind) probeOne(name string, now time.Time) {
	m.probeMu.Lock()
	if outstanding, ok := m.probes[name]; ok {
		if now.Sub(outstanding.sentAt) < probeTimeout {
			m.probeMu.Unlock()
			return
		}
		delete(m.probes, name)
		m.probeMu.Unlock()
		m.scheduler.ProbeResult(name, 0, false, now)
	} else {
		m.probeMu.Unlock()
	}
	m.sendProbe(name, now)
}

func (m *MultipathBind) sendProbe(name string, now time.Time) {
	m.mu.RLock()
	ep, ok := m.paths[name]
	m.mu.RUnlock()
	if !ok {
		return
	}
	var nonce [pathProbeSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return
	}
	m.probeMu.Lock()
	if m.probes == nil {
		m.probes = map[string]outstandingProbe{}
	}
	m.probes[name] = outstandingProbe{nonce: nonce, sentAt: now}
	m.probeMu.Unlock()
	frame := EncodeControlFrame(FramePathProbe, nonce[:])
	_ = m.base.Send([][]byte{frame}, ep)
}

// FramePathProbe and FramePathAck are deliberately tiny, fixed-size control
// frames. A probe has a twelve byte nonce; an ack echoes exactly those twelve
// bytes. Neither carries an address, token, or arbitrary payload, so
// replying to a probe cannot be used as a useful amplification primitive.
// The size (encoded frame: controlHeaderLen(5)+12 = 17 bytes) is deliberately
// chosen to clear wstransport.ValidDatagram's 16-byte floor -- the WSS
// carrier (Bind.Send/read) silently drops anything smaller with no error, so
// an 8-byte nonce (the original size) made a WSS-carried probe/ack
// unforwardable.
const (
	FramePathProbe byte = 6
	FramePathAck   byte = 7
	pathProbeSize       = 12
	// FrameThroughputReport is a multipath-v2-only frame; see its own doc
	// comment further down for the payload shape.
	FrameThroughputReport byte = 8
)

// PathKind is a human-readable candidate class, suitable for local status.
type PathKind string

const (
	PathWSS      PathKind = "wss"
	PathUDPRelay PathKind = "udp-relay"
	PathDirect   PathKind = "direct-udp"
)

// NormalizeTransportName standardizes transport aliases to canonical candidate names.
func NormalizeTransportName(s string) string {
	switch s {
	case "direct", "udp", "direct-udp":
		return string(PathDirect)
	case "relay", "udprelay", "udp-relay":
		return string(PathUDPRelay)
	case "ws", "wss", "websocket":
		return string(PathWSS)
	case "auto", "none", "":
		return ""
	default:
		return s
	}
}

// PathStatus is a race-free scheduler snapshot. Loss is in [0,1].
type PathStatus struct {
	Name        string
	Kind        PathKind
	Healthy     bool
	RTT         time.Duration
	Loss        float64
	LastSuccess time.Time
	Primary     bool
	// DeliveryRatio is an EWMA-smoothed fraction, in [0,1], of mirrored bytes
	// sent to this candidate that the peer actually reported receiving back
	// (see Scheduler.ReportDeliveryRatio) -- a relative "is this candidate
	// dropping traffic under its current load" signal, not an absolute
	// bits/sec estimate: a mirror sample is deliberately bandwidth-capped, so
	// it could never prove an absolute throughput ceiling. -1 means "no
	// comparable sample yet", not "confirmed total loss" -- see
	// Scheduler.score's doc comment.
	DeliveryRatio float64
	// Forced indicates whether this candidate is the user's manual selection.
	Forced bool
}

type candidate struct {
	PathStatus
	probes          [20]bool // newest result overwrites probes[probeNext]
	probeNext, used int
	misses          int
	// recent RTT observations let the latency duplication rule use p95
	// without retaining unbounded telemetry.
	rtts    [20]time.Duration
	rttNext int
}

// Scheduler implements the v1 (RTT/loss) selection policy, extended in v2
// with an optional throughput term (see score) and the hysteresis that term
// requires (see selectLocked). It is intentionally independent from sockets
// so both UDP and WebSocket carriers use identical health decisions and it
// is straightforward to test deterministically.
type Scheduler struct {
	mu         sync.RWMutex
	candidates map[string]*candidate

	// forced holds the user-forced transport name, if any (e.g. "direct-udp",
	// "udp-relay", "wss"). When set and the corresponding candidate is
	// registered and Healthy, it is selected as primary. If the forced
	// transport is unavailable or unhealthy, selectLocked falls back to
	// automatic score-based candidate selection.
	forced atomic.Pointer[string]

	// v2 tuning knobs; defaulted at construction, overridable via
	// SetV2Options. maxThroughputPenalty is deliberately not
	// caller-configurable -- it exists to keep the throughput term's
	// contribution to score bounded relative to the existing loss term's,
	// not to be tuned per deployment.
	minDeliveryRatio     float64
	maxThroughputPenalty time.Duration
	switchMargin         time.Duration
	minDwell             time.Duration
	// v2 records whether this scheduler's session negotiated
	// CapabilityMultipathV2 -- and so can actually measure a challenger's
	// real-traffic delivery via ReportDeliveryRatio. Gates the incumbent
	// protection in selectLocked; false (v1) keeps the original immediate
	// RTT/loss-only switching, since v1 has no delivery signal to wait for.
	v2 bool

	// primary holds the hysteresis-committed incumbent name and when it was
	// last (re)selected, swapped atomically rather than guarded by mu: Select
	// is called on every packet send, concurrently, from wireguard-go's
	// pooled encryption/send workers, and must stay a cheap read lock in the
	// common (no-switch) case. Committing a primary change is the rare
	// event, so it pays its own atomic store instead of forcing every caller
	// through an exclusive lock.
	primary atomic.Pointer[primaryState]
}

// primaryState is Scheduler.primary's payload: the hysteresis-committed
// incumbent and when it was last (re)selected.
type primaryState struct {
	name  string
	since time.Time
}

func NewScheduler() *Scheduler {
	return &Scheduler{
		candidates:           make(map[string]*candidate),
		minDeliveryRatio:     defaultMinDeliveryRatio,
		maxThroughputPenalty: defaultMaxThroughputPenalty,
		switchMargin:         defaultSwitchMargin,
		minDwell:             defaultMinDwell,
	}
}

// SetV2Options overrides this scheduler's throughput-scoring/hysteresis
// tunables. Call resolveV2Options on the caller-supplied config first (see
// its doc comment) so a zero field here reliably means "use the production
// default", not "leave whatever this scheduler happened to start with".
func (s *Scheduler) SetV2Options(opts V2Options) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if opts.MinDeliveryRatio > 0 {
		s.minDeliveryRatio = opts.MinDeliveryRatio
	}
	if opts.SwitchMargin > 0 {
		s.switchMargin = opts.SwitchMargin
	}
	if opts.MinDwell > 0 {
		s.minDwell = opts.MinDwell
	}
}

// SetV2 records whether this scheduler's session negotiated
// CapabilityMultipathV2. Pass the same value every time it can change for a
// given scheduler (a server-side peer's scheduler is constructed before its
// negotiated capability is known -- see RegisterPath), since selectLocked
// reads it on every Select call.
func (s *Scheduler) SetV2(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.v2 = enabled
}

func (s *Scheduler) Register(name string, kind PathKind) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.candidates[name]; p != nil {
		p.Kind = kind
		return
	}
	s.candidates[name] = &candidate{PathStatus: PathStatus{Name: name, Kind: kind, DeliveryRatio: -1}}
}

// ProbeResult records one completed or timed-out probe. Three failures make a
// candidate unhealthy, but it remains registered and can recover on the next
// acknowledgement.
func (s *Scheduler) ProbeResult(name string, rtt time.Duration, ok bool, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.candidates[name]
	if p == nil {
		return
	}
	p.probes[p.probeNext] = ok
	p.probeNext = (p.probeNext + 1) % len(p.probes)
	if p.used < len(p.probes) {
		p.used++
	}
	if !ok {
		p.misses++
		if p.misses >= 3 {
			p.Healthy = false
		}
		p.Loss = p.loss()
		return
	}
	p.misses = 0
	p.Healthy, p.LastSuccess = true, now
	if rtt > 0 {
		if p.RTT == 0 {
			p.RTT = rtt
		} else {
			p.RTT = (p.RTT*7 + rtt) / 8
		}
		p.rtts[p.rttNext] = rtt
		p.rttNext = (p.rttNext + 1) % len(p.rtts)
	}
	p.Loss = p.loss()
}

// ReportDeliveryRatio records one comparable sample of how much mirrored
// traffic a candidate actually delivered: ratio is bytesReceived (from an
// incoming FrameThroughputReport) divided by however many bytes the sender
// itself attempted to mirror to this candidate in a comparable window (see
// MultipathBind/ServerMultipathBind's mirrorAccounting) -- computed by the
// caller, not here, since only the caller knows its own send-side
// accounting. Clamped to [0,1] and EWMA-smoothed, the same idiom
// ProbeResult uses for RTT. Deliberately never called when nothing
// comparable was attempted (a caller with no attempted-bytes sample for the
// window simply skips the call) -- that silence is what keeps
// DeliveryRatio's -1 "no data yet" sentinel meaningful; passing a
// manufactured ratio like 0 or 1 for missing data would corrupt score's
// neutral-when-unknown handling. LastSuccess intentionally stays
// probe-driven, not report-driven: a report reflects goodput, not
// reachability.
func (s *Scheduler) ReportDeliveryRatio(name string, ratio float64) {
	if ratio < 0 {
		ratio = 0
	}
	if ratio > 1 {
		ratio = 1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.candidates[name]
	if p == nil {
		return
	}
	if p.DeliveryRatio < 0 {
		p.DeliveryRatio = ratio
	} else {
		p.DeliveryRatio = (p.DeliveryRatio*7 + ratio) / 8
	}
}

func (p *candidate) loss() float64 {
	if p.used == 0 {
		return 1
	}
	good := 0
	for i := 0; i < p.used; i++ {
		if p.probes[i] {
			good++
		}
	}
	return float64(p.used-good) / float64(p.used)
}

func (p *candidate) p95() time.Duration {
	v := make([]time.Duration, 0, len(p.rtts))
	for _, r := range p.rtts {
		if r > 0 {
			v = append(v, r)
		}
	}
	if len(v) == 0 {
		return p.RTT
	}
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	return v[(len(v)*95+99)/100-1]
}

// score ranks a candidate: lower is better. Loss dominates jitter (a
// one-percent loss penalty is 100ms). A delivery-ratio shortfall below the
// scheduler's minimum adds a further, capped penalty -- but only once a
// comparable sample exists: DeliveryRatio < 0 means "no data yet" and is
// scored as neutral, never as if the candidate had confirmed total loss. The
// alternative (treating no-data-yet as zero) would make every freshly
// registered v2 candidate unusable until its first mirrored sample happened
// to land and be reported back.
func (s *Scheduler) score(p *candidate) time.Duration {
	sc := p.RTT + time.Duration(p.Loss*10_000_000_000)
	if p.DeliveryRatio >= 0 && p.DeliveryRatio < s.minDeliveryRatio {
		shortfall := (s.minDeliveryRatio - p.DeliveryRatio) / s.minDeliveryRatio
		sc += time.Duration(shortfall * float64(s.maxThroughputPenalty))
	}
	return sc
}

// Select returns the primary path and, when required, exactly one alternate.
// Empty strings mean that no healthy candidate exists. It holds only a read
// lock: selectLocked commits hysteresis bookkeeping via Scheduler.primary's
// atomic pointer, not under mu, so this stays a cheap, non-exclusive read in
// the common case despite being called on every send from wireguard-go's
// pooled, concurrent encryption/send workers -- an exclusive lock here would
// serialize all of them through one mutex per packet.
func (s *Scheduler) Select() (primary, alternate string, duplicate bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.selectLocked()
}

// selectLocked ranks healthy candidates and picks the primary, applying
// margin+dwell hysteresis only when the delivery-ratio term is actually part
// of the picture (the challenger or the current incumbent has a real
// sample) -- a plain RTT/loss comparison, which is v1's entire behavior,
// switches immediately exactly as it always has. RTT is already
// EWMA-smoothed and loss already uses a rolling window, so a suddenly lossy
// or slow path must still fail over without delay; only the newly added,
// individually noisy delivery-ratio samples need hysteresis to avoid
// flapping. An incumbent that is no longer Healthy has already dropped out
// of paths entirely, so it fails over instantly regardless -- hysteresis
// never delays that case.
//
// v2 additionally never lets an unsampled challenger unseat a healthy
// incumbent at all (see the DeliveryRatio < 0 check below): unlike v1, v2
// has a real signal for "can this candidate actually carry WireGuard
// traffic," so probe-only RTT/loss is deliberately not enough to promote it
// until that signal exists.
// SetForced overrides automatic candidate selection with a specific transport
// name ("wss", "udp-relay", "direct-udp", or "" / "auto" to clear). When a
// forced candidate is set, it will be selected as primary as long as it is
// registered and Healthy. If the forced transport is not registered or becomes
// unhealthy, selectLocked falls back to automatic score-based candidate selection.
func (s *Scheduler) SetForced(name string) {
	norm := NormalizeTransportName(name)
	if norm == "" {
		s.forced.Store(nil)
		return
	}
	s.forced.Store(&norm)
}

// Forced returns the user-forced transport name, or "" if automatic mode is active.
func (s *Scheduler) Forced() string {
	p := s.forced.Load()
	if p == nil {
		return ""
	}
	return *p
}

// selectLocked ranks healthy candidates and picks the primary, applying
// user-forced selection when active and healthy, or falling back to
// margin+dwell hysteresis and delivery-ratio terms in automatic mode.
func (s *Scheduler) selectLocked() (primary, alternate string, duplicate bool) {
	var paths []*candidate
	for _, p := range s.candidates {
		if p.Healthy {
			paths = append(paths, p)
		}
	}
	sort.Slice(paths, func(i, j int) bool { return s.score(paths[i]) < s.score(paths[j]) })
	if len(paths) == 0 {
		s.primary.Store(nil)
		return "", "", false
	}

	forcedName := s.Forced()
	forcedCandidate := findCandidate(paths, forcedName)

	var chosen *candidate
	if forcedCandidate != nil {
		// User explicitly forced this candidate, and it is currently registered and Healthy.
		chosen = forcedCandidate
	} else {
		// Either no forced candidate, or the forced candidate is unavailable/unhealthy.
		// Fall back to automatic score-based selection among healthy candidates.
		cur := s.primary.Load()
		var curName string
		var curSince time.Time
		if cur != nil {
			curName, curSince = cur.name, cur.since
		}
		incumbent := findCandidate(paths, curName)

		best := paths[0]
		// v2 can actually measure a challenger's real WireGuard delivery (via
		// mirrored-traffic sampling; see ReportDeliveryRatio). Until a
		// challenger has at least one such sample, its score reflects only
		// probe RTT/loss -- proof it can carry the tiny probe frames, not real
		// traffic. A healthy incumbent must not be unseated on that alone.
		if s.v2 && incumbent != nil && incumbent.Healthy && best != incumbent && best.DeliveryRatio < 0 {
			best = incumbent
		}
		chosen = best
		if incumbent != nil && incumbent != best &&
			(best.DeliveryRatio >= 0 || incumbent.DeliveryRatio >= 0) {
			now := time.Now()
			if !(s.score(best)+s.switchMargin < s.score(incumbent) && now.Sub(curSince) >= s.minDwell) {
				chosen = incumbent
			}
		}
	}

	cur := s.primary.Load()
	var curName string
	if cur != nil {
		curName = cur.name
	}
	if chosen.Name != curName {
		s.primary.Store(&primaryState{name: chosen.Name, since: time.Now()})
	}
	primary = chosen.Name
	if len(paths) == 1 {
		return primary, "", false
	}
	var alt *candidate
	for _, c := range paths {
		if c.Name != primary {
			alt = c
			break
		}
	}
	if chosen.Loss >= .05 || (chosen.p95() > 150*time.Millisecond && chosen.p95() >= alt.p95()+50*time.Millisecond) {
		return primary, alt.Name, true
	}
	return primary, "", false
}

func findCandidate(paths []*candidate, name string) *candidate {
	if name == "" {
		return nil
	}
	for _, c := range paths {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// Status holds only a read lock, for the same reason Select does (see its
// doc comment): selectLocked commits any hysteresis state change through
// Scheduler.primary's atomic pointer, not through mu.
func (s *Scheduler) Status() []PathStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	primary, alternate, dup := s.selectLocked()
	_ = alternate
	_ = dup
	forced := s.Forced()
	out := make([]PathStatus, 0, len(s.candidates))
	for _, p := range s.candidates {
		v := p.PathStatus
		v.Primary = v.Name == primary
		v.Forced = v.Name == forced
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// DuplicateCache suppresses only WireGuard transport (type 4) packets. The
// receiver index and counter are authenticated portions of a transport packet
// and uniquely identify a retransmitted encrypted packet for this short cache.
type DuplicateCache struct {
	mu      sync.Mutex
	entries map[[12]byte]time.Time
	ttl     time.Duration
	limit   int
}

func NewDuplicateCache(limit int, ttl time.Duration) *DuplicateCache {
	if limit <= 0 {
		limit = 4096
	}
	if ttl <= 0 {
		ttl = 10 * time.Second
	}
	return &DuplicateCache{entries: make(map[[12]byte]time.Time), limit: limit, ttl: ttl}
}

func transportKey(b []byte) (k [12]byte, ok bool) {
	if len(b) < 16 || binary.LittleEndian.Uint32(b[:4]) != 4 {
		return k, false
	}
	copy(k[:], b[4:16])
	return k, true
}

// Seen returns true only for a repeated type-4 packet in the cache window.
func (c *DuplicateCache) Seen(b []byte, now time.Time) bool {
	k, ok := transportKey(b)
	if !ok {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, expiry := range c.entries {
		if !expiry.After(now) {
			delete(c.entries, key)
		}
	}
	if _, found := c.entries[k]; found {
		return true
	}
	if len(c.entries) >= c.limit {
		for key := range c.entries {
			delete(c.entries, key)
			break
		}
	}
	c.entries[k] = now.Add(c.ttl)
	return false
}

// ValidPathControl strictly validates the fixed probe/ack payload shape.
func ValidPathControl(typ byte, payload []byte) bool {
	return (typ == FramePathProbe || typ == FramePathAck) && len(payload) == pathProbeSize
}
