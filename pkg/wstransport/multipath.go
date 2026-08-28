package wstransport

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
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
	probeMu     sync.Mutex
	probes      map[string]outstandingProbe
	mtuProbes   map[string]outstandingMTUProbe
	mtuDone     map[string]bool
	stop        chan struct{}
	lifecycleMu sync.Mutex
	stopped     bool

	pathMTU bool

	// dupLimiter bounds Select's reactive WireGuard type-4 duplication.
	dupLimiter *byteRateLimiter

	// relayEndpointID is the "udp-relay" candidate's endpoint identity
	// string, cached at RegisterPath time so Send/wrapReceive can recognize
	// its traffic with a cheap string compare instead of a locked map
	// lookup on every packet -- see relaySentBytes/relayReceivedBytes.
	// nil until (if ever) a session negotiates the UDP-relay tier.
	relayEndpointID atomic.Pointer[string]
	// relaySent*/relayReceived* count this client's own observed traffic on
	// the udp-relay candidate specifically -- comparing them against the
	// relay's own client-facing-leg counters (reported relay->server over
	// /v1/relay/control) localizes a loss to specifically the client<->relay
	// leg. Always allocated (zero-value atomics), reported to the server as
	// protocol.ClientUDPRelayStats via POST /v1/udp-relay (see
	// pkg/client/directupgrade.go's postUDPRelay) -- best-effort and
	// approximate, since control frames sent directly via m.base.Send
	// (sendProbe, sendMTUProbe, the relay-bind keepalive) are not counted
	// here, only ordinary WireGuard dispatch through Send/wrapReceive.
	relaySentBytes, relaySentPackets         atomic.Uint64
	relayReceivedBytes, relayReceivedPackets atomic.Uint64
}

// RelayLegStats returns this client's cumulative observed traffic on the
// udp-relay candidate, for reporting to the server (see
// protocol.ClientUDPRelayStats). All-zero means either udp-relay was never
// registered as a candidate for this session, or nothing has been sent or
// received over it yet -- a caller should simply omit the report rather
// than treat that as a meaningful zero.
func (m *MultipathBind) RelayLegStats() (sentBytes, sentPackets, receivedBytes, receivedPackets uint64) {
	return m.relaySentBytes.Load(), m.relaySentPackets.Load(), m.relayReceivedBytes.Load(), m.relayReceivedPackets.Load()
}

// ResetRelayLegStats zeroes the udp-relay leg counters RelayLegStats
// reports. The relay's own per-allocation hop counters
// (protocol.RelayUDPStats) start over at zero on every fresh token (see
// pkg/server/udprelay.go's udpRelaySessionState) -- if this side's
// cumulative-since-connection-start counters were compared against that,
// any re-allocation (the rung lost and re-climbed, or a relay failover)
// would read as a burst of client<->relay loss that never happened.
// Callers must call this on a token change, not on every RegisterPath
// refresh: RegisterPath runs idempotently on every reminder call for an
// unchanged, still-live session, and zeroing there would erase real
// mid-session counters for no reason.
func (m *MultipathBind) ResetRelayLegStats() {
	m.relaySentBytes.Store(0)
	m.relaySentPackets.Store(0)
	m.relayReceivedBytes.Store(0)
	m.relayReceivedPackets.Store(0)
}

// outstandingProbe is one in-flight FramePathProbe this side is waiting on an
// ack for, keyed by candidate name in both MultipathBind and
// serverMultipathPeer.
type outstandingProbe struct {
	nonce  [pathProbeSize]byte
	sentAt time.Time
}

type outstandingMTUProbe struct {
	nonce  [pathProbeSize]byte
	target uint16
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

func NewMultipathBind(base conn.Bind, id string, pathMTU bool, opts MultipathOptions) *MultipathBind {
	opts = resolveMultipathOptions(opts)
	m := &MultipathBind{
		base: base, scheduler: NewScheduler(), cache: NewDuplicateCache(4096, 10*time.Second),
		paths: make(map[string]conn.Endpoint), endpoint: multipathEndpoint{id: id},
		probes: make(map[string]outstandingProbe), mtuProbes: make(map[string]outstandingMTUProbe), mtuDone: make(map[string]bool), stop: make(chan struct{}),
		pathMTU:    pathMTU,
		dupLimiter: newByteRateLimiter(opts.DuplicateRateBytesPerSec),
	}
	go m.probeLoop(m.stop)
	return m
}

// RegisterPath adds or refreshes a candidate. endpoint must be produced by
// the underlying carrier bind, not by this bind. Datagram candidates fire an
// immediate out-of-band probe rather than waiting for the next probeLoop tick.
// WSS is deliberately not actively probed: its ordered stream already has
// authoritative connect/disconnect and read/write-error lifecycle signals,
// and injecting health/MTU frames into that same stream can interfere with
// payload delivery without adding useful reachability evidence.
func (m *MultipathBind) RegisterPath(name string, kind PathKind, endpoint conn.Endpoint) {
	m.mu.Lock()
	m.paths[name] = endpoint
	m.mu.Unlock()
	if name == string(PathUDPRelay) {
		id := endpoint.DstToString()
		m.relayEndpointID.Store(&id)
	}
	m.scheduler.Register(name, kind)
	if kind != PathWSS {
		m.sendProbe(name, time.Now())
	}
}
func (m *MultipathBind) Scheduler() *Scheduler { return m.scheduler }
func (m *MultipathBind) Paths() []PathStatus   { return m.scheduler.Status() }
func (m *MultipathBind) SetForced(name string) { m.scheduler.SetForced(name) }
func (m *MultipathBind) Forced() string        { return m.scheduler.Forced() }

func (m *MultipathBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	m.restartProbeLoop()
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
				if !seen {
					if id := m.relayEndpointID.Load(); id != nil && eps[i].DstToString() == *id {
						m.relayReceivedBytes.Add(uint64(len(b)))
						m.relayReceivedPackets.Add(1)
					}
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
		slog.Debug("multipath client send has no healthy candidate", "paths", m.scheduler.Status())
		return errors.New("no healthy multipath candidate")
	}
	m.mu.RLock()
	first, second := m.paths[primary], m.paths[alternate]
	m.mu.RUnlock()
	if first == nil {
		slog.Debug("multipath client selected an unregistered candidate", "candidate", primary, "paths", m.scheduler.Status())
		return errors.New("selected multipath candidate is not registered")
	}
	if err := m.base.Send(bufs, first); err != nil {
		slog.Debug("multipath client primary send failed", "candidate", primary, "error", err)
		m.scheduler.CarrierFailure(primary)
		return err
	}
	if primary == string(PathUDPRelay) {
		n := 0
		for _, b := range bufs {
			n += len(b)
		}
		m.relaySentBytes.Add(uint64(n))
		m.relaySentPackets.Add(uint64(len(bufs)))
	}
	// Type 4 is WireGuard transport. All handshake/control types remain
	// single-path even when the scheduler asks for reactive duplication.
	if !(len(bufs) > 0 && len(bufs[0]) >= 4 && binary.LittleEndian.Uint32(bufs[0][:4]) == 4) {
		return nil
	}
	if duplicate {
		if second != nil {
			// bufs is wireguard-go's whole outbound batch (up to
			// device.maxBatchSize packets), not just bufs[0] -- the type-4
			// check above only inspects the first buffer to classify the
			// batch, but every buffer in it is duplicated below, so the
			// budget and counters must charge for the batch's total size or
			// they undercount by up to that batch size under load, exactly
			// when the budget matters most.
			n := 0
			for _, b := range bufs {
				n += len(b)
			}
			if !m.dupLimiter.Allow(n) {
				m.scheduler.RecordDuplication(alternate, n, false)
				return nil
			}
			m.scheduler.RecordDuplication(alternate, n, true)
			return m.base.Send(bufs, second)
		}
		return nil
	}
	return nil
}
func (m *MultipathBind) Close() error {
	m.lifecycleMu.Lock()
	if !m.stopped {
		close(m.stop)
		m.stopped = true
	}
	m.lifecycleMu.Unlock()
	return m.base.Close()
}

// restartProbeLoop restores background health probing after wireguard-go
// closes a bind for a port or route reconfiguration and opens the same bind
// again. conn.Bind.Close is therefore a rebind boundary, not necessarily the
// final lifetime of this MultipathBind.
func (m *MultipathBind) restartProbeLoop() {
	m.lifecycleMu.Lock()
	if m.stopped {
		m.stop = make(chan struct{})
		m.stopped = false
		go m.probeLoop(m.stop)
	}
	m.lifecycleMu.Unlock()
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
	case FramePathMTUProbe, FramePathMTUAck:
		if !m.pathMTU {
			return
		}
	default:
		return
	}
	switch typ {
	case FramePathProbe:
		m.sendControlReply(ep, EncodeControlFrame(FramePathAck, payload))
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
			m.sendMTUProbe(name, minPathMTUProbe)
		}
	case FramePathMTUProbe:
		probe, ok := DecodePathMTUProbe(payload)
		if !ok {
			return
		}
		m.sendControlReply(ep, EncodeControlFrame(FramePathMTUAck, EncodePathMTUAck(probe.Nonce, probe.Target)))
	case FramePathMTUAck:
		ack, ok := DecodePathMTUAck(payload)
		if !ok {
			return
		}
		name, ok := m.nameForEndpoint(ep)
		if !ok {
			return
		}
		m.probeMu.Lock()
		outstanding, found := m.mtuProbes[name]
		if found && outstanding.target == ack.Target && bytes.Equal(outstanding.nonce[:], ack.Nonce[:]) {
			delete(m.mtuProbes, name)
		} else {
			found = false
		}
		m.probeMu.Unlock()
		if found {
			m.scheduler.ReportDatagramMTU(name, ack.Target)
			next := nextPathMTUProbe(ack.Target)
			if next == 0 {
				m.probeMu.Lock()
				m.mtuDone[name] = true
				m.probeMu.Unlock()
			} else {
				m.sendMTUProbe(name, next)
			}
		}
	}
}

// sendControlReply is used only from a carrier receive callback. It must
// return immediately: in particular, a WSS write can wait behind a congested
// payload batch, and blocking here stops WireGuard from receiving unrelated
// packets and eventually fills Bind.packets. One bounded worker per candidate
// is sufficient because every health probe is retried.
func (m *MultipathBind) sendControlReply(ep conn.Endpoint, frame []byte) {
	name, ok := m.nameForEndpoint(ep)
	if !ok || !m.scheduler.ReserveControlSend(name) {
		return
	}
	go func() {
		defer m.scheduler.FinishControlSend(name)
		_ = m.base.Send([][]byte{frame}, ep)
	}()
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

func (m *MultipathBind) probeLoop(stop <-chan struct{}) {
	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.probeAll()
		case <-stop:
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
		if !m.scheduler.requiresActiveProbe(name) {
			continue
		}
		m.probeOne(name, now)
	}
}

func isWireGuardTransport(b []byte) bool {
	return len(b) >= 4 && binary.LittleEndian.Uint32(b[:4]) == 4
}

func isWireGuardTransportBatch(bufs [][]byte) bool {
	return len(bufs) > 0 && isWireGuardTransport(bufs[0])
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

func (m *MultipathBind) sendMTUProbe(name string, target uint16) {
	if !m.pathMTU || target == 0 {
		return
	}
	m.mu.RLock()
	ep := m.paths[name]
	m.mu.RUnlock()
	if ep == nil {
		return
	}
	var nonce [pathProbeSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return
	}
	m.probeMu.Lock()
	if m.mtuDone[name] {
		m.probeMu.Unlock()
		return
	}
	if _, exists := m.mtuProbes[name]; exists {
		m.probeMu.Unlock()
		return
	}
	m.mtuProbes[name] = outstandingMTUProbe{nonce: nonce, target: target}
	m.probeMu.Unlock()
	_ = m.base.Send([][]byte{EncodeControlFrame(FramePathMTUProbe, EncodePathMTUProbe(nonce, target))}, ep)
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
	// FrameThroughputReport is reserved for the retired multipath-v2
	// real-payload mirror/report experiment. Current peers ignore it.
	FrameThroughputReport byte = 8
	FramePathMTUProbe     byte = 9
	FramePathMTUAck       byte = 10
	// FramePathDataAck is reserved for the retired receive-triggered payload
	// ACK experiment. Current v3 peers ignore it.
	FramePathDataAck byte = 11
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

// ValidateTransportName validates a user-facing transport selection and
// returns its canonical candidate name. The scheduler intentionally keeps
// NormalizeTransportName lenient because it is also used on its hot path;
// command, API, and connection boundaries must use this function instead.
func ValidateTransportName(s string) (string, error) {
	normalized := NormalizeTransportName(s)
	if normalized == "" || normalized == string(PathDirect) || normalized == string(PathUDPRelay) || normalized == string(PathWSS) {
		return normalized, nil
	}
	return "", fmt.Errorf("invalid transport %q (valid values: auto, direct-udp, udp-relay, wss)", s)
}

// PathStatus is a race-free scheduler snapshot. Loss is in [0,1].
type PathStatus struct {
	Name        string        `json:"name"`
	Kind        PathKind      `json:"kind"`
	Healthy     bool          `json:"healthy"`
	RTT         time.Duration `json:"rtt"`
	Loss        float64       `json:"loss"`
	LastSuccess time.Time     `json:"last_success"`
	Primary     bool          `json:"primary"`
	// DatagramMTU is the largest conservative UDP payload confirmed by the
	// authenticated probe exchange. It is diagnostic only: WireGuard keeps
	// its established 1420-byte tunnel MTU for this connection.
	DatagramMTU uint16 `json:"datagram_mtu"`
	// Forced indicates whether this candidate is the user's manual selection.
	Forced bool `json:"forced"`
	// DuplicatedBytes is the cumulative count of primary WireGuard bytes
	// reactively duplicated to this candidate (see Scheduler.selectLocked's
	// duplicate return and MultipathBind.Send). DuplicationSuppressedBytes
	// is how many further bytes duplication would have sent here but were
	// withheld by the bounded duplication budget -- together they make that
	// budget's effect on this path directly inspectable instead of only
	// bounding it blindly.
	DuplicatedBytes            uint64 `json:"duplicated_bytes"`
	DuplicationSuppressedBytes uint64 `json:"duplication_suppressed_bytes"`
}

type candidate struct {
	PathStatus
	probes          [20]bool // newest result overwrites probes[probeNext]
	probeNext, used int
	misses          int
	// duplicatedBytes/duplicationSuppressedBytes back PathStatus's
	// identically-named fields. Updated via RecordDuplication from the
	// packet-send hot path, which only ever holds Scheduler.mu's read lock
	// (see Select's doc comment on why), so -- unlike the rest of
	// candidate's fields -- these must be atomics rather than mu-guarded
	// plain fields.
	duplicatedBytes            atomic.Uint64
	duplicationSuppressedBytes atomic.Uint64
	controlSending             atomic.Bool
}

// Scheduler implements v3's sticky, failure-driven selection policy. Probe
// RTT/loss rank replacements only after the incumbent fails; they never
// preempt a healthy live flow. It is intentionally
// independent from sockets so both UDP and WSS use identical decisions.
type Scheduler struct {
	mu         sync.RWMutex
	candidates map[string]*candidate

	// forced holds the user-forced transport name, if any (e.g. "direct-udp",
	// "udp-relay", "wss"). When set and the corresponding candidate is
	// registered and Healthy, it is selected as primary. If the forced
	// transport is unavailable or unhealthy, selectLocked falls back to
	// the best healthy replacement while retaining sticky selection.
	forced atomic.Pointer[string]

	// primary holds the committed incumbent name, swapped atomically rather
	// than guarded by mu: Select
	// is called on every packet send, concurrently, from wireguard-go's
	// pooled encryption/send workers, and must stay a cheap read lock in the
	// common (no-switch) case. Committing a primary change is the rare
	// event, so it pays its own atomic store instead of forcing every caller
	// through an exclusive lock.
	primary atomic.Pointer[primaryState]
}

// primaryState is Scheduler.primary's committed incumbent.
type primaryState struct {
	name string
}

func NewScheduler() *Scheduler {
	return &Scheduler{candidates: make(map[string]*candidate)}
}

func (s *Scheduler) Register(name string, kind PathKind) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.candidates[name]; p != nil {
		p.Kind = kind
		return
	}
	s.candidates[name] = &candidate{PathStatus: PathStatus{Name: name, Kind: kind, DatagramMTU: 1420}}
}

// requiresActiveProbe reports whether candidate health needs an out-of-band
// datagram challenge. Stream carriers use their native connection lifecycle;
// probing them on the ordered payload stream is both redundant and capable of
// creating head-of-line interference.
func (s *Scheduler) requiresActiveProbe(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p := s.candidates[name]
	return p != nil && p.Kind != PathWSS
}

// ActivateCarrier records an already-established carrier as usable and, if
// no primary exists yet, commits it as the initial incumbent. V3 uses this for
// its authenticated WSS bootstrap so later UDP probe timing cannot make the
// client and server independently choose different first paths. Native stream
// lifecycle callbacks can later fail or recover the carrier.
func (s *Scheduler) ActivateCarrier(name string, now time.Time) {
	s.mu.Lock()
	p := s.candidates[name]
	if p != nil {
		p.Healthy = true
		p.LastSuccess = now
		p.misses = 0
	}
	s.mu.Unlock()
	if p != nil && s.primary.CompareAndSwap(nil, &primaryState{name: name}) {
		slog.Debug("multipath initial carrier activated", "candidate", name)
	}
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
			if p.Healthy {
				slog.Debug("multipath candidate became unhealthy", "candidate", name, "consecutive_probe_misses", p.misses)
			}
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
	}
	p.Loss = p.loss()
}

// CarrierFailure immediately removes a candidate from selection after its
// payload carrier returns an error. Waiting for three later probe timeouts
// would unnecessarily keep sending into a known-broken WebSocket. A later
// successful probe makes the candidate healthy again.
func (s *Scheduler) CarrierFailure(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.candidates[name]
	if p == nil {
		return
	}
	if p.Healthy {
		slog.Debug("multipath candidate carrier failed", "candidate", name)
	}
	p.Healthy = false
	p.misses = 3
}

// ReserveControlSend bounds receive-triggered probe and MTU replies to one
// pending write per candidate. Dropping an overlapping reply is safe: health
// probes retry, while allowing them to queue behind a backpressured carrier
// can stall WireGuard's receive workers and all tunnel connections.
func (s *Scheduler) ReserveControlSend(name string) bool {
	s.mu.RLock()
	p := s.candidates[name]
	s.mu.RUnlock()
	return p != nil && p.controlSending.CompareAndSwap(false, true)
}

func (s *Scheduler) FinishControlSend(name string) {
	s.mu.RLock()
	p := s.candidates[name]
	s.mu.RUnlock()
	if p != nil {
		p.controlSending.Store(false)
	}
}

// RecordDuplication accounts one reactive-duplication decision for name:
// allowed bytes actually sent, or withheld bytes if the duplication budget
// denied them (see MultipathBind.Send). It only ever takes a read lock to
// look up the candidate, then updates its counters via atomic add -- Select
// is called on every packet send and deliberately never takes an exclusive
// lock (see its doc comment), so recording a decision from the same hot path
// must not either, especially since duplication is only active while a
// candidate is degraded, i.e. exactly when this would be called most.
func (s *Scheduler) RecordDuplication(name string, n int, allowed bool) {
	s.mu.RLock()
	p := s.candidates[name]
	s.mu.RUnlock()
	if p == nil {
		return
	}
	if allowed {
		p.duplicatedBytes.Add(uint64(n))
	} else {
		p.duplicationSuppressedBytes.Add(uint64(n))
	}
}

// ReportDatagramMTU caches one successfully acknowledged bounded probe. A
// smaller or malformed value cannot lower the safe default or influence path
// selection; the value is purely inspectable diagnosis.
func (s *Scheduler) ReportDatagramMTU(name string, mtu uint16) {
	if mtu < minPathMTUProbe || mtu > MaxRelayDatagram {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.candidates[name]; p != nil && mtu > p.DatagramMTU {
		p.DatagramMTU = mtu
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

// score ranks a candidate: lower is better. Loss dominates jitter (a
// one-percent loss penalty is 100ms).
func (s *Scheduler) score(p *candidate) time.Duration {
	return p.RTT + time.Duration(p.Loss*10_000_000_000)
}

// Select returns the primary path and, when required, exactly one alternate.
// Empty strings mean that no proven or previously selected candidate exists.
// It holds only a read lock: selectLocked commits the incumbent via
// Scheduler.primary's
// atomic pointer, not under mu, so this stays a cheap, non-exclusive read in
// the common case despite being called on every send from wireguard-go's
// pooled, concurrent encryption/send workers -- an exclusive lock here would
// serialize all of them through one mutex per packet.
func (s *Scheduler) Select() (primary, alternate string, duplicate bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.selectLocked()
}

// SetForced overrides sticky automatic selection with a specific transport
// name ("wss", "udp-relay", "direct-udp", or "" / "auto" to clear). When a
// forced candidate is set, it will be selected as primary as long as it is
// registered and Healthy. If the forced transport is not registered or becomes
// unhealthy, selectLocked falls back to the healthy incumbent or best replacement.
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

// selectLocked keeps a healthy incumbent sticky. Multipath switching is a
// continuity mechanism, not a per-packet race between independently noisy
// client/server scores: automatic mode changes path only when the incumbent
// is genuinely unhealthy. A forced healthy path still takes effect
// immediately. If every registered path is unhealthy, the last incumbent is
// retained as a degraded escape route rather than silently dropping every
// WireGuard packet; probes and carrier reconnects can then recover it.
func (s *Scheduler) selectLocked() (primary, alternate string, duplicate bool) {
	var paths []*candidate
	var registered []*candidate
	for _, p := range s.candidates {
		registered = append(registered, p)
		if p.Healthy {
			paths = append(paths, p)
		}
	}
	sort.Slice(paths, func(i, j int) bool {
		left, right := s.score(paths[i]), s.score(paths[j])
		if left == right {
			return paths[i].Name < paths[j].Name
		}
		return left < right
	})
	if len(paths) == 0 {
		if len(registered) == 0 {
			s.primary.Store(nil)
			return "", "", false
		}
		cur := s.primary.Load()
		// Do not send on a newly registered path before it proves reachability.
		// The degraded escape route applies only to a path that was previously
		// selected and subsequently lost health.
		if cur != nil {
			for _, p := range registered {
				if p.Name == cur.name {
					return p.Name, "", false
				}
			}
		}
		if forcedName := s.Forced(); forcedName != "" {
			for _, p := range registered {
				if p.Name == forcedName && !p.LastSuccess.IsZero() {
					return p.Name, "", false
				}
			}
		}
		return "", "", false
	}

	forcedName := s.Forced()
	forcedCandidate := findCandidate(paths, forcedName)

	var chosen *candidate
	if forcedCandidate != nil {
		// User explicitly forced this candidate, and it is currently registered and Healthy.
		chosen = forcedCandidate
	} else {
		// Either no forced candidate, or the forced candidate is unavailable or
		// unhealthy. Retain a healthy incumbent; score is used only to choose a
		// replacement after actual failure.
		cur := s.primary.Load()
		var curName string
		if cur != nil {
			curName = cur.name
		}
		incumbent := findCandidate(paths, curName)
		if incumbent != nil {
			chosen = incumbent
		} else {
			chosen = paths[0]
		}
	}

	cur := s.primary.Load()
	var curName string
	if cur != nil {
		curName = cur.name
	}
	if chosen.Name != curName {
		slog.Debug("multipath primary changed", "from", curName, "to", chosen.Name, "forced", forcedName != "")
		s.primary.Store(&primaryState{name: chosen.Name})
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
	// Duplicate only during an active failure suspicion (one or two
	// consecutive missed probes). RTT differences and historical rolling loss
	// never mirror a healthy flow onto a standby path.
	if chosen.misses > 0 {
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
// doc comment): selectLocked commits any incumbent change through
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
		v.DuplicatedBytes = p.duplicatedBytes.Load()
		v.DuplicationSuppressedBytes = p.duplicationSuppressedBytes.Load()
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
	if expiry, found := c.entries[k]; found {
		if expiry.After(now) {
			return true
		}
		delete(c.entries, k)
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
