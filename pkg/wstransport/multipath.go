package wstransport

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sort"
	"sync"
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
}

type multipathEndpoint struct{ id string }

func (e multipathEndpoint) ClearSrc()           {}
func (e multipathEndpoint) SrcToString() string { return e.id }
func (e multipathEndpoint) DstToString() string { return e.id }
func (e multipathEndpoint) DstToBytes() []byte  { return []byte(e.id) }
func (e multipathEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (e multipathEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

func NewMultipathBind(base conn.Bind, id string) *MultipathBind {
	return &MultipathBind{base: base, scheduler: NewScheduler(), cache: NewDuplicateCache(4096, 10*time.Second), paths: make(map[string]conn.Endpoint), endpoint: multipathEndpoint{id: id}}
}

// RegisterPath adds or refreshes a candidate. endpoint must be produced by
// the underlying carrier bind, not by this bind.
func (m *MultipathBind) RegisterPath(name string, kind PathKind, endpoint conn.Endpoint) {
	m.mu.Lock()
	m.paths[name] = endpoint
	m.mu.Unlock()
	m.scheduler.Register(name, kind)
}
func (m *MultipathBind) Scheduler() *Scheduler { return m.scheduler }
func (m *MultipathBind) Paths() []PathStatus   { return m.scheduler.Status() }

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
				if m.cache.Seen(bufs[i][:sizes[i]], time.Now()) {
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
	// single-path even when the scheduler asks for duplication.
	if duplicate && len(bufs) > 0 && len(bufs[0]) >= 4 && binary.LittleEndian.Uint32(bufs[0][:4]) == 4 && second != nil {
		return m.base.Send(bufs, second)
	}
	return nil
}
func (m *MultipathBind) Close() error              { return m.base.Close() }
func (m *MultipathBind) SetMark(mark uint32) error { return m.base.SetMark(mark) }
func (m *MultipathBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if s == MultipathSentinel {
		return m.endpoint, nil
	}
	return m.base.ParseEndpoint(s)
}
func (m *MultipathBind) BatchSize() int { return m.base.BatchSize() }

// FramePathProbe and FramePathAck are deliberately tiny control frames.  A
// probe has an eight byte nonce; an ack echoes exactly those eight bytes.  In
// particular, neither frame carries an address, token, or arbitrary payload,
// so replying to a probe cannot be used as a useful amplification primitive.
const (
	FramePathProbe byte = 6
	FramePathAck   byte = 7
	pathProbeSize       = 8
)

// PathKind is a human-readable candidate class, suitable for local status.
type PathKind string

const (
	PathWSS      PathKind = "wss"
	PathUDPRelay PathKind = "udp-relay"
	PathDirect   PathKind = "direct-udp"
)

// PathStatus is a race-free scheduler snapshot. Loss is in [0,1].
type PathStatus struct {
	Name        string
	Kind        PathKind
	Healthy     bool
	RTT         time.Duration
	Loss        float64
	LastSuccess time.Time
	Primary     bool
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

// Scheduler implements the fixed v1 selection policy. It is intentionally
// independent from sockets so both UDP and WebSocket carriers use identical
// health decisions and it is straightforward to test deterministically.
type Scheduler struct {
	mu         sync.RWMutex
	candidates map[string]*candidate
}

func NewScheduler() *Scheduler { return &Scheduler{candidates: make(map[string]*candidate)} }

func (s *Scheduler) Register(name string, kind PathKind) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.candidates[name]; p != nil {
		p.Kind = kind
		return
	}
	s.candidates[name] = &candidate{PathStatus: PathStatus{Name: name, Kind: kind}}
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

func score(p *candidate) time.Duration {
	// Loss dominates jitter: a one-percent loss penalty is 100ms.
	return p.RTT + time.Duration(p.Loss*10_000_000_000)
}

// Select returns the primary path and, when required, exactly one alternate.
// Empty strings mean that no healthy candidate exists.
func (s *Scheduler) Select() (primary, alternate string, duplicate bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.selectLocked()
}

func (s *Scheduler) selectLocked() (primary, alternate string, duplicate bool) {
	var paths []*candidate
	for _, p := range s.candidates {
		if p.Healthy {
			paths = append(paths, p)
		}
	}
	sort.Slice(paths, func(i, j int) bool { return score(paths[i]) < score(paths[j]) })
	if len(paths) == 0 {
		return
	}
	primary = paths[0].Name
	if len(paths) == 1 {
		return
	}
	alt := paths[1]
	if paths[0].Loss >= .05 || (paths[0].p95() > 150*time.Millisecond && paths[0].p95() >= alt.p95()+50*time.Millisecond) {
		return primary, alt.Name, true
	}
	return primary, "", false
}

func (s *Scheduler) Status() []PathStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	primary, alternate, dup := s.selectLocked()
	_ = alternate
	_ = dup
	out := make([]PathStatus, 0, len(s.candidates))
	for _, p := range s.candidates {
		v := p.PathStatus
		v.Primary = v.Name == primary
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
