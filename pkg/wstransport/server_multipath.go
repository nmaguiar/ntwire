package wstransport

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// ServerMultipathBind keeps a separate stable WireGuard endpoint for every
// authenticated relay client. Concrete WSS and UDP endpoints are only paths
// behind that logical endpoint, so receive-side endpoint roaming cannot
// switch a peer back to WSS after UDP relay has been selected.
type ServerMultipathBind struct {
	base     conn.Bind
	mu       sync.RWMutex // guards peers and bySource (registry-level state)
	peers    map[string]*serverMultipathPeer
	bySource map[string]*serverMultipathPeer

	// cache dedupes a repeated WireGuard transport packet arriving on more
	// than one candidate for the same peer -- the server-side counterpart of
	// MultipathBind.cache. Bind-wide (not per-peer): DuplicateCache's key
	// already includes the packet's receiver index, which is unique per
	// peer, so one shared cache is both correct and cheaper than one per
	// peer.
	cache *DuplicateCache

	opts   MultipathOptions
	forced string

	stop        chan struct{}
	lifecycleMu sync.Mutex
	stopped     bool
}

// serverMultipathPeer holds one authenticated client's per-candidate state.
// paths/probes are guarded by mu, a lock local to this peer rather than the
// parent ServerMultipathBind.mu -- wrap already holds ServerMultipathBind.mu
// for the whole receive batch, and dispatching a control frame from inside
// that loop must never re-take the same lock.
type serverMultipathPeer struct {
	id        string
	endpoint  serverMultipathEndpoint
	scheduler *Scheduler

	mu        sync.RWMutex
	paths     map[string]conn.Endpoint
	probes    map[string]outstandingProbe
	mtuProbes map[string]outstandingMTUProbe
	mtuDone   map[string]bool
	pathMTU   bool

	// dupLimiter is this peer's counterpart of MultipathBind.dupLimiter.
	// Reactive type-4 duplication has a strict per-peer byte budget.
	dupLimiter *byteRateLimiter
}

// nameForEndpoint reverse-looks-up which of this peer's registered
// candidates ep belongs to.
func (p *serverMultipathPeer) nameForEndpoint(ep conn.Endpoint) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	target := ep.DstToString()
	for name, e := range p.paths {
		if e.DstToString() == target {
			return name, true
		}
	}
	return "", false
}

type serverMultipathEndpoint struct{ id string }

func (e serverMultipathEndpoint) ClearSrc()           {}
func (e serverMultipathEndpoint) SrcToString() string { return e.id }
func (e serverMultipathEndpoint) DstToString() string { return e.id }
func (e serverMultipathEndpoint) DstToBytes() []byte  { return []byte(e.id) }
func (e serverMultipathEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (e serverMultipathEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

func NewServerMultipathBind(base conn.Bind, opts MultipathOptions) *ServerMultipathBind {
	m := &ServerMultipathBind{
		base: base, peers: map[string]*serverMultipathPeer{}, bySource: map[string]*serverMultipathPeer{},
		cache: NewDuplicateCache(4096, 10*time.Second), opts: resolveMultipathOptions(opts), stop: make(chan struct{}),
	}
	go m.probeLoop(m.stop)
	return m
}
func (m *ServerMultipathBind) peer(id string) *serverMultipathPeer {
	p := m.peers[id]
	if p == nil {
		p = &serverMultipathPeer{
			id: id, endpoint: serverMultipathEndpoint{id: id}, scheduler: NewScheduler(), paths: map[string]conn.Endpoint{}, probes: map[string]outstandingProbe{}, mtuProbes: map[string]outstandingMTUProbe{}, mtuDone: map[string]bool{},
			dupLimiter: newByteRateLimiter(m.opts.DuplicateRateBytesPerSec),
		}
		m.peers[id] = p
	}
	return p
}

// RegisterPath adds or refreshes one peer's candidate. Datagram paths fire an
// immediate out-of-band probe; WSS health follows its native carrier lifecycle
// instead. See MultipathBind.RegisterPath.
func (m *ServerMultipathBind) RegisterPath(peerID, name string, kind PathKind, ep conn.Endpoint, pathMTU bool) {
	m.mu.Lock()
	p := m.peer(peerID)
	m.bySource[ep.DstToString()] = p
	forced := m.forced
	m.mu.Unlock()

	p.mu.Lock()
	p.paths[name] = ep
	p.pathMTU = pathMTU
	p.mu.Unlock()
	p.scheduler.SetForced(forced)

	p.scheduler.Register(name, kind)
	if kind != PathWSS {
		m.sendProbe(p, name, time.Now())
	}
}

// ActivatePath commits an already-established carrier as a peer's initial
// incumbent. It is used for authenticated WSS bootstrap after RegisterPath;
// UDP candidates still require their probe acknowledgement before selection.
func (m *ServerMultipathBind) ActivatePath(peerID, name string) {
	m.mu.RLock()
	p := m.peers[peerID]
	m.mu.RUnlock()
	if p != nil {
		p.scheduler.ActivateCarrier(name, time.Now())
	}
}

// DeactivatePath immediately removes a stream carrier from automatic
// selection when its native lifecycle reports a disconnect. A later
// connection callback re-registers and activates the same stable path name.
func (m *ServerMultipathBind) DeactivatePath(peerID, name string) {
	m.mu.RLock()
	p := m.peers[peerID]
	m.mu.RUnlock()
	if p != nil {
		p.scheduler.CarrierFailure(name)
	}
}

// SetForced applies a server operator's default transport selection to every
// existing and future peer. An unhealthy/unregistered choice still uses the
// scheduler's normal safe fallback behavior.
func (m *ServerMultipathBind) SetForced(name string) {
	normalized := NormalizeTransportName(name)
	m.mu.Lock()
	m.forced = normalized
	peers := make([]*serverMultipathPeer, 0, len(m.peers))
	for _, p := range m.peers {
		peers = append(peers, p)
	}
	m.mu.Unlock()
	for _, p := range peers {
		p.scheduler.SetForced(normalized)
	}
}
func (m *ServerMultipathBind) RemovePeer(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.peers, id)
	for k, p := range m.bySource {
		if p.id == id {
			delete(m.bySource, k)
		}
	}
}
func (m *ServerMultipathBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	m.restartProbeLoop()
	f, p, err := m.base.Open(port)
	if err != nil {
		return nil, 0, err
	}
	out := make([]conn.ReceiveFunc, len(f))
	for i, fn := range f {
		out[i] = m.wrap(fn)
	}
	return out, p, nil
}

// wrap re-tags every ordinary WireGuard datagram's endpoint to its peer's
// stable multipath endpoint, and -- since WSS has no control-frame
// interception of its own, unlike the UDP carrier (see FilterBind's
// probeHandler, wired up as HandlePathControl below) -- also catches a
// active v3 probe frames arriving over WSS here,
// before it can reach WireGuard's own demux as bogus payload. It also
// dedupes a repeated WireGuard transport packet caused by bounded reactive
// duplication -- the server-side counterpart of MultipathBind.wrapReceive.
func (m *ServerMultipathBind) wrap(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			n, err := fn(bufs, sizes, eps)
			if err != nil {
				return n, err
			}
			m.mu.RLock()
			out := 0
			for i := 0; i < n; i++ {
				b := bufs[i][:sizes[i]]
				if typ, payload, ok := DecodeControlFrame(b); ok {
					if p := m.bySource[eps[i].DstToString()]; p != nil {
						m.dispatchControl(p, typ, payload, eps[i])
					}
					continue
				}
				p := m.bySource[eps[i].DstToString()]
				if p != nil && isWireGuardTransport(b) {
					// A WebSocket carrier is already authenticated as this session.
					// Consequently, an inbound WireGuard transport packet proves the
					// candidate can carry return traffic even if its probe ACK is still
					// queued behind the initial handshake. Without this confirmation,
					// WireGuard can receive the first request but drop its response with
					// "no healthy multipath path".
					if name, ok := p.nameForEndpoint(eps[i]); ok {
						p.scheduler.ProbeResult(name, 0, true, time.Now())
					}
				}
				seen := m.cache.Seen(b, time.Now())
				if seen {
					continue
				}
				if p != nil {
					eps[i] = p.endpoint
				}
				if out != i {
					bufs[out], sizes[out], eps[out] = bufs[i], sizes[i], eps[i]
				}
				out++
			}
			m.mu.RUnlock()
			if out > 0 {
				return out, nil
			}
		}
	}
}

// HandlePathControl is the entry point for an active v3 probe frame arriving over
// the UDP carrier, registered as that FilterBind's probe handler (see
// pkg/server/dataplane.go's StartDataPlane -- exported because that wiring
// happens from pkg/server, a different package). WSS-carried frames are
// instead caught inline by wrap above. Unlike wrap, UDP-sourced traffic
// never reaches this bind's own dedup path -- FilterBind already stripped
// this frame out of the ordinary receive stream before this is called, and
// an ordinary (non-control) UDP datagram never reaches here at all, only
// wrap's receive path.
func (m *ServerMultipathBind) HandlePathControl(typ byte, payload []byte, ep conn.Endpoint) {
	m.mu.RLock()
	p := m.bySource[ep.DstToString()]
	m.mu.RUnlock()
	if p == nil {
		return
	}
	m.dispatchControl(p, typ, payload, ep)
}

// dispatchControl only ever touches p.mu (never m.mu), so it is
// always safe to call regardless of whether the caller already holds
// m.mu.RLock (wrap) or not (HandlePathControl).
func (m *ServerMultipathBind) dispatchControl(p *serverMultipathPeer, typ byte, payload []byte, ep conn.Endpoint) {
	switch typ {
	case FramePathProbe, FramePathAck:
		if !ValidPathControl(typ, payload) {
			return
		}
	case FramePathMTUProbe, FramePathMTUAck:
		if !p.pathMTU {
			return
		}
	default:
		return
	}
	switch typ {
	case FramePathProbe:
		m.sendControlReply(p, ep, EncodeControlFrame(FramePathAck, payload))
	case FramePathAck:
		name, ok := p.nameForEndpoint(ep)
		if !ok {
			return
		}
		now := time.Now()
		p.mu.Lock()
		outstanding, found := p.probes[name]
		if found && bytes.Equal(outstanding.nonce[:], payload) {
			delete(p.probes, name)
		} else {
			found = false
		}
		p.mu.Unlock()
		if found {
			p.scheduler.ProbeResult(name, now.Sub(outstanding.sentAt), true, now)
			m.sendMTUProbe(p, name, minPathMTUProbe)
		}
	case FramePathMTUProbe:
		probe, ok := DecodePathMTUProbe(payload)
		if !ok {
			return
		}
		m.sendControlReply(p, ep, EncodeControlFrame(FramePathMTUAck, EncodePathMTUAck(probe.Nonce, probe.Target)))
	case FramePathMTUAck:
		ack, ok := DecodePathMTUAck(payload)
		if !ok {
			return
		}
		name, ok := p.nameForEndpoint(ep)
		if !ok {
			return
		}
		p.mu.Lock()
		outstanding, found := p.mtuProbes[name]
		if found && outstanding.target == ack.Target && bytes.Equal(outstanding.nonce[:], ack.Nonce[:]) {
			delete(p.mtuProbes, name)
		} else {
			found = false
		}
		p.mu.Unlock()
		if found {
			p.scheduler.ReportDatagramMTU(name, ack.Target)
			next := nextPathMTUProbe(ack.Target)
			if next == 0 {
				p.mu.Lock()
				p.mtuDone[name] = true
				p.mu.Unlock()
			} else {
				m.sendMTUProbe(p, name, next)
			}
		}
	}
}

// sendControlReply keeps a probe/MTU response from blocking the carrier's
// receive callback. A backpressured WSS writer must not stop delivery of
// WireGuard payloads for this peer (or, through the shared receive worker,
// other peers). Overlapping replies are safely dropped and retried by the
// normal probe loop.
func (m *ServerMultipathBind) sendControlReply(p *serverMultipathPeer, ep conn.Endpoint, frame []byte) {
	name, ok := p.nameForEndpoint(ep)
	if !ok || !p.scheduler.ReserveControlSend(name) {
		return
	}
	go func() {
		defer p.scheduler.FinishControlSend(name)
		_ = m.base.Send([][]byte{frame}, ep)
	}()
}

// probeLoop probes every registered candidate of every peer roughly once a
// second. It is a single goroutine for the whole ServerMultipathBind, not one
// per peer -- a busy relay server can have hundreds of authenticated peers.
func (m *ServerMultipathBind) probeLoop(stop <-chan struct{}) {
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

func (m *ServerMultipathBind) probeAll() {
	now := time.Now()
	m.mu.RLock()
	peers := make([]*serverMultipathPeer, 0, len(m.peers))
	for _, p := range m.peers {
		peers = append(peers, p)
	}
	m.mu.RUnlock()
	for _, p := range peers {
		p.mu.RLock()
		names := make([]string, 0, len(p.paths))
		for name := range p.paths {
			names = append(names, name)
		}
		p.mu.RUnlock()
		for _, name := range names {
			if !p.scheduler.requiresActiveProbe(name) {
				continue
			}
			m.probeOne(p, name, now)
		}
	}
}

func (m *ServerMultipathBind) probeOne(p *serverMultipathPeer, name string, now time.Time) {
	p.mu.Lock()
	if outstanding, ok := p.probes[name]; ok {
		if now.Sub(outstanding.sentAt) < probeTimeout {
			p.mu.Unlock()
			return
		}
		delete(p.probes, name)
		p.mu.Unlock()
		p.scheduler.ProbeResult(name, 0, false, now)
	} else {
		p.mu.Unlock()
	}
	m.sendProbe(p, name, now)
}

func (m *ServerMultipathBind) sendProbe(p *serverMultipathPeer, name string, now time.Time) {
	p.mu.Lock()
	ep, ok := p.paths[name]
	if !ok {
		p.mu.Unlock()
		return
	}
	var nonce [pathProbeSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		p.mu.Unlock()
		return
	}
	if p.probes == nil {
		p.probes = map[string]outstandingProbe{}
	}
	p.probes[name] = outstandingProbe{nonce: nonce, sentAt: now}
	p.mu.Unlock()
	frame := EncodeControlFrame(FramePathProbe, nonce[:])
	_ = m.base.Send([][]byte{frame}, ep)
}

func (m *ServerMultipathBind) sendMTUProbe(p *serverMultipathPeer, name string, target uint16) {
	if !p.pathMTU || target == 0 {
		return
	}
	p.mu.RLock()
	ep := p.paths[name]
	p.mu.RUnlock()
	if ep == nil {
		return
	}
	var nonce [pathProbeSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return
	}
	p.mu.Lock()
	if p.mtuDone[name] {
		p.mu.Unlock()
		return
	}
	if _, exists := p.mtuProbes[name]; exists {
		p.mu.Unlock()
		return
	}
	p.mtuProbes[name] = outstandingMTUProbe{nonce: nonce, target: target}
	p.mu.Unlock()
	_ = m.base.Send([][]byte{EncodeControlFrame(FramePathMTUProbe, EncodePathMTUProbe(nonce, target))}, ep)
}

func (m *ServerMultipathBind) Close() error {
	m.lifecycleMu.Lock()
	if !m.stopped {
		close(m.stop)
		m.stopped = true
	}
	m.lifecycleMu.Unlock()
	return m.base.Close()
}

// restartProbeLoop restores candidate health probing when wireguard-go closes
// a bind for reconfiguration and then opens that same bind again.
func (m *ServerMultipathBind) restartProbeLoop() {
	m.lifecycleMu.Lock()
	if m.stopped {
		m.stop = make(chan struct{})
		m.stopped = false
		go m.probeLoop(m.stop)
	}
	m.lifecycleMu.Unlock()
}
func (m *ServerMultipathBind) SetMark(mark uint32) error { return m.base.SetMark(mark) }
func (m *ServerMultipathBind) BatchSize() int            { return m.base.BatchSize() }
func (m *ServerMultipathBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	m.mu.RLock()
	p := m.peers[s]
	m.mu.RUnlock()
	if p == nil {
		// Legacy/direct-only peers retain ordinary endpoint parsing. They are
		// deliberately not placed in the scheduler until they negotiate and
		// register a candidate path.
		return m.base.ParseEndpoint(s)
	}
	return p.endpoint, nil
}
func (m *ServerMultipathBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(serverMultipathEndpoint)
	if !ok {
		return m.base.Send(bufs, ep)
	}
	m.mu.RLock()
	p := m.peers[e.id]
	m.mu.RUnlock()
	if p == nil {
		slog.Debug("multipath server send has unknown peer", "peer", e.id)
		return errors.New("unknown multipath peer")
	}
	primary, alternate, duplicate := p.scheduler.Select()
	p.mu.RLock()
	first, second := p.paths[primary], p.paths[alternate]
	p.mu.RUnlock()
	if first == nil {
		slog.Debug("multipath server send has no healthy path", "peer", e.id, "selected", primary, "paths", p.scheduler.Status())
		return errors.New("no healthy multipath path")
	}
	if err := m.base.Send(bufs, first); err != nil {
		slog.Debug("multipath server primary send failed", "peer", e.id, "candidate", primary, "error", err)
		p.scheduler.CarrierFailure(primary)
		return err
	}
	if !(len(bufs) > 0 && len(bufs[0]) >= 4 && binary.LittleEndian.Uint32(bufs[0][:4]) == 4) {
		return nil
	}
	if duplicate {
		if second != nil {
			// See MultipathBind.Send's identical comment: bufs is the whole
			// outbound batch, not just bufs[0], so the budget/counters must
			// charge for its total size.
			n := 0
			for _, b := range bufs {
				n += len(b)
			}
			if !p.dupLimiter.Allow(n) {
				p.scheduler.RecordDuplication(alternate, n, false)
				return nil
			}
			p.scheduler.RecordDuplication(alternate, n, true)
			return m.base.Send(bufs, second)
		}
		return nil
	}
	return nil
}
