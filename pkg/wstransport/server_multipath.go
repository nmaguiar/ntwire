package wstransport

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
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

	stop      chan struct{}
	closeOnce sync.Once
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

	mu     sync.RWMutex
	paths  map[string]conn.Endpoint
	probes map[string]outstandingProbe
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

func NewServerMultipathBind(base conn.Bind) *ServerMultipathBind {
	m := &ServerMultipathBind{base: base, peers: map[string]*serverMultipathPeer{}, bySource: map[string]*serverMultipathPeer{}, stop: make(chan struct{})}
	go m.probeLoop()
	return m
}
func (m *ServerMultipathBind) peer(id string) *serverMultipathPeer {
	p := m.peers[id]
	if p == nil {
		p = &serverMultipathPeer{id: id, endpoint: serverMultipathEndpoint{id: id}, scheduler: NewScheduler(), paths: map[string]conn.Endpoint{}}
		m.peers[id] = p
	}
	return p
}

// RegisterPath adds or refreshes one peer's candidate, and fires one
// immediate, out-of-band probe for it -- see MultipathBind.RegisterPath's
// doc comment for why that matters: without it, a freshly registered
// candidate sits unusable (Select only ever returns a Healthy one) for up to
// a full probeInterval.
func (m *ServerMultipathBind) RegisterPath(peerID, name string, kind PathKind, ep conn.Endpoint) {
	m.mu.Lock()
	p := m.peer(peerID)
	m.bySource[ep.DstToString()] = p
	m.mu.Unlock()

	p.mu.Lock()
	p.paths[name] = ep
	p.mu.Unlock()

	p.scheduler.Register(name, kind)
	m.sendProbe(p, name, time.Now())
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
// probeHandler, wired up as handlePathControl below) -- also catches a
// FramePathProbe/FramePathAck/FrameThroughputReport arriving over WSS here,
// before it can reach WireGuard's own demux as bogus payload.
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
				if p := m.bySource[eps[i].DstToString()]; p != nil {
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

// HandlePathControl is the entry point for a probe/ack arriving over the UDP
// carrier, registered as that FilterBind's probe handler (see
// pkg/server/dataplane.go's StartDataPlane -- exported because that wiring
// happens from pkg/server, a different package). WSS-carried frames are
// instead caught inline by wrap above.
func (m *ServerMultipathBind) HandlePathControl(typ byte, payload []byte, ep conn.Endpoint) {
	m.mu.RLock()
	p := m.bySource[ep.DstToString()]
	m.mu.RUnlock()
	if p == nil {
		return
	}
	m.dispatchControl(p, typ, payload, ep)
}

// dispatchControl only ever touches p.mu (never m.mu), so it is always safe
// to call regardless of whether the caller already holds m.mu.RLock (wrap)
// or not (handlePathControl).
func (m *ServerMultipathBind) dispatchControl(p *serverMultipathPeer, typ byte, payload []byte, ep conn.Endpoint) {
	if !ValidPathControl(typ, payload) {
		return
	}
	switch typ {
	case FramePathProbe:
		ack := EncodeControlFrame(FramePathAck, payload)
		_ = m.base.Send([][]byte{ack}, ep)
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
		}
	}
}

// probeLoop probes every registered candidate of every peer roughly once a
// second. It is a single goroutine for the whole ServerMultipathBind, not one
// per peer -- a busy relay server can have hundreds of authenticated peers.
func (m *ServerMultipathBind) probeLoop() {
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

func (m *ServerMultipathBind) Close() error {
	m.closeOnce.Do(func() { close(m.stop) })
	return m.base.Close()
}
func (m *ServerMultipathBind) SetMark(mark uint32) error { return m.base.SetMark(mark) }
func (m *ServerMultipathBind) BatchSize() int            { return m.base.BatchSize() }
func (m *ServerMultipathBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	m.mu.RLock()
	p := m.peers[s]
	m.mu.RUnlock()
	if p == nil {
		return nil, errors.New("unknown multipath peer")
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
		return errors.New("unknown multipath peer")
	}
	primary, alternate, duplicate := p.scheduler.Select()
	p.mu.RLock()
	first, second := p.paths[primary], p.paths[alternate]
	p.mu.RUnlock()
	if first == nil {
		return errors.New("no healthy multipath path")
	}
	if err := m.base.Send(bufs, first); err != nil {
		return err
	}
	if duplicate && len(bufs) > 0 && len(bufs[0]) >= 4 && binary.LittleEndian.Uint32(bufs[0][:4]) == 4 && second != nil {
		return m.base.Send(bufs, second)
	}
	return nil
}
