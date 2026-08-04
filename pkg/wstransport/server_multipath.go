package wstransport

import (
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
	mu       sync.RWMutex
	peers    map[string]*serverMultipathPeer
	bySource map[string]*serverMultipathPeer
}

type serverMultipathPeer struct {
	id        string
	endpoint  serverMultipathEndpoint
	scheduler *Scheduler
	paths     map[string]conn.Endpoint
}
type serverMultipathEndpoint struct{ id string }

func (e serverMultipathEndpoint) ClearSrc()           {}
func (e serverMultipathEndpoint) SrcToString() string { return e.id }
func (e serverMultipathEndpoint) DstToString() string { return e.id }
func (e serverMultipathEndpoint) DstToBytes() []byte  { return []byte(e.id) }
func (e serverMultipathEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (e serverMultipathEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

func NewServerMultipathBind(base conn.Bind) *ServerMultipathBind {
	return &ServerMultipathBind{base: base, peers: map[string]*serverMultipathPeer{}, bySource: map[string]*serverMultipathPeer{}}
}
func (m *ServerMultipathBind) peer(id string) *serverMultipathPeer {
	p := m.peers[id]
	if p == nil {
		p = &serverMultipathPeer{id: id, endpoint: serverMultipathEndpoint{id: id}, scheduler: NewScheduler(), paths: map[string]conn.Endpoint{}}
		m.peers[id] = p
	}
	return p
}
func (m *ServerMultipathBind) RegisterPath(peerID, name string, kind PathKind, ep conn.Endpoint) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.peer(peerID)
	p.paths[name] = ep
	m.bySource[ep.DstToString()] = p
	p.scheduler.Register(name, kind)
	if kind == PathWSS {
		p.scheduler.ProbeResult(name, time.Millisecond, true, time.Now())
	} else {
		p.scheduler.ProbeResult(name, 0, true, time.Now())
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
func (m *ServerMultipathBind) wrap(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, err := fn(bufs, sizes, eps)
		if err != nil {
			return n, err
		}
		m.mu.RLock()
		defer m.mu.RUnlock()
		for i := 0; i < n; i++ {
			if p := m.bySource[eps[i].DstToString()]; p != nil {
				eps[i] = p.endpoint
			}
		}
		return n, nil
	}
}
func (m *ServerMultipathBind) Close() error              { return m.base.Close() }
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
	if p == nil {
		m.mu.RUnlock()
		return errors.New("unknown multipath peer")
	}
	primary, alternate, duplicate := p.scheduler.Select()
	first, second := p.paths[primary], p.paths[alternate]
	m.mu.RUnlock()
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
