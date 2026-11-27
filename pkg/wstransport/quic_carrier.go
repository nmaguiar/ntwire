package wstransport

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"golang.zx2c4.com/wireguard/conn"
)

const (
	quicSendDepth    = 32
	quicReceiveDepth = 256
	MaxQUICSendWait  = 5 * time.Millisecond
)

// QUICBind receives only fully attached connections. Its endpoints are
// pinned to connection incarnations and never resolved from a network name.
type QUICBind struct {
	mu                                      sync.Mutex
	open                                    *quicBindOpen
	peers                                   map[*carrierInstance]*quicPeer
	batchAdmission                          bool
	sendWait                                time.Duration
	sent, received, sendDrops, receiveDrops atomic.Uint64
	waitEvents, waitNS                      atomic.Uint64
}

// NewQUICBind optionally enables batch admission with one bounded wait per
// batch. A zero wait still enables batch admission for controlled comparisons.
func NewQUICBind(sendWait *time.Duration) (*QUICBind, error) {
	b := new(QUICBind)
	if sendWait != nil {
		if *sendWait < 0 || *sendWait > MaxQUICSendWait {
			return nil, errors.New("invalid QUIC send admission wait")
		}
		b.batchAdmission, b.sendWait = true, *sendWait
	}
	return b, nil
}

// QUICStats counts ciphertext datagrams at the carrier boundary. Sent
// counts acceptance by QUIC, while Received counts delivery to the bind.
type QUICStats struct {
	Sent         uint64 `json:"sent"`
	Received     uint64 `json:"received"`
	SendDrops    uint64 `json:"send_queue_drops"`
	ReceiveDrops uint64 `json:"receive_queue_drops"`
	WaitEvents   uint64 `json:"send_wait_events,omitempty"`
	WaitNS       uint64 `json:"send_wait_ns,omitempty"`
}

func (b *QUICBind) Stats() QUICStats {
	return QUICStats{Sent: b.sent.Load(), Received: b.received.Load(),
		SendDrops: b.sendDrops.Load(), ReceiveDrops: b.receiveDrops.Load(),
		WaitEvents: b.waitEvents.Load(), WaitNS: b.waitNS.Load()}
}

func (s QUICStats) Delta(before QUICStats) QUICStats {
	s.Sent -= min(s.Sent, before.Sent)
	s.Received -= min(s.Received, before.Received)
	s.SendDrops -= min(s.SendDrops, before.SendDrops)
	s.ReceiveDrops -= min(s.ReceiveDrops, before.ReceiveDrops)
	s.WaitEvents -= min(s.WaitEvents, before.WaitEvents)
	s.WaitNS -= min(s.WaitNS, before.WaitNS)
	return s
}

// PeerRTT samples the QUIC sender's smoothed RTT on the lane's current
// authenticated connection. It does not schedule a probe.
func (b *QUICBind) PeerRTT(id string) time.Duration {
	b.mu.Lock()
	var active *quic.Conn
	for _, p := range b.peers {
		if c, ok := p.conn.(quicDatagramLink); ok && p.endpoint.id == id && c.Context().Err() == nil {
			active = c.Conn
			break
		}
	}
	b.mu.Unlock()
	if active == nil {
		return 0
	}
	return active.ConnectionStats().SmoothedRTT
}

type quicBindOpen struct {
	done     chan struct{}
	incoming chan packet
}

type quicPeer struct {
	conn      DatagramLink
	endpoint  endpoint
	max       int
	out       chan []byte
	admission sync.Mutex
}

// DatagramLink owns one authenticated carrier connection. Close must unblock
// receive and cause Context to become done. Only one goroutine sends.
type DatagramLink interface {
	Context() context.Context
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
	Close() error
}

type quicDatagramLink struct{ *quic.Conn }

func (c quicDatagramLink) Close() error { return c.CloseWithError(0, "carrier closed") }

// QUICBind does not own the listener or the handshake; it owns a connection
// from the moment Adopt succeeds.
func (b *QUICBind) Adopt(id string, c *quic.Conn, maxDatagram int, detached func(conn.Endpoint)) (conn.Endpoint, error) {
	ep, _, err := b.AdoptLink(id, quicDatagramLink{c}, maxDatagram, detached)
	return ep, err
}

// AdoptLink reuses the bounded packet queues for another datagram carrier.
// Done closes after its reader and writer no longer use the connection.
func (b *QUICBind) AdoptLink(id string, c DatagramLink, maxDatagram int, detached func(conn.Endpoint)) (conn.Endpoint, <-chan struct{}, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open == nil || c.Context().Err() != nil {
		return nil, nil, net.ErrClosed
	}
	identity := new(carrierInstance)
	p := &quicPeer{
		conn: c, endpoint: endpoint{id: id, carrier: identity, pinned: true},
		max: maxDatagram, out: make(chan []byte, quicSendDepth),
	}
	b.peers[identity] = p
	done, written := make(chan struct{}), make(chan struct{})
	open := b.open
	go func() {
		defer close(written)
		defer c.Close()
		b.writePeer(p)
	}()
	go func() {
		defer close(done)
		b.readPeer(open, p)
		_ = c.Close()
		<-written
		b.mu.Lock()
		delete(b.peers, p.endpoint.carrier)
		b.mu.Unlock()
		detached(p.endpoint)
	}()
	return p.endpoint, done, nil
}

func (b *QUICBind) readPeer(open *quicBindOpen, p *quicPeer) {
	ctx := p.conn.Context()
	for {
		data, err := p.conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		if len(data) == 0 || len(data) > p.max {
			continue
		}
		select {
		case <-open.done:
			return
		case open.incoming <- packet{data: data, endpoint: p.endpoint}:
			b.received.Add(1)
		default:
			b.receiveDrops.Add(1)
		}
	}
}

func (b *QUICBind) writePeer(p *quicPeer) {
	ctx := p.conn.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-p.out:
			err := p.conn.SendDatagram(data)
			var oversized *quic.DatagramTooLargeError
			if errors.As(err, &oversized) {
				// The earlier qualification cannot describe this path any
				// longer. Close it so both endpoints return to a standby.
				return
			}
			if err != nil {
				return
			}
			b.sent.Add(1)
		}
	}
}

func (b *QUICBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(endpoint)
	if !ok || !e.pinned {
		return conn.ErrWrongEndpointType
	}
	b.mu.Lock()
	p := b.peers[e.carrier]
	if p == nil || p.conn.Context().Err() != nil {
		b.mu.Unlock()
		return net.ErrClosed
	}
	for _, data := range bufs {
		if len(data) > p.max {
			b.mu.Unlock()
			return ErrCarrierDatagram
		}
	}
	if b.batchAdmission {
		done := b.open.done
		b.mu.Unlock()
		return b.admitBatch(p.conn.Context(), done, p, bufs)
	}
	defer b.mu.Unlock()
	for i, data := range bufs {
		if len(p.out) == cap(p.out) {
			b.sendDrops.Add(uint64(len(bufs) - i))
			break // Backpressure becomes bounded datagram loss.
		}
		p.out <- append([]byte(nil), data...)
	}
	return nil
}

// admitBatch waits only on this peer's writable queue. One sender may wait,
// for one deadline shared by the entire batch. Writers on other lanes and
// bind teardown never wait behind that deadline.
func (b *QUICBind) admitBatch(ctx context.Context, done <-chan struct{}, p *quicPeer, bufs [][]byte) error {
	if !p.admission.TryLock() {
		b.sendDrops.Add(uint64(len(bufs)))
		return nil
	}
	defer p.admission.Unlock()
	var until time.Time
	var timer *time.Timer
	for i, data := range bufs {
		select {
		case <-done:
			return net.ErrClosed
		case <-ctx.Done():
			return net.ErrClosed
		default:
		}
		if len(p.out) < cap(p.out) {
			p.out <- append([]byte(nil), data...)
			continue
		}
		if b.sendWait == 0 {
			b.sendDrops.Add(uint64(len(bufs) - i))
			break
		}
		if timer == nil {
			started := time.Now()
			until = started.Add(b.sendWait)
			timer = time.NewTimer(b.sendWait)
			b.waitEvents.Add(1)
			defer func() {
				timer.Stop()
				b.waitNS.Add(uint64(time.Since(started)))
			}()
		}
		if !time.Now().Before(until) {
			b.sendDrops.Add(uint64(len(bufs) - i))
			break
		}
		select {
		case p.out <- append([]byte(nil), data...):
		case <-timer.C:
			b.sendDrops.Add(uint64(len(bufs) - i))
			return nil
		case <-done:
			return net.ErrClosed
		case <-ctx.Done():
			return net.ErrClosed
		}
	}
	return nil
}

func (b *QUICBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	b.open = &quicBindOpen{done: make(chan struct{}), incoming: make(chan packet, quicReceiveDepth)}
	b.peers = make(map[*carrierInstance]*quicPeer)
	return []conn.ReceiveFunc{receivePacketQueue(b.open.done, b.open.incoming)}, 0, nil
}

func (b *QUICBind) Close() error {
	b.mu.Lock()
	if b.open == nil {
		b.mu.Unlock()
		return nil
	}
	close(b.open.done)
	peers := b.peers
	b.open, b.peers = nil, nil
	b.mu.Unlock()
	for _, p := range peers {
		_ = p.conn.Close()
	}
	return nil
}

func (*QUICBind) SetMark(uint32) error { return nil }
func (b *QUICBind) BatchSize() int {
	if b.batchAdmission {
		return conn.IdealBatchSize
	}
	return 1
}

func (*QUICBind) ParseEndpoint(string) (conn.Endpoint, error) {
	return nil, conn.ErrWrongEndpointType
}

// QUICConfig bounds control streams and buffering. 0-RTT and server-opened
// streams are disabled. A single client-opened bidi stream is for attach.
func QUICConfig(server bool) *quic.Config {
	streams := int64(-1)
	if server {
		streams = 1
	}
	return &quic.Config{
		EnableDatagrams: true, HandshakeIdleTimeout: 3 * time.Second,
		MaxIdleTimeout: 8 * time.Second, KeepAlivePeriod: 3 * time.Second,
		MaxIncomingStreams: streams, MaxIncomingUniStreams: -1, RequireStreamCreditRelease: true,
		InitialStreamReceiveWindow: 4096, MaxStreamReceiveWindow: 4096,
		InitialConnectionReceiveWindow: 4096, MaxConnectionReceiveWindow: 4096,
	}
}

// SendQUICProof waits for DPLPMTUD to permit one complete probe. This is only
// used during attach, with a deadline, and never splits the payload.
func SendQUICProof(ctx context.Context, c *quic.Conn, proof []byte) error {
	return SendCarrierSizeProof(ctx, c.Context(), c.SendDatagram, proof)
}

func SendCarrierSizeProof(ctx, lifetime context.Context, send func([]byte) error, proof []byte) error {
	for {
		var oversized *quic.DatagramTooLargeError
		if err := send(proof); !errors.As(err, &oversized) {
			return err
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-lifetime.Done():
			timer.Stop()
			return context.Cause(lifetime)
		case <-timer.C:
		}
	}
}
