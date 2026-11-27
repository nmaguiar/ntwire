package wstransport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/nmaguiar/ntwire/pkg/ipfamily"
	"golang.zx2c4.com/wireguard/conn"
)

// Bind carries WireGuard datagrams over one WebSocket connection. It is a
// conn.Bind so it can be used by wireguard-go without changing the device.
// The server side accepts many WebSocket connections; the client side dials
// one connection when Open is called.
type Bind struct {
	url    string
	client *http.Client

	// redialMin/redialMax bound the backoff between reconnect attempts after
	// the client-side "remote" peer drops (see redial). Fields rather than
	// package constants so tests can shrink them instead of sleeping through
	// real backoff delays.
	redialMin, redialMax time.Duration
	// dialTimeout bounds one redial attempt so a dial that hangs (e.g. a DNS
	// lookup stuck on a since-vanished interface) cannot block the retry loop
	// from ever observing Close.
	dialTimeout time.Duration
	// writeTimeout bounds writing a dequeued WireGuard batch, including time
	// waiting for the WebSocket's write lock. A timeout retires that carrier.
	writeTimeout time.Duration
	// Client-side native WebSocket ping/pong detects silent carrier loss.
	pingInterval, pingTimeout time.Duration
	rttRequests               chan struct{} // configured before opening a client bind
	// noRedial disables the automatic reconnect entirely -- see DisableRedial.
	noRedial bool
	// The adaptive client can keep its receive loop open after an
	// unavailable initial upgrade while another carrier qualifies.
	deferInitialDial func(status int, err error) bool
	initialDialErr   error

	callbacksMu     sync.Mutex // orders peer replacement and lifecycle publication
	mu              sync.Mutex
	open            bool
	done            chan struct{}
	packets         chan packet
	peers           map[string]*peer
	header          http.Header
	readLimit       int64
	OnPeerConnected func(string, conn.Endpoint)
	// OnPeerDisconnected mirrors OnPeerConnected for lifecycle consumers.
	// Callbacks run outside Bind's state mutex and must not retain credentials.
	// Lifecycle callbacks are serialized with peer replacement.
	OnPeerDisconnected func(string, conn.Endpoint)
	// OnWriteFailure is called when a peer's writer times out, fails, or its
	// queue has overflowed repeatedly. Send itself never blocks on the
	// carrier, so multipath schedulers use this instead of a synchronous
	// Send error to fail over. It runs outside Bind's mutex.
	OnWriteFailure func(string, conn.Endpoint)

	// Dropped counts batches discarded because a peer's queue was full.
	Dropped     atomic.Uint64
	performance atomic.Pointer[queuePerformance]
}

const (
	// peerQueueDepth bounds the batches buffered per carrier. WireGuard
	// treats the carrier as lossy, so overflow is dropped rather than letting
	// one slow peer block wireguard-go's device-wide goroutines.
	peerQueueDepth = 256
	// overflowFailureThreshold consecutive drops close the carrier so a
	// multipath scheduler can fail over and the client can reconnect.
	overflowFailureThreshold = 64
)

type packet struct {
	data     []byte
	endpoint conn.Endpoint
}
type peer struct {
	id       string
	ws       *websocket.Conn
	endpoint endpoint
	done     chan struct{}
	stop     chan struct{}
	stopOnce sync.Once
	bindDone <-chan struct{}
	incoming chan<- packet
	// out is the bounded outbound queue drained by a single writer goroutine
	// (Bind.writeLoop), which is what serializes writes to ws.
	out         chan [][]byte
	sampled     *sampledPeerQueue
	overflow    atomic.Int32
	pingRTT     atomic.Int64
	failureOnce sync.Once
}
type endpoint struct {
	id      string
	address netip.AddrPort
	carrier *carrierInstance
	pinned  bool
}

// Hybrid keeps UDP as the primary transport and adds WebSocket receive and
// send support to the same WireGuard device on the server.
type Hybrid struct {
	UDP       conn.Bind
	WebSocket *Bind
}

// NewHybrid wraps its UDP bind in a FilterBind so a caller that type-asserts
// h.UDP can send/receive the magic-prefixed control frames used by the
// opportunistic direct-connection upgrade (see pkg/server's directudp.go),
// without disturbing normal WireGuard traffic on the same socket.
func NewHybrid(loggers ...*slog.Logger) *Hybrid {
	return &Hybrid{UDP: NewFilterBind(NewUDPBind(0, firstLogger(loggers))), WebSocket: NewServer()}
}

// WSSentinel is the placeholder endpoint address a client-side Hybrid (see
// NewHybridClient) uses to mean "the WebSocket fallback" rather than a real
// host:port. wgnet.AddPeer's initial seed and later
// wgnet.Stack.UpdateEndpoint calls both pass it straight to ParseEndpoint,
// which is how a stalled direct-UDP attempt reverts to WebSocket without
// redialing anything. It is not a valid net.SplitHostPort input, so it can
// never collide with a genuine UDP endpoint string.
const WSSentinel = "ws:relay"

// NewHybridClient builds a client-side Hybrid: WebSocket to url as the
// initial and fallback transport, plus a raw UDP bind (also wrapped in a
// FilterBind, for the same opportunistic-upgrade control frames NewHybrid's
// server side handles) for the opportunistic direct-UDP upgrade. Unlike a
// server-side Hybrid -- which never seeds a peer endpoint explicitly, so its
// ParseEndpoint only ever needs to produce a UDP endpoint -- a client seeds
// its single peer's endpoint at AddPeer time and again on every upgrade
// attempt or revert, so ParseEndpoint must be able to produce either
// endpoint type. See WSSentinel.
//
// ipVersion restricts the UDP bind (self-reflection, NAT priming, the direct
// and UDP-relay upgrade rungs, and ordinary WireGuard traffic once upgraded)
// to one IP family: "4" or "6". "" leaves it dual-stack. It has no effect on
// the WebSocket carrier itself, which is a single TCP connection to a host
// already resolved (and, if set, family-filtered) by the caller's HTTP
// client -- see pkg/ipfamily.
func NewHybridClient(url string, client *http.Client, header http.Header, ipVersion string, loggers ...*slog.Logger) *Hybrid {
	return &Hybrid{UDP: NewFilterBind(ipfamily.New(NewUDPBind(0, firstLogger(loggers)), ipVersion)), WebSocket: NewClient(url, client, header)}
}

// NewMultipathHybridClient returns the existing carrier pair plus the stable
// logical bind used by capable relay peers. WSS is registered and activated first;
// UDP candidates are added only after their authenticated setup succeeds.
// ipVersion is forwarded to NewHybridClient; see its doc.
func NewMultipathHybridClient(url string, client *http.Client, header http.Header, pathMTU bool, opts MultipathOptions, ipVersion string, loggers ...*slog.Logger) (*Hybrid, *MultipathBind) {
	h := NewHybridClient(url, client, header, ipVersion, loggers...)
	m := NewMultipathBind(h, "relay-server", pathMTU, opts)
	h.UDP.(*FilterBind).SetProbeHandler(m.handlePathControl)
	// The initial callback runs before onOpen has registered the path, so the
	// explicit activation in onOpen below is still required. On a later redial
	// the path already exists and this callback restores it immediately.
	h.WebSocket.OnPeerConnected = func(_ string, _ conn.Endpoint) {
		m.scheduler.ActivateCarrier("wss", time.Now())
	}
	h.WebSocket.OnPeerDisconnected = func(_ string, _ conn.Endpoint) {
		m.scheduler.CarrierFailure("wss")
	}
	// Send never reports a stalled carrier synchronously; a wedged or
	// persistently overflowing WSS writer is reported here instead.
	h.WebSocket.OnWriteFailure = func(_ string, _ conn.Endpoint) {
		m.scheduler.CarrierFailure("wss")
	}
	// Bind.ParseEndpoint intentionally rejects a client WebSocket before Open
	// has connected it. Register the fallback from MultipathBind.Open instead,
	// after h.Open has established the peer. WSS health is activated from that
	// real connection lifecycle; only later datagram candidates use active
	// probes (see RegisterPath).
	m.onOpen = func() error {
		ep, err := h.WebSocket.ParseEndpoint(WSSentinel)
		if err != nil {
			return err
		}
		m.RegisterPath("wss", PathWSS, ep)
		m.scheduler.ActivateCarrier("wss", time.Now())
		return nil
	}
	return h, m
}

func firstLogger(loggers []*slog.Logger) *slog.Logger {
	if len(loggers) > 0 {
		return loggers[0]
	}
	return nil
}
func (h *Hybrid) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := h.UDP.Open(port)
	if err != nil {
		return nil, 0, err
	}
	ws, _, err := h.WebSocket.Open(0)
	if err != nil {
		_ = h.UDP.Close()
		return nil, 0, err
	}
	return append(fns, ws...), actual, nil
}
func (h *Hybrid) Close() error              { _ = h.WebSocket.Close(); return h.UDP.Close() }
func (h *Hybrid) SetMark(mark uint32) error { return h.UDP.SetMark(mark) }
func (h *Hybrid) Send(bufs [][]byte, ep conn.Endpoint) error {
	if err := h.WebSocket.Send(bufs, ep); !errors.Is(err, conn.ErrWrongEndpointType) {
		return err
	}
	return h.UDP.Send(bufs, ep)
}

// ParseEndpoint resolves s to a UDP endpoint, except for WSSentinel, which
// resolves to the WebSocket bind's single "remote" endpoint instead. A
// server-side Hybrid never passes WSSentinel, so this is a no-op change for
// that case; a client-side Hybrid (NewHybridClient) uses it to move its
// peer's endpoint between transports without redialing either one.
func (h *Hybrid) ParseEndpoint(s string) (conn.Endpoint, error) {
	if s == WSSentinel {
		return h.WebSocket.ParseEndpoint(s)
	}
	return h.UDP.ParseEndpoint(s)
}
func (h *Hybrid) BatchSize() int { return h.UDP.BatchSize() }

// redialMinDefault/redialMaxDefault/dialTimeoutDefault are NewClient's
// defaults for the client-side redial loop (see redial). Exposed as instance
// fields, not consulted directly, so a test can shrink them.
const (
	redialMinDefault    = time.Second
	redialMaxDefault    = 30 * time.Second
	dialTimeoutDefault  = 10 * time.Second
	writeTimeoutDefault = 5 * time.Second
	pingIntervalDefault = 15 * time.Second
	pingTimeoutDefault  = 10 * time.Second
)

func NewClient(url string, client *http.Client, header http.Header) *Bind {
	return &Bind{url: url, client: client, header: header, redialMin: redialMinDefault, redialMax: redialMaxDefault, dialTimeout: dialTimeoutDefault, writeTimeout: writeTimeoutDefault, pingInterval: pingIntervalDefault, pingTimeout: pingTimeoutDefault}
}

// SetDatagramReadLimit applies a carrier-specific ciphertext maximum at the
// WebSocket framing layer. Call it before opening the bind.
func (b *Bind) SetDatagramReadLimit(n int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open || n < 1 || n > maxDatagramSize {
		return errors.New("invalid WebSocket datagram read limit")
	}
	b.readLimit = n
	return nil
}

// SetHeader replaces the headers used for the client's WebSocket dial (both
// the initial Open and every subsequent redial attempt). It exists because
// the Authorization bearer token Open originally dialed with is only valid
// until the control-plane session's next renewal -- see
// Connection.renew/reconnect in pkg/client, which call this on every token
// rotation so a later redial (see read/redial) presents a live token instead
// of one the server has already invalidated. A no-op on a server-side Bind,
// which never dials anything.
func (b *Bind) SetHeader(header http.Header) {
	b.mu.Lock()
	b.header = header
	b.mu.Unlock()
}

// DisableRedial permanently turns off the automatic reconnect a client-side
// Bind otherwise starts every time its "remote" peer drops (see redial). It
// exists for tests that need a disconnect to stay observably disconnected: a
// redial's first attempt fires with no backoff (see redial's attempt==0
// case), so it can win a race against a test closing the peer's server-side
// listener a moment later -- a connection already past the OS's TCP
// handshake at the instant the listener closes can still land, even though
// every later attempt is correctly refused. Reordering test code narrows
// that window but cannot close it; only disabling redial does. A no-op on a
// server-side Bind, which never dials out.
func (b *Bind) DisableRedial() {
	b.mu.Lock()
	b.noRedial = true
	b.mu.Unlock()
}

// SetRedialBackoff overrides the default backoff and dial timeout for the
// client-side reconnect loop. It is intended for tests that need fast
// reconnects without sleeping through production backoff intervals.
func (b *Bind) SetRedialBackoff(min, max, dialTimeout time.Duration) {
	b.mu.Lock()
	b.redialMin, b.redialMax, b.dialTimeout = min, max, dialTimeout
	b.mu.Unlock()
}

// NewServer creates a bind whose ServeHTTP method attaches authenticated
// WebSocket connections. The id is usually the ntwire session ID.
func NewServer() *Bind { return &Bind{writeTimeout: writeTimeoutDefault} }

func newPeer(id string, ws *websocket.Conn, ep endpoint, recorder *queuePerformance) *peer {
	ep.carrier = &carrierInstance{}
	p := &peer{id: id, ws: ws, endpoint: ep, done: make(chan struct{}), stop: make(chan struct{})}
	if recorder == nil {
		p.out = make(chan [][]byte, peerQueueDepth)
	} else {
		p.sampled = &sampledPeerQueue{out: make(chan queuedBatch, peerQueueDepth), recorder: recorder}
	}
	return p
}

func (p *peer) stopIO() {
	p.stopOnce.Do(func() { close(p.stop) })
}

func (p *peer) nextBatch() (wssQueueBatch, bool) {
	if p.sampled != nil {
		return p.sampled.next(p.stop)
	}
	select {
	case <-p.stop:
		return wssQueueBatch{}, false
	case batch := <-p.out:
		return wssQueueBatch{datagrams: batch}, true
	}
}

type queueResult uint8

const (
	queueAccepted queueResult = iota
	queueClosed
	queueFull
)

func (p *peer) enqueue(batch [][]byte) queueResult {
	if p.sampled != nil {
		return p.sampled.enqueue(batch, p.stop)
	}
	select {
	case <-p.stop:
		return queueClosed
	case p.out <- batch:
		return queueAccepted
	default:
		return queueFull
	}
}

// writeLoop is the only writer of p.ws. A stalled write is bounded by
// writeTimeout; on failure the carrier is closed (which triggers the usual
// disconnect/redial path) and OnWriteFailure is invoked.
func (b *Bind) writeLoop(p *peer) {
	b.mu.Lock()
	writeTimeout := b.writeTimeout
	b.mu.Unlock()
	if writeTimeout <= 0 {
		writeTimeout = writeTimeoutDefault
	}
	// A write timeout retires this writer and carrier. Use one cancellation
	// context for their lifetime, and arm the timer only while writing a batch.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	recorder := b.performance.Load()
	var deadline *time.Timer
	for {
		batch, ok := p.nextBatch()
		if !ok {
			return
		}
		if deadline == nil {
			deadline = time.AfterFunc(writeTimeout, cancel)
		} else {
			deadline.Reset(writeTimeout)
		}
		var err error
		var writeStart time.Time
		for _, buf := range batch.datagrams {
			if batch.sampledAt != 0 && writeStart.IsZero() {
				writeStart = time.Now()
			}
			if err = p.ws.Write(ctx, websocket.MessageBinary, buf); err != nil {
				break
			}
		}
		if !deadline.Stop() {
			// The callback may already be scheduled even when the write just
			// finished. Never reuse this context or rearm that timer afterward.
			err = context.DeadlineExceeded
		}
		if !writeStart.IsZero() {
			recorder.recordWrite(time.Since(writeStart))
		}
		if err != nil {
			p.stopIO()
			slog.Warn("WireGuard WebSocket write failed", "peer", p.id, "error", err)
			b.reportWriteFailure(p)
			p.ws.CloseNow()
			return
		}
	}
}

func (b *Bind) reportWriteFailure(p *peer) {
	p.failureOnce.Do(func() {
		b.callbacksMu.Lock()
		defer b.callbacksMu.Unlock()
		b.mu.Lock()
		current := b.peers[p.id] == p
		b.mu.Unlock()
		if !current {
			return
		}
		if b.OnWriteFailure != nil {
			b.OnWriteFailure(p.id, p.endpoint)
		}
	})
}

// AllowDeferredInitialDial permits a disconnected client bind when allow
// classifies its initial dial as unavailable. Configure it before Open.
func (b *Bind) AllowDeferredInitialDial(allow func(status int, err error) bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.deferInitialDial = allow
}

func (b *Bind) InitialDialError() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.initialDialErr
}

// RetryDeferredDial starts the usual backoff loop once for this bind opening.
func (b *Bind) RetryDeferredDial() {
	b.mu.Lock()
	if !b.open || b.noRedial || b.initialDialErr == nil {
		b.mu.Unlock()
		return
	}
	b.initialDialErr = nil
	done := b.done
	b.mu.Unlock()
	go b.redial(done)
}

func (b *Bind) Open(_ uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.callbacksMu.Lock()
	defer b.callbacksMu.Unlock()
	b.mu.Lock()
	if b.open {
		b.mu.Unlock()
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	b.open, b.done = true, make(chan struct{})
	b.packets, b.peers = make(chan packet, conn.IdealBatchSize), map[string]*peer{}
	var connected *peer
	var onConnected func(string, conn.Endpoint)
	b.initialDialErr = nil
	if b.url != "" {
		ws, response, err := websocket.Dial(context.Background(), b.url, &websocket.DialOptions{HTTPClient: b.client, HTTPHeader: b.header})
		if err != nil {
			status := 0
			if response != nil {
				status = response.StatusCode
			}
			if b.deferInitialDial == nil || !b.deferInitialDial(status, err) {
				close(b.done)
				b.open = false
				b.mu.Unlock()
				return nil, 0, err
			}
			b.initialDialErr = err
		} else {
			if b.readLimit > 0 {
				ws.SetReadLimit(b.readLimit)
			}
			p := newPeer("remote", ws, endpoint{id: "remote", address: endpointAddress(b.url)}, b.performance.Load())
			p.bindDone, p.incoming = b.done, b.packets
			b.peers[p.id] = p
			connected, onConnected = p, b.OnPeerConnected
		}
	}
	receive := receivePacketQueue(b.done, b.packets)
	b.mu.Unlock()
	if connected != nil {
		if onConnected != nil {
			onConnected(connected.id, connected.endpoint)
		}
		go b.read(connected)
	}
	return []conn.ReceiveFunc{receive}, 0, nil
}

func receivePacketQueue(done <-chan struct{}, packets <-chan packet) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case <-done:
			return 0, net.ErrClosed
		default:
		}
		select {
		case <-done:
			return 0, net.ErrClosed
		case first := <-packets:
			sizes[0] = copy(bufs[0], first.data)
			eps[0] = first.endpoint
			n := 1
			for n < len(bufs) {
				select {
				case p := <-packets:
					sizes[n] = copy(bufs[n], p.data)
					eps[n] = p.endpoint
					n++
				default:
					return n, nil
				}
			}
			return n, nil
		}
	}
}

func (b *Bind) ServeHTTP(w http.ResponseWriter, r *http.Request, id string) error {
	return b.serveHTTP(w, r, id, nil)
}

// ServeCarrier upgrades first and then acquires the admission guard. The
// guard serializes publication against session renewal and revocation. It
// must release its resources in the completion callback.
func (b *Bind) ServeCarrier(w http.ResponseWriter, r *http.Request, id string, admit func(conn.Endpoint) (complete func(bool), err error)) error {
	return b.serveHTTP(w, r, id, admit)
}

func (b *Bind) serveHTTP(w http.ResponseWriter, r *http.Request, id string, admit func(conn.Endpoint) (func(bool), error)) error {
	b.mu.Lock()
	ready, generation, limit := b.open, b.done, b.readLimit
	b.mu.Unlock()
	if !ready {
		return errors.New("WebSocket transport is not ready")
	}
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return err
	}
	if limit > 0 {
		ws.SetReadLimit(limit)
	}
	p := newPeer(id, ws, endpoint{id: id, address: endpointAddress(r.RemoteAddr)}, b.performance.Load())
	var complete func(bool)
	if admit != nil {
		ep := p.endpoint
		ep.pinned = true
		complete, err = admit(ep)
		if err != nil {
			_ = ws.CloseNow()
			return err
		}
	}
	b.callbacksMu.Lock()
	b.mu.Lock()
	if !b.open || b.done != generation {
		// Closed between the readiness check above and here -- b.peers is
		// nil now, so writing into it would panic. A client racing its own
		// redial against Close (see redial) is exactly the case that made
		// this window wide enough to hit in practice.
		b.mu.Unlock()
		b.callbacksMu.Unlock()
		if complete != nil {
			complete(false)
		}
		_ = ws.Close(websocket.StatusServiceRestart, "closing")
		return errors.New("WebSocket transport is not ready")
	}
	if old := b.peers[id]; old != nil {
		old.stopIO()
		if complete == nil {
			_ = old.ws.Close(websocket.StatusNormalClosure, "replaced")
		} else {
			_ = old.ws.CloseNow()
		}
	}
	p.bindDone, p.incoming = b.done, b.packets
	b.peers[id] = p
	b.mu.Unlock()
	if b.OnPeerConnected != nil {
		b.OnPeerConnected(id, p.endpoint)
	}
	b.callbacksMu.Unlock()
	if complete != nil {
		complete(true)
	}
	slog.Debug("WireGuard WebSocket peer connected", "peer", id, "remote", r.RemoteAddr)
	go b.read(p)
	// Keep the HTTP upgrade handler alive for the WebSocket's lifetime. This
	// is essential when the underlying net.Conn itself is relayed through a
	// second WebSocket: returning immediately lets net/http tear down request
	// state beneath the still-active transport.
	<-p.done
	return nil
}

func (b *Bind) read(p *peer) {
	go b.writeLoop(p)
	// Tie the heartbeat to this exact carrier, including redial replacements.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if b.url != "" {
		go b.keepalive(ctx, p)
	}
	defer func() {
		p.stopIO()
		b.callbacksMu.Lock()
		removed := b.remove(p)
		// A new connection with the same stable peer id may already have
		// replaced p. In that case p is stale and must not mark the replacement
		// carrier disconnected after its OnPeerConnected callback activated it.
		if removed && b.OnPeerDisconnected != nil {
			b.OnPeerDisconnected(p.id, p.endpoint)
		}
		b.callbacksMu.Unlock()
		close(p.done)
		slog.Debug("WireGuard WebSocket peer disconnected", "peer", p.id)
		// Only a client-side Bind (b.url != "") ever dials out; a server-side
		// Bind's peers arrive via ServeHTTP, and a disconnect there just means
		// the client is gone. Every client-side peer is "remote" (see Open and
		// redial), so b.url alone is a sufficient discriminator.
		b.mu.Lock()
		noRedial := b.noRedial
		b.mu.Unlock()
		if removed && b.url != "" && !noRedial {
			go b.redial(p.bindDone)
		}
	}()
	// Ordinary WireGuard datagrams fit here. A larger message can allocate
	// additional storage for that message without growing the scratch space.
	var scratch [2048]byte
	for {
		data, err := readWSSDatagram(p.ws, scratch[:])
		if err != nil {
			slog.Debug("WireGuard WebSocket read failed", "peer", p.id, "error", err)
			return
		}
		if data == nil {
			continue
		}
		select {
		case <-p.bindDone:
			return
		case <-p.stop:
			return
		case p.incoming <- packet{data, p.endpoint}:
		}
	}
}

func readWSSDatagram(ws *websocket.Conn, scratch []byte) ([]byte, error) {
	typ, reader, err := ws.Reader(context.Background())
	if err != nil {
		return nil, err
	}
	if typ != websocket.MessageBinary {
		// The next Reader can only start after this message is drained.
		_, err := io.Copy(io.Discard, reader)
		return nil, err
	}
	for used := 0; used < len(scratch); {
		n, err := reader.Read(scratch[used:])
		used += n
		if err == io.EOF {
			data, ok := Accept(scratch[:used])
			if !ok {
				return nil, nil
			}
			// The inbound queue may still own this frame during the next read.
			return bytes.Clone(data), nil
		}
		if err != nil {
			return nil, err
		}
	}
	tail, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if len(scratch)+len(tail) > maxDatagramSize {
		return nil, nil
	}
	data := make([]byte, len(scratch)+len(tail))
	copy(data, scratch)
	copy(data[len(scratch):], tail)
	return data, nil
}

// keepalive detects silent network loss even when no WireGuard packets are
// flowing and small writes still fit in the kernel's TCP buffers. Use native
// WebSocket control frames rather than multipath payload probes. The reader
// processes pongs concurrently; a missed pong closes only this carrier, and
// read's existing lifecycle path marks it unavailable and schedules redial.
func (b *Bind) keepalive(ctx context.Context, p *peer) {
	interval, timeout := b.pingInterval, b.pingTimeout
	if interval <= 0 {
		interval = pingIntervalDefault
	}
	if timeout <= 0 {
		timeout = pingTimeoutDefault
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var lastProbe time.Time
	for {
		sample := false
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-b.rttRequests:
			sample = true
		}
		if sample && p.writeBacklogged() {
			continue
		}
		if b.rttRequests != nil && time.Since(lastProbe) < 2*time.Second {
			continue
		}
		pingCtx, cancel := context.WithTimeout(ctx, timeout)
		started := time.Now()
		lastProbe = started
		err := p.ws.Ping(pingCtx)
		cancel()
		if err != nil {
			if sample {
				continue
			}
			if ctx.Err() == nil {
				slog.Debug("WireGuard WebSocket heartbeat failed", "peer", p.id, "error", err)
				p.stopIO()
				_ = p.ws.CloseNow()
			}
			return
		}
		p.pingRTT.Store(int64(time.Since(started)))
	}
}

// EnableDemandRTT prepares the client heartbeat loop to accept a bounded
// measurement request during forwarding. Call before opening the bind.
func (b *Bind) EnableDemandRTT() {
	b.rttRequests = make(chan struct{}, 1)
}

// RequestPeerRTT wakes the existing heartbeat loop with at most one
// pending request.
func (b *Bind) RequestPeerRTT() {
	select {
	case b.rttRequests <- struct{}{}:
	default:
	}
}

// PeerBacklogged provides a coarse pressure signal without enabling latency
// instrumentation or acquiring a queue writer's lock.
func (b *Bind) PeerBacklogged(id string) bool {
	pressured, connected := b.PeerQueuePressure(id)
	return !connected || pressured
}

// PeerQueuePressure distinguishes a live send queue from an absent peer.
func (b *Bind) PeerQueuePressure(id string) (pressured, connected bool) {
	b.mu.Lock()
	p := b.peers[id]
	b.mu.Unlock()
	return p != nil && p.writeBacklogged(), p != nil
}

func (p *peer) writeBacklogged() bool {
	if p.overflow.Load() > 0 {
		return true
	}
	switch {
	case p.sampled != nil:
		return len(p.sampled.out) > cap(p.sampled.out)/8
	default:
		return len(p.out) > cap(p.out)/8
	}
}

// PeerRTT is the most recent successful WebSocket heartbeat RTT for the
// current peer incarnation. It is zero before a heartbeat completes.
func (b *Bind) PeerRTT(id string) time.Duration {
	b.mu.Lock()
	p := b.peers[id]
	b.mu.Unlock()
	if p == nil {
		return 0
	}
	return time.Duration(p.pingRTT.Load())
}

func (b *Bind) remove(p *peer) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.peers[p.id] == p {
		delete(b.peers, p.id)
		return true
	}
	return false
}

// redial keeps retrying the client-side WebSocket dial, with jittered
// exponential backoff, until it succeeds or the bind closes. Without this,
// once the "remote" peer's TCP connection drops (interface change, NAT
// rebind, a proxy hiccup), Send fails permanently and nothing above this
// layer -- Hybrid's WSSentinel fallback, MultipathBind's "wss" candidate --
// ever gets a working WebSocket carrier again for the rest of the process's
// life. A successful redial needs no coordination with either caller: both
// route by the stable endpoint{id:"remote"} value, resolved through
// b.peers["remote"] at Send time, so a fresh peer object under the same id
// is immediately usable with no re-registration.
func (b *Bind) redial(done <-chan struct{}) {
	b.mu.Lock()
	backoff := b.redialMin
	b.mu.Unlock()
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			// Full jitter: spreads out redial attempts from many peers that
			// dropped at the same moment (e.g. a shared uplink flapping)
			// instead of them all retrying in lockstep.
			if backoff <= 0 {
				backoff = time.Millisecond
			}
			wait := time.Duration(rand.Int63n(int64(backoff)))
			select {
			case <-done:
				return
			case <-time.After(wait):
			}
			b.mu.Lock()
			redialMax := b.redialMax
			b.mu.Unlock()
			backoff = min(backoff*2, redialMax)
		}
		select {
		case <-done:
			return
		default:
		}
		b.mu.Lock()
		url, client, header := b.url, b.client, b.header
		dialTimeout, limit := b.dialTimeout, b.readLimit
		b.mu.Unlock()
		dialCtx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		ws, _, err := websocket.Dial(dialCtx, url, &websocket.DialOptions{HTTPClient: client, HTTPHeader: header})
		cancel()
		if err != nil {
			slog.Debug("WireGuard WebSocket redial failed", "error", err)
			continue
		}
		if limit > 0 {
			ws.SetReadLimit(limit)
		}
		p := newPeer("remote", ws, endpoint{id: "remote", address: endpointAddress(url)}, b.performance.Load())
		b.callbacksMu.Lock()
		b.mu.Lock()
		if !b.open || b.done != done {
			// Closed, or closed and reopened, while this attempt was dialing.
			b.mu.Unlock()
			b.callbacksMu.Unlock()
			_ = ws.Close(websocket.StatusNormalClosure, "closing")
			return
		}
		p.bindDone, p.incoming = b.done, b.packets
		b.peers[p.id] = p
		b.mu.Unlock()
		if b.OnPeerConnected != nil {
			b.OnPeerConnected(p.id, p.endpoint)
		}
		b.callbacksMu.Unlock()
		slog.Debug("WireGuard WebSocket peer reconnected", "peer", p.id)
		go b.read(p)
		return
	}
}

// CloseSession immediately terminates the fallback transport for a revoked or
// expired server session.
func (b *Bind) CloseSession(id string) {
	b.mu.Lock()
	p := b.peers[id]
	delete(b.peers, id)
	b.mu.Unlock()
	if p != nil {
		p.stopIO()
		// Close waits for the peer's close handshake; never hold the caller
		// (often under server locks) behind an unresponsive carrier.
		go func() { _ = p.ws.Close(websocket.StatusPolicyViolation, "session closed") }()
	}
}

func (b *Bind) Close() error {
	b.mu.Lock()
	if !b.open {
		b.mu.Unlock()
		return nil
	}
	close(b.done)
	b.open = false
	peers := b.peers
	b.peers = nil
	b.mu.Unlock()
	for _, p := range peers {
		p.stopIO()
		_ = p.ws.Close(websocket.StatusNormalClosure, "closed")
	}
	return nil
}
func (*Bind) SetMark(uint32) error { return nil }
func (*Bind) BatchSize() int       { return conn.IdealBatchSize }
func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(endpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	b.mu.Lock()
	p := b.peers[e.id]
	b.mu.Unlock()
	if p == nil || (e.pinned && e.carrier != p.endpoint.carrier) {
		return fmt.Errorf("WebSocket peer is not connected")
	}
	var batch [][]byte
	if len(bufs) == 1 {
		if ValidDatagram(bufs[0]) {
			batch = [][]byte{append([]byte(nil), bufs[0]...)}
		}
	} else {
		batch = copyWSSBatch(bufs)
	}
	if len(batch) == 0 {
		return nil
	}
	switch p.enqueue(batch) {
	case queueClosed:
		return fmt.Errorf("WebSocket peer is not connected")
	case queueAccepted:
		p.overflow.Store(0)
	case queueFull:
		b.Dropped.Add(1)
		if p.overflow.Add(1) == overflowFailureThreshold {
			slog.Warn("WireGuard WebSocket carrier is not draining; dropping", "peer", p.id)
			// Closing wakes read's disconnect/redial path even if the
			// writer subsequently drains. Keep Send independent of callbacks.
			go func() {
				p.stopIO()
				b.reportWriteFailure(p)
				_ = p.ws.CloseNow()
			}()
		}
	}
	return nil
}

func copyWSSBatch(bufs [][]byte) [][]byte {
	// Larger calls outside WireGuard's batch contract keep per-datagram copies.
	if len(bufs) > conn.IdealBatchSize {
		batch := make([][]byte, 0, len(bufs))
		for _, buf := range bufs {
			if ValidDatagram(buf) {
				batch = append(batch, append([]byte(nil), buf...))
			}
		}
		return batch
	}
	var count, size int
	for _, buf := range bufs {
		if ValidDatagram(buf) {
			count++
			size += len(buf)
		}
	}
	if count == 0 {
		return nil
	}
	batch := make([][]byte, 0, count)
	storage := make([]byte, size)
	for _, buf := range bufs {
		if ValidDatagram(buf) {
			n := copy(storage, buf)
			batch = append(batch, storage[:n:n])
			storage = storage[n:]
		}
	}
	return batch
}

func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	b.mu.Lock()
	_, ok := b.peers["remote"]
	b.mu.Unlock()
	if b.url != "" && !ok {
		return nil, fmt.Errorf("WebSocket peer is not connected")
	}
	return endpoint{id: "remote", address: endpointAddress(s)}, nil
}
func (e endpoint) ClearSrc()           {}
func (e endpoint) SrcToString() string { return "" }
func (e endpoint) DstToString() string { return e.address.String() }
func (e endpoint) DstToBytes() []byte  { b, _ := e.address.MarshalBinary(); return b }
func (e endpoint) DstIP() netip.Addr   { return e.address.Addr() }
func (e endpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func endpointAddress(value string) netip.AddrPort {
	host, port, err := net.SplitHostPort(value)
	if err == nil {
		if p, e := netip.ParseAddrPort(net.JoinHostPort(host, port)); e == nil {
			return p
		}
	}
	return netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
}
