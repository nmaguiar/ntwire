package wstransport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/coder/websocket"
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
	// noRedial disables the automatic reconnect entirely -- see DisableRedial.
	noRedial bool

	mu              sync.Mutex
	open            bool
	done            chan struct{}
	packets         chan packet
	peers           map[string]*peer
	header          http.Header
	OnPeerConnected func(string, conn.Endpoint)
	// OnPeerDisconnected mirrors OnPeerConnected for lifecycle consumers.
	// Callbacks run outside Bind's mutex and must not retain credentials.
	OnPeerDisconnected func(string, conn.Endpoint)
}

type packet struct {
	data     []byte
	endpoint conn.Endpoint
}
type peer struct {
	id       string
	ws       *websocket.Conn
	endpoint endpoint
	done     chan struct{}
}
type endpoint struct {
	id      string
	address netip.AddrPort
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
func NewHybrid() *Hybrid {
	return &Hybrid{UDP: NewFilterBind(conn.NewStdNetBind()), WebSocket: NewServer()}
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
func NewHybridClient(url string, client *http.Client, header http.Header) *Hybrid {
	return &Hybrid{UDP: NewFilterBind(conn.NewStdNetBind()), WebSocket: NewClient(url, client, header)}
}

// NewMultipathHybridClient returns the existing carrier pair plus the stable
// logical bind used by capable relay peers. WSS is registered first and is
// immediately usable; UDP candidates are added only after their authenticated
// setup succeeds.
func NewMultipathHybridClient(url string, client *http.Client, header http.Header, v2 bool, opts V2Options) (*Hybrid, *MultipathBind) {
	h := NewHybridClient(url, client, header)
	m := NewMultipathBind(h, "relay-server", v2, opts)
	h.UDP.(*FilterBind).SetProbeHandler(m.handlePathControl)
	// Bind.ParseEndpoint intentionally rejects a client WebSocket before Open
	// has connected it. Register the fallback from MultipathBind.Open instead,
	// after h.Open has established the peer. RegisterPath itself fires an
	// immediate real probe (see its doc comment); a synthetic ProbeResult
	// seed used to stand in here, but that's what left "wss" and every other
	// candidate frozen at whatever health they started with forever, since
	// nothing ever re-probed them afterward.
	m.onOpen = func() error {
		ep, err := h.WebSocket.ParseEndpoint(WSSentinel)
		if err != nil {
			return err
		}
		m.RegisterPath("wss", PathWSS, ep)
		return nil
	}
	return h, m
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
	redialMinDefault   = time.Second
	redialMaxDefault   = 30 * time.Second
	dialTimeoutDefault = 10 * time.Second
)

func NewClient(url string, client *http.Client, header http.Header) *Bind {
	return &Bind{url: url, client: client, header: header, redialMin: redialMinDefault, redialMax: redialMaxDefault, dialTimeout: dialTimeoutDefault}
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

// NewServer creates a bind whose ServeHTTP method attaches authenticated
// WebSocket connections. The id is usually the ntwire session ID.
func NewServer() *Bind { return &Bind{} }

func (b *Bind) Open(_ uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	if b.open {
		b.mu.Unlock()
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	b.open, b.done = true, make(chan struct{})
	b.packets, b.peers = make(chan packet, conn.IdealBatchSize), map[string]*peer{}
	var connected *peer
	var onConnected func(string, conn.Endpoint)
	if b.url != "" {
		ws, _, err := websocket.Dial(context.Background(), b.url, &websocket.DialOptions{HTTPClient: b.client, HTTPHeader: b.header})
		if err != nil {
			close(b.done)
			b.open = false
			b.mu.Unlock()
			return nil, 0, err
		}
		p := &peer{id: "remote", ws: ws, endpoint: endpoint{id: "remote", address: endpointAddress(b.url)}, done: make(chan struct{})}
		b.peers[p.id] = p
		connected, onConnected = p, b.OnPeerConnected
	}
	b.mu.Unlock()
	if connected != nil {
		if onConnected != nil {
			onConnected(connected.id, connected.endpoint)
		}
		go b.read(connected)
	}
	return []conn.ReceiveFunc{b.receive}, 0, nil
}

func (b *Bind) receive(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	select {
	case <-b.done:
		return 0, net.ErrClosed
	case first := <-b.packets:
		sizes[0] = copy(bufs[0], first.data)
		eps[0] = first.endpoint
		n := 1
		for n < len(bufs) {
			select {
			case p := <-b.packets:
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

func (b *Bind) ServeHTTP(w http.ResponseWriter, r *http.Request, id string) error {
	b.mu.Lock()
	ready := b.open
	b.mu.Unlock()
	if !ready {
		return errors.New("WebSocket transport is not ready")
	}
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return err
	}
	p := &peer{id: id, ws: ws, endpoint: endpoint{id: id, address: endpointAddress(r.RemoteAddr)}, done: make(chan struct{})}
	b.mu.Lock()
	if !b.open {
		// Closed between the readiness check above and here -- b.peers is
		// nil now, so writing into it would panic. A client racing its own
		// redial against Close (see redial) is exactly the case that made
		// this window wide enough to hit in practice.
		b.mu.Unlock()
		_ = ws.Close(websocket.StatusServiceRestart, "closing")
		return errors.New("WebSocket transport is not ready")
	}
	if old := b.peers[id]; old != nil {
		_ = old.ws.Close(websocket.StatusNormalClosure, "replaced")
	}
	b.peers[id] = p
	b.mu.Unlock()
	if b.OnPeerConnected != nil {
		b.OnPeerConnected(id, p.endpoint)
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
	defer func() {
		b.remove(p)
		close(p.done)
		if b.OnPeerDisconnected != nil {
			b.OnPeerDisconnected(p.id, p.endpoint)
		}
		slog.Debug("WireGuard WebSocket peer disconnected", "peer", p.id)
		// Only a client-side Bind (b.url != "") ever dials out; a server-side
		// Bind's peers arrive via ServeHTTP, and a disconnect there just means
		// the client is gone. Every client-side peer is "remote" (see Open and
		// redial), so b.url alone is a sufficient discriminator.
		b.mu.Lock()
		noRedial := b.noRedial
		b.mu.Unlock()
		if b.url != "" && !noRedial {
			go b.redial()
		}
	}()
	for {
		typ, data, err := p.ws.Read(context.Background())
		if err != nil {
			slog.Debug("WireGuard WebSocket read failed", "peer", p.id, "error", err)
			return
		}
		if typ != websocket.MessageBinary {
			continue
		}
		data, ok := Accept(data)
		if !ok {
			continue
		}
		copyData := append([]byte(nil), data...)
		select {
		case <-b.done:
			return
		case b.packets <- packet{copyData, p.endpoint}:
		}
	}
}

func (b *Bind) remove(p *peer) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.peers[p.id] == p {
		delete(b.peers, p.id)
	}
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
func (b *Bind) redial() {
	b.mu.Lock()
	done := b.done
	b.mu.Unlock()
	backoff := b.redialMin
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
			backoff = min(backoff*2, b.redialMax)
		}
		select {
		case <-done:
			return
		default:
		}
		b.mu.Lock()
		url, client, header := b.url, b.client, b.header
		b.mu.Unlock()
		dialCtx, cancel := context.WithTimeout(context.Background(), b.dialTimeout)
		ws, _, err := websocket.Dial(dialCtx, url, &websocket.DialOptions{HTTPClient: client, HTTPHeader: header})
		cancel()
		if err != nil {
			slog.Debug("WireGuard WebSocket redial failed", "error", err)
			continue
		}
		p := &peer{id: "remote", ws: ws, endpoint: endpoint{id: "remote", address: endpointAddress(url)}, done: make(chan struct{})}
		b.mu.Lock()
		if !b.open || b.done != done {
			// Closed, or closed and reopened, while this attempt was dialing.
			b.mu.Unlock()
			_ = ws.Close(websocket.StatusNormalClosure, "closing")
			return
		}
		b.peers[p.id] = p
		b.mu.Unlock()
		if b.OnPeerConnected != nil {
			b.OnPeerConnected(p.id, p.endpoint)
		}
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
		_ = p.ws.Close(websocket.StatusPolicyViolation, "session closed")
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
	if p == nil {
		return fmt.Errorf("WebSocket peer is not connected")
	}
	for _, buf := range bufs {
		if !ValidDatagram(buf) {
			continue
		}
		if err := p.ws.Write(context.Background(), websocket.MessageBinary, buf); err != nil {
			return err
		}
	}
	return nil
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
