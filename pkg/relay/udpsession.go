package relay

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

// ErrPoolExhausted is returned by udpSessionTable.Allocate when every port in
// the relay's configured listen.udp_relay_ports range is already claimed by
// a live session.
var ErrPoolExhausted = fmt.Errorf("udp relay port pool exhausted")

// ErrUDPRelayTenantAtCapacity is Allocate's per-tenant analogue to
// ErrPoolExhausted: this tenant is at limits.max_udp_relay_sessions_per_server
// even though the relay-wide pool still has free ports, the same
// relationship ErrTenantAtCapacity has to the relay-wide fd budget for the
// TLS-passthrough tier.
var ErrUDPRelayTenantAtCapacity = fmt.Errorf("udp relay tenant session capacity exceeded")

// portAllocator hands out relay-side UDP ports for the UDP-relay tier's
// server leg from a fixed, pre-bound pool. One port is reserved per live
// session because WireGuard's per-peer single-endpoint model needs every
// session to look like a distinct server-facing address -- the datagram
// equivalent of Registry minting one conn_id per TLS-passthrough connection.
// Every net.PacketConn in the pool is opened once at Relay.Start and never
// closed until the relay itself shuts down; allocate/release only flip an
// in-use bit, never open or close a socket, so session churn never pays a
// bind() syscall.
type portAllocator struct {
	mu    sync.Mutex
	conns map[uint16]net.PacketConn // every pooled port's socket; fixed after Start
	free  []uint16
	inUse map[uint16]bool
}

// newPortAllocator takes ownership of conns (keyed by port); the caller must
// not use them directly afterward except to Close the whole pool on shutdown.
func newPortAllocator(conns map[uint16]net.PacketConn) *portAllocator {
	free := make([]uint16, 0, len(conns))
	for port := range conns {
		free = append(free, port)
	}
	sort.Slice(free, func(i, j int) bool { return free[i] < free[j] })
	return &portAllocator{conns: conns, free: free, inUse: map[uint16]bool{}}
}

func (p *portAllocator) allocate() (port uint16, conn net.PacketConn, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.free) == 0 {
		return 0, nil, false
	}
	port = p.free[len(p.free)-1]
	p.free = p.free[:len(p.free)-1]
	p.inUse[port] = true
	return port, p.conns[port], true
}

func (p *portAllocator) release(port uint16) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.inUse[port] {
		return
	}
	delete(p.inUse, port)
	p.free = append(p.free, port)
}

// udpRelaySession is one live TURN-style pairing: a dedicated server-leg
// port and (once bound) a locked client-leg source address. Both legs are
// tracked independently -- forwarding starts only once both are bound (see
// datagramRelay) -- and either leg's bind frame can re-lock its own address
// (a keepalive that also doubles as a rebind signal if a NAT mapping
// changed) without touching the other leg's state.
type udpRelaySession struct {
	token      string
	tenant     string
	serverPort uint16
	// serverConn is this session's own pooled socket. Every server-ward
	// write MUST go out this conn, never a shared/convenience socket, or a
	// datagram arriving at the server from an unexpected source triggers
	// WireGuard's own passive peer-roaming there and corrupts the demux
	// mapping this whole per-session-port scheme exists to avoid.
	serverConn net.PacketConn

	mu          sync.Mutex
	serverAddr  netip.AddrPort // locked once the server's bind frame arrives
	serverBound bool
	clientAddr  netip.AddrPort // locked once the client's bind frame arrives
	clientBound bool

	lastActivity           atomic.Int64 // unix nanos; touched by any bind/keepalive/forwarded frame
	clientPacketsReceived  atomic.Uint64
	clientBytesReceived    atomic.Uint64
	serverPacketsForwarded atomic.Uint64
	serverBytesForwarded   atomic.Uint64
	serverPacketsReceived  atomic.Uint64
	serverBytesReceived    atomic.Uint64
	clientPacketsForwarded atomic.Uint64
	clientBytesForwarded   atomic.Uint64
}

func (s *udpRelaySession) touch() { s.lastActivity.Store(time.Now().UnixNano()) }

func (s *udpRelaySession) idleFor() time.Duration {
	return time.Since(time.Unix(0, s.lastActivity.Load()))
}

func (s *udpRelaySession) clientReceived(n int) {
	s.clientPacketsReceived.Add(1)
	s.clientBytesReceived.Add(uint64(n))
}

func (s *udpRelaySession) serverForwarded(n int) {
	s.serverPacketsForwarded.Add(1)
	s.serverBytesForwarded.Add(uint64(n))
}

func (s *udpRelaySession) serverReceived(n int) {
	s.serverPacketsReceived.Add(1)
	s.serverBytesReceived.Add(uint64(n))
}

func (s *udpRelaySession) clientForwarded(n int) {
	s.clientPacketsForwarded.Add(1)
	s.clientBytesForwarded.Add(uint64(n))
}

// legs returns the session's current bind state under its own lock, for
// callers (datagramRelay's forwarding path) that need a consistent snapshot
// of both legs at once rather than two separately-locked reads that could
// race a concurrent bind.
func (s *udpRelaySession) legs() (serverAddr netip.AddrPort, serverBound bool, clientAddr netip.AddrPort, clientBound bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.serverAddr, s.serverBound, s.clientAddr, s.clientBound
}

// udpSessionTable owns the port allocator, the token- and (bound)
// clientAddr-keyed session indexes, per-tenant session counts, and the idle
// sweep for the UDP-relay forwarding tier. It is kept as a sibling to
// Registry rather than folded into it: Registry owns the TLS-passthrough
// tier's pending/live counters and conn_id capability lifecycle -- single-use,
// redeemed exactly once -- a shape this tier does not share, since a
// UDP-relay session is long-lived and re-bindable.
type udpSessionTable struct {
	mu       sync.Mutex
	alloc    *portAllocator
	byToken  map[string]*udpRelaySession
	byPort   map[uint16]*udpRelaySession
	byClient map[netip.AddrPort]*udpRelaySession // populated/moved only on a client bind frame
	tenantN  map[string]int
	limits   Limits
}

func newUDPSessionTable(alloc *portAllocator, limits Limits) *udpSessionTable {
	return &udpSessionTable{
		alloc:    alloc,
		byToken:  map[string]*udpRelaySession{},
		byPort:   map[uint16]*udpRelaySession{},
		byClient: map[netip.AddrPort]*udpRelaySession{},
		tenantN:  map[string]int{},
		limits:   limits,
	}
}

// Allocate mints a new UDP-relay session for tenant, reserving one pooled
// port on the server leg. serverAddr is that port's own bound address (the
// same LocalAddr().String() convention the reflector's ReflectAddr already
// uses), which the caller threads back to the server over the control
// connection.
func (t *udpSessionTable) Allocate(tenant string) (token, serverAddr string, err error) {
	t.mu.Lock()
	if t.tenantN[tenant] >= t.limits.MaxUDPRelaySessionsPerServer {
		t.mu.Unlock()
		return "", "", ErrUDPRelayTenantAtCapacity
	}
	t.mu.Unlock()

	port, conn, ok := t.alloc.allocate()
	if !ok {
		return "", "", ErrPoolExhausted
	}
	tok, err := randomConnID() // same 32-byte random-token shape Registry uses for conn_id
	if err != nil {
		t.alloc.release(port)
		return "", "", err
	}
	sess := &udpRelaySession{token: tok, tenant: tenant, serverPort: port, serverConn: conn}
	sess.touch()

	t.mu.Lock()
	t.byToken[tok] = sess
	t.byPort[port] = sess
	t.tenantN[tenant]++
	t.mu.Unlock()

	return tok, conn.LocalAddr().String(), nil
}

// BindServer locks the session identified by token's server leg to from, the
// source address its bind frame arrived from. A repeat call with the same
// token re-locks to a new from address rather than being rejected -- see
// wstransport.FrameRelayBind's doc comment for why a token-authenticated
// rebind is the intended model, not just a first-seen-wins address lock.
func (t *udpSessionTable) BindServer(token string, from netip.AddrPort) (*udpRelaySession, bool) {
	t.mu.Lock()
	sess, ok := t.byToken[token]
	t.mu.Unlock()
	if !ok {
		return nil, false
	}
	sess.mu.Lock()
	sess.serverAddr, sess.serverBound = from, true
	sess.mu.Unlock()
	sess.touch()
	return sess, true
}

// BindClient locks the session identified by token's client leg to from, and
// maintains the byClient index used to demux ordinary (non-bind) datagrams
// arriving on the shared client-facing socket. See BindServer on rebinding.
func (t *udpSessionTable) BindClient(token string, from netip.AddrPort) (*udpRelaySession, bool) {
	t.mu.Lock()
	sess, ok := t.byToken[token]
	t.mu.Unlock()
	if !ok {
		return nil, false
	}
	sess.mu.Lock()
	prevAddr, prevBound := sess.clientAddr, sess.clientBound
	sess.clientAddr, sess.clientBound = from, true
	sess.mu.Unlock()
	sess.touch()

	t.mu.Lock()
	if prevBound && prevAddr != from && t.byClient[prevAddr] == sess {
		delete(t.byClient, prevAddr)
	}
	t.byClient[from] = sess
	t.mu.Unlock()
	return sess, true
}

// LookupByClientAddr finds the session, if any, whose client leg is
// currently locked to addr -- the demux path for every client-facing
// datagram that isn't itself a bind frame.
func (t *udpSessionTable) LookupByClientAddr(addr netip.AddrPort) (*udpRelaySession, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	sess, ok := t.byClient[addr]
	return sess, ok
}

// sessionForPort finds the session currently bound to one of the pooled
// server-leg ports -- the demux path for every server-facing datagram, since
// each pooled socket's serve goroutine only knows its own fixed port, and
// that port is reused across sessions over the relay's lifetime.
func (t *udpSessionTable) sessionForPort(port uint16) (*udpRelaySession, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	sess, ok := t.byPort[port]
	return sess, ok
}

// StatsForTenant returns a bounded snapshot for sessions owned by tenant.
// It is called only from the relay's authenticated control loop, so allocation
// tokens never cross tenant boundaries or reach an unauthenticated listener.
func (t *udpSessionTable) StatsForTenant(tenant string) []protocol.RelayUDPStats {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]protocol.RelayUDPStats, 0, t.tenantN[tenant])
	for _, s := range t.byToken {
		if s.tenant != tenant {
			continue
		}
		out = append(out, protocol.RelayUDPStats{
			Token:                  s.token,
			ClientPacketsReceived:  s.clientPacketsReceived.Load(),
			ClientBytesReceived:    s.clientBytesReceived.Load(),
			ServerPacketsForwarded: s.serverPacketsForwarded.Load(),
			ServerBytesForwarded:   s.serverBytesForwarded.Load(),
			ServerPacketsReceived:  s.serverPacketsReceived.Load(),
			ServerBytesReceived:    s.serverBytesReceived.Load(),
			ClientPacketsForwarded: s.clientPacketsForwarded.Load(),
			ClientBytesForwarded:   s.clientBytesForwarded.Load(),
		})
	}
	return out
}

// Release tears down the session identified by token: both index entries are
// removed synchronously (a NAT reusing a freed external port for a different
// client must never hit a stale byClient mapping) and its pooled port is
// returned to the allocator. Releasing an unknown token is a no-op, since
// both the client's revert path and the relay's own idle sweep can race a
// server's explicit RelayUDPRelease for the same session.
func (t *udpSessionTable) Release(token string) {
	t.mu.Lock()
	sess, ok := t.byToken[token]
	if !ok {
		t.mu.Unlock()
		return
	}
	delete(t.byToken, token)
	delete(t.byPort, sess.serverPort)
	t.tenantN[sess.tenant]--
	if t.tenantN[sess.tenant] <= 0 {
		delete(t.tenantN, sess.tenant)
	}
	t.mu.Unlock()

	sess.mu.Lock()
	clientAddr, clientBound := sess.clientAddr, sess.clientBound
	sess.mu.Unlock()
	if clientBound {
		t.mu.Lock()
		if t.byClient[clientAddr] == sess {
			delete(t.byClient, clientAddr)
		}
		t.mu.Unlock()
	}

	t.alloc.release(sess.serverPort)
}

// runIdleSweep reclaims any session with no bind/keepalive/forwarded traffic
// on either leg within idleTimeout, until stop is closed. It is the backstop
// for a session whose server never sends RelayUDPRelease (crash, or a
// control-connection drop with no reconnect) -- the same role
// Registry.useNonceLocked's expiry sweep plays for the nonce cache, just
// ticker-driven here instead of amortized onto each new use.
func (t *udpSessionTable) runIdleSweep(stop <-chan struct{}, idleTimeout time.Duration) {
	interval := idleTimeout / 4
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			t.sweepOnce(idleTimeout)
		case <-stop:
			return
		}
	}
}

func (t *udpSessionTable) sweepOnce(idleTimeout time.Duration) {
	t.mu.Lock()
	var stale []string
	for tok, sess := range t.byToken {
		if sess.idleFor() > idleTimeout {
			stale = append(stale, tok)
		}
	}
	t.mu.Unlock()
	for _, tok := range stale {
		t.Release(tok)
	}
}
