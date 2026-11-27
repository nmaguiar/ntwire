package wstransport

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/conn"
)

// DefaultUDPBufferBytes is the requested read and write capacity for each
// userspace WireGuard UDP socket. Kernels may clamp it; that is reported but
// never prevents a tunnel from starting.
const DefaultUDPBufferBytes = 4 << 20

// UDPBufferStatus records the requested and kernel-accepted capacity of one
// WireGuard UDP socket. Socket is "ipv4" or "ipv6".
type UDPBufferStatus struct {
	Socket    string
	Requested int
	Read      int
	Write     int
	Err       error
}

// UDPBind owns the sockets used by a userspace WireGuard device. Unlike
// conn.StdNetBind, it can tune them immediately after opening while retaining
// batched UDP I/O on Linux.
type UDPBind struct {
	mu           sync.Mutex
	ipv4         *net.UDPConn
	ipv6         *net.UDPConn
	requested    int
	log          *slog.Logger
	status       []UDPBufferStatus
	receiveStop  chan struct{}
	dontFragment bool

	// altPort, when non-zero, opens a second socket pair on that port (for
	// example 443/udp for networks that only pass QUIC-like traffic). It is
	// opt-in; with altPort zero none of the alt fields are touched and the
	// receive/send paths are unchanged.
	altPort    uint16
	alt4, alt6 *net.UDPConn
	// altPeers remembers sources whose most recent datagram arrived on an
	// alt socket, so replies leave from the socket the peer's NAT mapping
	// expects. Keyed by netip.AddrPort; values are *atomic.Int64 holding the
	// last-seen time (UnixNano). It is bounded by altPeerLimit and
	// altPeerTTL, so unsolicited or spoofed datagrams to the alternate port
	// cannot grow it without bound; an evicted or rejected source simply
	// gets replies from the primary socket.
	altPeers     sync.Map
	altPeerCount atomic.Int64
	altSweepMu   sync.Mutex
}

const (
	// altPeerLimit caps remembered alternate-port sources.
	altPeerLimit = 4096
	// altPeerTTL forgets a source that has sent nothing on the alternate
	// port for this long. Multipath probes (1 s) and WireGuard keepalives
	// keep live peers fresh.
	altPeerTTL = 3 * time.Minute
)

// noteAltPeer records key as last seen on the alternate socket.
func (b *UDPBind) noteAltPeer(key netip.AddrPort, now time.Time) {
	if v, ok := b.altPeers.Load(key); ok {
		seen := v.(*atomic.Int64)
		if now.UnixNano()-seen.Load() > int64(time.Second) {
			seen.Store(now.UnixNano())
		}
		return
	}
	if b.altPeerCount.Load() >= altPeerLimit {
		b.sweepAltPeers(now)
		if b.altPeerCount.Load() >= altPeerLimit {
			return
		}
	}
	seen := &atomic.Int64{}
	seen.Store(now.UnixNano())
	if _, loaded := b.altPeers.LoadOrStore(key, seen); !loaded {
		b.altPeerCount.Add(1)
	}
}

func (b *UDPBind) forgetAltPeer(key netip.AddrPort) {
	if _, loaded := b.altPeers.LoadAndDelete(key); loaded {
		b.altPeerCount.Add(-1)
	}
}

// sweepAltPeers drops expired entries. Only one sweep runs at a time.
func (b *UDPBind) sweepAltPeers(now time.Time) {
	if !b.altSweepMu.TryLock() {
		return
	}
	defer b.altSweepMu.Unlock()
	b.altPeers.Range(func(k, v any) bool {
		if now.UnixNano()-v.(*atomic.Int64).Load() > int64(altPeerTTL) {
			b.forgetAltPeer(k.(netip.AddrPort))
		}
		return true
	})
}

// isAltPeer reports whether replies to key should use the alternate socket.
func (b *UDPBind) isAltPeer(key netip.AddrPort, now time.Time) bool {
	v, ok := b.altPeers.Load(key)
	return ok && now.UnixNano()-v.(*atomic.Int64).Load() <= int64(altPeerTTL)
}

// SetAltPort configures an additional listening port, opened by the next
// Open. It must be called before Open; zero disables the alternate socket.
func (b *UDPBind) SetAltPort(port uint16) {
	b.mu.Lock()
	b.altPort = port
	b.mu.Unlock()
}

// NewUDPBind returns a WireGuard UDP bind with a validated buffer request.
// A non-positive requested value uses DefaultUDPBufferBytes. log may be nil
// when callers expose BufferStatus through another diagnostic surface.
func NewUDPBind(requested int, log *slog.Logger) *UDPBind {
	if requested <= 0 {
		requested = DefaultUDPBufferBytes
	}
	return &UDPBind{requested: requested, log: log}
}

// NewProbeUDPBind opens a dedicated UDP socket with IP fragmentation
// disabled. A sized path proof must cross the network as one datagram.
func NewProbeUDPBind() *UDPBind {
	b := NewUDPBind(0, nil)
	b.dontFragment = true
	return b
}

func dontFragmentUDP(socket *net.UDPConn, ipv6 bool) error {
	if socket == nil {
		return nil
	}
	raw, err := socket.SyscallConn()
	if err != nil {
		return err
	}
	var optErr error
	err = raw.Control(func(fd uintptr) { optErr = setUDPDontFragment(fd, ipv6) })
	return errors.Join(err, optErr)
}

// BufferStatus returns a snapshot of the buffer settings from the most recent
// successful Open. Inspection errors are included rather than hidden, since a
// platform may support setting a buffer without exposing its effective value.
func (b *UDPBind) BufferStatus() []UDPBufferStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]UDPBufferStatus(nil), b.status...)
}

func (b *UDPBind) Open(uport uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ipv4 != nil || b.ipv6 != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	if b.dontFragment && b.altPort != 0 {
		return nil, 0, errors.New("use a separate bind for each UDP proof socket")
	}
	var tries int
again:
	port := int(uport)
	v4, err4 := net.ListenUDP("udp4", &net.UDPAddr{Port: port})
	if err4 != nil && !errors.Is(err4, syscall.EAFNOSUPPORT) {
		return nil, 0, err4
	}
	if v4 != nil {
		port = v4.LocalAddr().(*net.UDPAddr).Port
	}
	v6, err6 := net.ListenUDP("udp6", &net.UDPAddr{Port: port})
	if uport == 0 && errors.Is(err6, syscall.EADDRINUSE) && tries < 100 {
		if v4 != nil {
			_ = v4.Close()
		}
		tries++
		goto again
	}
	if err6 != nil && !errors.Is(err6, syscall.EAFNOSUPPORT) {
		if v4 != nil {
			_ = v4.Close()
		}
		return nil, 0, err6
	}
	if v4 == nil && v6 == nil {
		return nil, 0, syscall.EAFNOSUPPORT
	}

	if b.dontFragment {
		if err := errors.Join(dontFragmentUDP(v4, false), dontFragmentUDP(v6, true)); err != nil {
			if v4 != nil {
				_ = v4.Close()
			}
			if v6 != nil {
				_ = v6.Close()
			}
			return nil, 0, fmt.Errorf("disable adaptive UDP fragmentation: %w", err)
		}
	}
	b.status = b.status[:0]
	if v4 != nil {
		b.recordBufferStatus("ipv4", v4)
		b.ipv4 = v4
	}
	if v6 != nil {
		b.recordBufferStatus("ipv6", v6)
		b.ipv6 = v6
	}
	var a4, a6 *net.UDPConn
	if b.altPort != 0 {
		var err error
		if a4, a6, err = listenUDPPair(int(b.altPort)); err != nil {
			b.closeLocked()
			if v4 != nil {
				_ = v4.Close()
			}
			if v6 != nil {
				_ = v6.Close()
			}
			b.ipv4, b.ipv6 = nil, nil
			return nil, 0, fmt.Errorf("alternate WireGuard UDP port %d: %w", b.altPort, err)
		}
		if a4 != nil {
			b.recordBufferStatus("ipv4-alt", a4)
		}
		if a6 != nil {
			b.recordBufferStatus("ipv6-alt", a6)
		}
		b.alt4 = a4
		b.alt6 = a6
	}
	fns := make([]conn.ReceiveFunc, 0, 4)
	b.receiveStop = make(chan struct{})
	alt := b.altPort != 0
	if v4 != nil {
		fns = append(fns, resilientUDPReceive(b.trackAlt(makeUDPReceive(ipv4.NewPacketConn(v4), v4), alt, false), b.receiveStop, b.log, "ipv4"))
	}
	if v6 != nil {
		fns = append(fns, resilientUDPReceive(b.trackAlt(makeUDPReceive(ipv6.NewPacketConn(v6), v6), alt, false), b.receiveStop, b.log, "ipv6"))
	}
	if a4 != nil {
		fns = append(fns, resilientUDPReceive(b.trackAlt(makeUDPReceive(ipv4.NewPacketConn(a4), a4), true, true), b.receiveStop, b.log, "ipv4-alt"))
	}
	if a6 != nil {
		fns = append(fns, resilientUDPReceive(b.trackAlt(makeUDPReceive(ipv6.NewPacketConn(a6), a6), true, true), b.receiveStop, b.log, "ipv6-alt"))
	}
	return fns, uint16(port), nil
}

// listenUDPPair opens IPv4 and IPv6 sockets on a fixed port, tolerating a
// missing address family the same way Open does for the primary port.
func listenUDPPair(port int) (*net.UDPConn, *net.UDPConn, error) {
	v4, err4 := net.ListenUDP("udp4", &net.UDPAddr{Port: port})
	if err4 != nil && !errors.Is(err4, syscall.EAFNOSUPPORT) {
		return nil, nil, err4
	}
	v6, err6 := net.ListenUDP("udp6", &net.UDPAddr{Port: port})
	if err6 != nil && !errors.Is(err6, syscall.EAFNOSUPPORT) {
		if v4 != nil {
			_ = v4.Close()
		}
		return nil, nil, err6
	}
	if v4 == nil && v6 == nil {
		return nil, nil, syscall.EAFNOSUPPORT
	}
	return v4, v6, nil
}

// altPeerKey normalizes an IPv4-mapped IPv6 source so receive and send
// agree on the same key.
func altPeerKey(a netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
}

// trackAlt records which socket each source last used. With no alternate
// port configured it returns fn unchanged, so the default receive path has no
// extra work.
func (b *UDPBind) trackAlt(fn conn.ReceiveFunc, enabled, isAlt bool) conn.ReceiveFunc {
	if !enabled {
		return fn
	}
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, err := fn(bufs, sizes, eps)
		for i := 0; i < n; i++ {
			e, ok := eps[i].(udpEndpoint)
			if !ok {
				continue
			}
			key := altPeerKey(e.addr)
			if isAlt {
				b.noteAltPeer(key, time.Now())
			} else if _, seen := b.altPeers.Load(key); seen {
				b.forgetAltPeer(key)
			}
		}
		return n, err
	}
}

func (b *UDPBind) recordBufferStatus(socket string, pc *net.UDPConn) {
	status := UDPBufferStatus{Socket: socket, Requested: b.requested}
	if err := pc.SetReadBuffer(b.requested); err != nil {
		status.Err = fmt.Errorf("set read buffer: %w", err)
	} else if err := pc.SetWriteBuffer(b.requested); err != nil {
		status.Err = fmt.Errorf("set write buffer: %w", err)
	} else {
		status.Read, status.Write, status.Err = socketBufferBytes(pc)
	}
	b.status = append(b.status, status)
	if b.log == nil {
		return
	}
	if status.Err != nil {
		b.log.Warn("WireGuard UDP socket buffer tuning incomplete", "socket", socket, "requested_bytes", status.Requested, "error", status.Err)
		return
	}
	b.log.Info("WireGuard UDP socket buffers configured", "socket", socket, "requested_bytes", status.Requested, "read_buffer_bytes", status.Read, "write_buffer_bytes", status.Write)
}

type udpBatchReader interface {
	ReadBatch([]ipv6.Message, int) (int, error)
}

func makeUDPReceive(pc udpBatchReader, udp *net.UDPConn) conn.ReceiveFunc {
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		return makeUDPBatchReceive(pc)
	}
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if len(bufs) == 0 || len(bufs) > conn.IdealBatchSize || len(sizes) < len(bufs) || len(eps) < len(bufs) {
			return 0, fmt.Errorf("invalid WireGuard UDP receive batch")
		}
		n, _, _, addr, err := udp.ReadMsgUDPAddrPort(bufs[0], nil)
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		eps[0] = udpEndpoint{addr: addr}
		return 1, nil
	}
}

// Keep batch decoding independent of the platform so its endpoint contract can
// also be exercised on hosts that use ReadMsgUDP in production.
func makeUDPBatchReceive(pc udpBatchReader) conn.ReceiveFunc {
	const (
		minWindow   = 8
		shrinkAfter = 32
	)
	msgs := make([]ipv6.Message, conn.IdealBatchSize)
	for i := range msgs {
		msgs[i].Buffers = make(net.Buffers, 1)
	}
	// A ReceiveFunc has one serial reader. Prepare fewer descriptors when
	// reads are sparse, and use the full batch when the socket stays busy.
	window, sparse := minWindow, 0
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if len(bufs) == 0 || len(bufs) > len(msgs) || len(sizes) < len(bufs) || len(eps) < len(bufs) {
			return 0, fmt.Errorf("invalid WireGuard UDP receive batch")
		}
		limit := min(window, len(bufs))
		for i := range limit {
			msgs[i].Buffers[0] = bufs[i]
		}
		n, err := pc.ReadBatch(msgs[:limit], 0)
		if err != nil {
			return 0, err
		}
		for i := 0; i < n; i++ {
			sizes[i] = msgs[i].N
			eps[i] = udpEndpoint{addr: msgs[i].Addr.(*net.UDPAddr).AddrPort()}
		}
		// A smaller caller-provided array cannot tell us whether the window
		// would have filled. Keep the learned size for the next full read.
		if limit == window {
			switch {
			case n == window:
				window = min(window*2, len(msgs))
				sparse = 0
			case window > minWindow && n <= window/4:
				sparse++
				if sparse == shrinkAfter {
					for i := window / 2; i < window; i++ {
						msgs[i].Buffers[0] = nil
						msgs[i].Addr = nil
					}
					window /= 2
					sparse = 0
				}
			default:
				sparse = 0
			}
		}
		return n, nil
	}
}

func (b *UDPBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.receiveStop != nil {
		close(b.receiveStop)
		b.receiveStop = nil
	}
	errs := []error{b.closeLocked()}
	if b.ipv4 != nil {
		errs = append(errs, b.ipv4.Close())
		b.ipv4 = nil
	}
	if b.ipv6 != nil {
		errs = append(errs, b.ipv6.Close())
		b.ipv6 = nil
	}
	return errors.Join(errs...)
}

// closeLocked closes the alternate sockets and forgets their peers.
func (b *UDPBind) closeLocked() error {
	var errs []error
	if b.alt4 != nil {
		errs = append(errs, b.alt4.Close())
		b.alt4 = nil
	}
	if b.alt6 != nil {
		errs = append(errs, b.alt6.Close())
		b.alt6 = nil
	}
	b.altPeers.Clear()
	b.altPeerCount.Store(0)
	return errors.Join(errs...)
}

func (*UDPBind) SetMark(uint32) error { return nil }

func (*UDPBind) BatchSize() int {
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		return conn.IdealBatchSize
	}
	return 1
}

func (b *UDPBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if len(bufs) == 0 || len(bufs) > b.BatchSize() {
		return fmt.Errorf("invalid WireGuard UDP send batch")
	}
	var dst netip.AddrPort
	if endpoint, ok := ep.(udpEndpoint); ok {
		dst = endpoint.addr
	} else {
		dst = netip.AddrPortFrom(ep.DstIP(), portFromEndpoint(ep))
	}
	isIPv6 := dst.Addr().Is6()
	b.mu.Lock()
	if b.receiveStop == nil {
		b.mu.Unlock()
		return net.ErrClosed
	}
	udp := b.ipv4
	if isIPv6 {
		udp = b.ipv6
	}
	if b.altPort != 0 && b.isAltPeer(altPeerKey(dst), time.Now()) {
		if isIPv6 && b.alt6 != nil {
			udp = b.alt6
		} else if !isIPv6 && b.alt4 != nil {
			udp = b.alt4
		}
	}
	b.mu.Unlock()
	if udp == nil {
		return syscall.EAFNOSUPPORT
	}
	// A single datagram already needs just one write. Avoid packing batch
	// descriptors even for a full MTU payload.
	if len(bufs) == 1 {
		_, err := udp.WriteToUDPAddrPort(bufs[0], dst)
		return err
	}
	return sendUDPBatch(udp, bufs, dst)
}

func (b *UDPBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return udpEndpoint{addr: addr}, nil
}

type udpEndpoint struct{ addr netip.AddrPort }

func (udpEndpoint) ClearSrc()             {}
func (udpEndpoint) SrcToString() string   { return "" }
func (e udpEndpoint) DstToString() string { return e.addr.String() }
func (e udpEndpoint) DstToBytes() []byte  { b, _ := e.addr.MarshalBinary(); return b }
func (e udpEndpoint) DstIP() netip.Addr   { return e.addr.Addr() }
func (udpEndpoint) SrcIP() netip.Addr     { return netip.Addr{} }

// UDPSourceIP returns the remote IP of a raw UDP endpoint from UDPBind.
// WebSocket and logical multipath endpoints have independent admission.
func UDPSourceIP(endpoint conn.Endpoint) (netip.Addr, bool) {
	ep, ok := endpoint.(udpEndpoint)
	return ep.addr.Addr(), ok
}

func portFromEndpoint(ep conn.Endpoint) uint16 {
	addr, err := netip.ParseAddrPort(ep.DstToString())
	if err != nil {
		return 0
	}
	return addr.Port()
}
