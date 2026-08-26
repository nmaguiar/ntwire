package wstransport

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"syscall"

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
	mu        sync.Mutex
	ipv4      *net.UDPConn
	ipv6      *net.UDPConn
	requested int
	log       *slog.Logger
	status    []UDPBufferStatus
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

	b.status = b.status[:0]
	if v4 != nil {
		b.recordBufferStatus("ipv4", v4)
		b.ipv4 = v4
	}
	if v6 != nil {
		b.recordBufferStatus("ipv6", v6)
		b.ipv6 = v6
	}
	fns := make([]conn.ReceiveFunc, 0, 2)
	if v4 != nil {
		fns = append(fns, makeUDPReceive(ipv4.NewPacketConn(v4), v4))
	}
	if v6 != nil {
		fns = append(fns, makeUDPReceive(ipv6.NewPacketConn(v6), v6))
	}
	return fns, uint16(port), nil
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

func makeUDPReceive(pc interface {
	ReadBatch([]ipv6.Message, int) (int, error)
}, udp *net.UDPConn) conn.ReceiveFunc {
	msgs := make([]ipv6.Message, conn.IdealBatchSize)
	for i := range msgs {
		msgs[i].Buffers = make(net.Buffers, 1)
	}
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if len(bufs) == 0 || len(bufs) > conn.IdealBatchSize || len(sizes) < len(bufs) || len(eps) < len(bufs) {
			return 0, fmt.Errorf("invalid WireGuard UDP receive batch")
		}
		if runtime.GOOS != "linux" && runtime.GOOS != "android" {
			n, _, _, addr, err := udp.ReadMsgUDP(bufs[0], nil)
			if err != nil {
				return 0, err
			}
			sizes[0] = n
			eps[0] = udpEndpoint{addr: addr.AddrPort()}
			return 1, nil
		}
		for i := range bufs {
			msgs[i].Buffers[0] = bufs[i]
		}
		n, err := pc.ReadBatch(msgs[:len(bufs)], 0)
		if err != nil {
			return 0, err
		}
		for i := 0; i < n; i++ {
			sizes[i] = msgs[i].N
			if msgs[i].N > 0 {
				eps[i] = udpEndpoint{addr: msgs[i].Addr.(*net.UDPAddr).AddrPort()}
			}
		}
		return n, nil
	}
}

func (b *UDPBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	var errs []error
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
	b.mu.Lock()
	udp := b.ipv4
	if ep.DstIP().Is6() {
		udp = b.ipv6
	}
	b.mu.Unlock()
	if udp == nil {
		return syscall.EAFNOSUPPORT
	}
	addr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ep.DstIP(), portFromEndpoint(ep)))
	if runtime.GOOS != "linux" && runtime.GOOS != "android" {
		for _, buf := range bufs {
			if _, _, err := udp.WriteMsgUDP(buf, nil, addr); err != nil {
				return err
			}
		}
		return nil
	}
	msgs := make([]ipv6.Message, len(bufs))
	for i, buf := range bufs {
		msgs[i].Buffers = net.Buffers{buf}
		msgs[i].Addr = addr
	}
	pc := ipv6.NewPacketConn(udp)
	for start := 0; start < len(msgs); {
		n, err := pc.WriteBatch(msgs[start:], 0)
		if err != nil {
			return err
		}
		start += n
	}
	return nil
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

func portFromEndpoint(ep conn.Endpoint) uint16 {
	addr, err := netip.ParseAddrPort(ep.DstToString())
	if err != nil {
		return 0
	}
	return addr.Port()
}
