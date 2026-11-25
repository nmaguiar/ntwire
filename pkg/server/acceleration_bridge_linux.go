//go:build linux

package server

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

// Reserve most of the mapping pool for endpoints that have received a
// non-cookie packet from the kernel after WireGuard authenticated traffic.
const (
	bridgeMaxMappings = 4096
	bridgeMaxPending  = 512
	bridgePendingTTL  = 20 * time.Second
	bridgeIdleTTL     = 10 * time.Minute
)

type bridgeEndpoint struct {
	socket        *net.UDPConn
	packetConn    *ipv4.PacketConn
	endpoint      conn.Endpoint
	created       time.Time
	lastTraffic   time.Time
	authenticated bool
}

type kernelBridge struct {
	ns         *kernelNamespace
	port       int
	log        *slog.Logger
	bind       conn.Bind
	publicPort uint16
	boundPort  uint16

	lifeMu   sync.Mutex
	stop     chan struct{}
	stopped  bool
	closeErr error
	workers  sync.WaitGroup

	mu           sync.Mutex
	mappings     map[string]*bridgeEndpoint
	byAddress    map[netip.AddrPort]string
	pending      int
	sequence     uint32
	closed       bool
	dropped      atomic.Uint64
	socketErrors atomic.Uint64
	batchPackets atomic.Uint64
	batchRetries atomic.Uint64
	tuningErrors atomic.Uint64
	receiveError atomic.Bool
}

func newKernelBridge(ns *kernelNamespace, log *slog.Logger) *kernelBridge {
	return &kernelBridge{
		ns: ns, log: log, stop: make(chan struct{}),
		mappings: make(map[string]*bridgeEndpoint), byAddress: make(map[netip.AddrPort]string),
	}
}

func (b *kernelBridge) start() error {
	b.lifeMu.Lock()
	defer b.lifeMu.Unlock()
	if b.stopped {
		return net.ErrClosed
	}
	carriers, port, err := b.bind.Open(b.publicPort)
	if err != nil {
		return fmt.Errorf("open public WireGuard transport: %w", err)
	}
	b.boundPort = port
	for _, receive := range carriers {
		b.workers.Go(func() { b.receive(receive) })
	}
	b.workers.Go(b.reap)
	return nil
}

func (b *kernelBridge) receive(receive conn.ReceiveFunc) {
	bufs := make([][]byte, b.bind.BatchSize())
	for i := range bufs {
		bufs[i] = make([]byte, device.MaxMessageSize)
	}
	sizes := make([]int, len(bufs))
	endpoints := make([]conn.Endpoint, len(bufs))
	messages := make([]ipv4.Message, len(bufs))
	for i := range messages {
		messages[i].Buffers = make([][]byte, 1)
	}
	for {
		n, err := receive(bufs, sizes, endpoints)
		if err != nil {
			select {
			case <-b.stop:
				return
			default:
				b.socketErrors.Add(1)
				b.receiveError.Store(true)
				b.log.Error("accelerated WireGuard transport receive stopped", "error", err)
				return
			}
		}
		b.forwardBatch(bufs[:n], sizes, endpoints, messages)
	}
}

func isBridgeDatagram(packet []byte) bool {
	if len(packet) < 4 {
		return false
	}
	switch binary.LittleEndian.Uint32(packet) {
	case device.MessageInitiationType:
		return len(packet) == device.MessageInitiationSize
	case device.MessageResponseType:
		return len(packet) == device.MessageResponseSize
	case device.MessageCookieReplyType:
		return len(packet) == device.MessageCookieReplySize
	case device.MessageTransportType:
		return len(packet) >= device.MessageTransportSize
	default:
		return false
	}
}

// Keep datagrams in receive order and batch adjacent packets sent to the
// same connected private socket. Receive buffers remain owned by this loop.
func (b *kernelBridge) forwardBatch(bufs [][]byte, sizes []int, endpoints []conn.Endpoint, messages []ipv4.Message) {
	var endpoint conn.Endpoint
	var key string
	count := 0
	for i, buf := range bufs {
		if endpoints[i] == nil || !isBridgeDatagram(buf[:sizes[i]]) {
			continue
		}
		next := endpoints[i].DstToString()
		if count != 0 && next != key {
			b.forward(key, endpoint, messages[:count])
			count = 0
		}
		key, endpoint = next, endpoints[i]
		messages[count].Buffers[0] = buf[:sizes[i]]
		count++
	}
	if count != 0 {
		b.forward(key, endpoint, messages[:count])
	}
}

func (b *kernelBridge) forward(key string, endpoint conn.Endpoint, messages []ipv4.Message) {
	mapping := b.mapping(key, endpoint, false)
	if mapping == nil {
		b.dropped.Add(uint64(len(messages)))
		return
	}
	if len(messages) > 1 {
		// WriteBatch may return a successfully sent prefix. Retry only the
		// remainder through the scalar path if batching is unavailable.
		n, _ := mapping.packetConn.WriteBatch(messages, 0)
		if n > 0 {
			b.batchPackets.Add(uint64(n))
			messages = messages[n:]
		}
		b.batchRetries.Add(uint64(len(messages)))
	}
	for _, message := range messages {
		if _, err := mapping.socket.Write(message.Buffers[0]); err != nil && !errors.Is(err, net.ErrClosed) {
			b.socketErrors.Add(1)
		}
	}
}

func (b *kernelBridge) mapping(key string, endpoint conn.Endpoint, authorized bool) *bridgeEndpoint {
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	if prev := b.mappings[key]; prev != nil {
		prev.lastTraffic = now
		prev.endpoint = endpoint
		if authorized && !prev.authenticated {
			prev.authenticated = true
			b.pending--
		}
		return prev
	}
	if (!authorized && b.pending >= bridgeMaxPending) || len(b.mappings) >= bridgeMaxMappings || b.sequence >= 0xfffffe {
		return nil
	}

	// A retired socket's address is never assigned to a new mapping. The
	// kernel may still have an authenticated peer pointing to the old tuple.
	b.sequence++
	var socket *net.UDPConn
	if err := b.ns.call(func() error {
		var err error
		// 127.0.0.1 is reserved for the kernel listener destination.
		socket, err = privateUDP(bridgeSource(b.sequence+1), b.port)
		return err
	}); err != nil {
		b.socketErrors.Add(1)
		return nil
	}
	if socket.SetReadBuffer(wstransport.DefaultUDPBufferBytes) != nil {
		b.tuningErrors.Add(1)
	}
	mapping := &bridgeEndpoint{socket: socket, packetConn: ipv4.NewPacketConn(socket), endpoint: endpoint, created: now, lastTraffic: now, authenticated: authorized}
	if !authorized {
		b.pending++
	}
	b.mappings[key] = mapping
	address := socket.LocalAddr().(*net.UDPAddr).AddrPort()
	b.byAddress[netip.AddrPortFrom(address.Addr().Unmap(), address.Port())] = key
	b.workers.Go(func() { b.returnPackets(key, mapping) })
	return mapping
}

func (b *kernelBridge) returnPackets(key string, mapping *bridgeEndpoint) {
	// The kernel device has a 1420-byte tunnel MTU. A 2 KiB receive slot
	// accommodates its encrypted output and all handshake/control messages.
	const slots = 8
	var storage [slots][2048]byte
	var bufs [slots][]byte
	var vectors [slots][1][]byte
	var messages [slots]ipv4.Message
	for i := range messages {
		vectors[i][0] = storage[i][:]
		messages[i].Buffers = vectors[i][:]
	}
	for {
		n, err := mapping.packetConn.ReadBatch(messages[:], 0)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				b.socketErrors.Add(1)
				b.mu.Lock()
				if b.mappings[key] == mapping {
					b.remove(key, mapping)
				}
				b.mu.Unlock()
			}
			return
		}
		b.mu.Lock()
		if b.mappings[key] != mapping {
			b.mu.Unlock()
			return
		}
		endpoint := mapping.endpoint
		for i, message := range messages[:n] {
			if message.Flags&unix.MSG_TRUNC != 0 || message.N < 4 {
				b.dropped.Add(1)
				bufs[i] = nil
				continue
			}
			bufs[i] = storage[i][:message.N]
			if binary.LittleEndian.Uint32(bufs[i]) != device.MessageCookieReplyType {
				if !mapping.authenticated {
					mapping.authenticated = true
					b.pending--
				}
				mapping.lastTraffic = time.Now()
			}
		}
		b.mu.Unlock()
		for first := 0; first < n; {
			if bufs[first] == nil {
				first++
				continue
			}
			kind := binary.LittleEndian.Uint32(bufs[first])
			last := first + 1
			// Multipath duplicates transport packets only. Never present a
			// mixed batch with a handshake or cookie at its head.
			for last < n && bufs[last] != nil && binary.LittleEndian.Uint32(bufs[last]) == kind {
				last++
			}
			if err := b.bind.Send(bufs[first:last], endpoint); err != nil {
				b.socketErrors.Add(1)
			}
			first = last
		}
	}
}

func (b *kernelBridge) externalEndpoint(address netip.AddrPort) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.byAddress[netip.AddrPortFrom(address.Addr().Unmap(), address.Port())]
}

func (b *kernelBridge) remove(key string, mapping *bridgeEndpoint) {
	delete(b.mappings, key)
	address := mapping.socket.LocalAddr().(*net.UDPAddr).AddrPort()
	delete(b.byAddress, netip.AddrPortFrom(address.Addr().Unmap(), address.Port()))
	if !mapping.authenticated {
		b.pending--
	}
	_ = mapping.socket.Close()
}

func (b *kernelBridge) reap() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-b.stop:
			return
		case now := <-ticker.C:
			b.mu.Lock()
			for key, mapping := range b.mappings {
				if (!mapping.authenticated && now.Sub(mapping.created) >= bridgePendingTTL) ||
					(mapping.authenticated && now.Sub(mapping.lastTraffic) >= bridgeIdleTTL) {
					b.remove(key, mapping)
				}
			}
			b.mu.Unlock()
		}
	}
}

func (b *kernelBridge) writeMetrics(w io.Writer) {
	b.mu.Lock()
	total, pending := len(b.mappings), b.pending
	b.mu.Unlock()
	fmt.Fprintf(w, "ntwire_acceleration_bridge_mappings{state=\"established\"} %d\n", total-pending)
	fmt.Fprintf(w, "ntwire_acceleration_bridge_mappings{state=\"pending\"} %d\n", pending)
	fmt.Fprintf(w, "ntwire_acceleration_bridge_dropped_datagrams_total %d\n", b.dropped.Load())
	fmt.Fprintf(w, "ntwire_acceleration_bridge_socket_errors_total %d\n", b.socketErrors.Load())
	fmt.Fprintf(w, "ntwire_acceleration_bridge_batch_datagrams_total %d\n", b.batchPackets.Load())
	fmt.Fprintf(w, "ntwire_acceleration_bridge_batch_retries_total %d\n", b.batchRetries.Load())
	fmt.Fprintf(w, "ntwire_acceleration_bridge_socket_tuning_errors_total %d\n", b.tuningErrors.Load())
}

func (b *kernelBridge) close() error {
	b.lifeMu.Lock()
	defer b.lifeMu.Unlock()
	if b.stopped {
		return b.closeErr
	}
	b.stopped = true
	close(b.stop)
	b.mu.Lock()
	b.closed = true
	for key, mapping := range b.mappings {
		b.remove(key, mapping)
	}
	b.mu.Unlock()
	if b.bind != nil {
		b.closeErr = b.bind.Close()
	}
	b.workers.Wait()
	return b.closeErr
}
