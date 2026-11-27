//go:build linux

package server

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const kernelInterface = "ntwire0"

type namespaceCall struct {
	run  func() error
	done chan error
}

// The worker owns an anonymous namespace on a dedicated OS thread. Sockets
// opened there keep that namespace when used by ordinary Go goroutines.
type kernelNamespace struct {
	mu    sync.RWMutex
	calls chan namespaceCall
	done  chan struct{}
}

func newKernelNamespace() (*kernelNamespace, error) {
	ns := &kernelNamespace{calls: make(chan namespaceCall), done: make(chan struct{})}
	ready := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer close(ns.done)
		err := unix.Unshare(unix.CLONE_NEWNET)
		if err != nil {
			runtime.UnlockOSThread()
		}
		ready <- err
		if err != nil {
			return
		}
		for call := range ns.calls {
			call.done <- call.run()
		}
		// A locked thread exits with this goroutine. Never return it to the
		// scheduler with the server's network namespace still changed.
	}()
	if err := <-ready; err != nil {
		return nil, fmt.Errorf("create private network namespace: %w", err)
	}
	return ns, nil
}

func (n *kernelNamespace) call(run func() error) error {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.calls == nil {
		return net.ErrClosed
	}
	result := make(chan error, 1)
	n.calls <- namespaceCall{run: run, done: result}
	return <-result
}

func (n *kernelNamespace) close() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.calls != nil {
		close(n.calls)
		<-n.done
		n.calls = nil
	}
}

type kernelStack struct {
	ns        *kernelNamespace
	control   *wgctrl.Client
	routes    *netlink.Handle
	device    netlink.Link
	firewall  *kernelFirewall
	bridge    *kernelBridge
	ebpf      *kernelCounters
	ebpfMode  string
	public    string
	service   netip.Addr
	log       *slog.Logger
	failed    bool // only accessed on the namespace worker
	socketsMu sync.Mutex
	sockets   map[io.Closer]struct{}
	closeOnce sync.Once
	closeErr  error
}

func (s *Server) newKernelStack(c wgnet.Config, config AccelerationConfig) (serverStack, error) {
	var caps unix.CapUserData
	data := [2]unix.CapUserData{}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	if err := unix.Capget(&header, &data[0]); err == nil {
		caps = data[0]
		// The operations below are authoritative even when a capability is
		// visible in a container's effective set.
		s.log.Debug("Linux effective network capabilities", "net_admin", caps.Effective&(1<<unix.CAP_NET_ADMIN) != 0,
			"sys_admin", caps.Effective&(1<<unix.CAP_SYS_ADMIN) != 0)
	}
	prefix, err := netip.ParsePrefix(s.Config.Network.TunnelCIDR)
	if err != nil {
		return nil, err
	}
	if prefix.Overlaps(netip.MustParsePrefix("127.0.0.0/8")) || prefix.Overlaps(netip.MustParsePrefix("fe80::/10")) || prefix.Contains(netip.IPv6Loopback()) {
		return nil, fmt.Errorf("tunnel CIDR %s overlaps a loopback or IPv6 link-local network reserved by the kernel backend", prefix)
	}
	if c.PrivateKey == "" {
		key, err := wgnet.GenerateKey()
		if err != nil {
			return nil, err
		}
		c.PrivateKey = key.Private
	}
	key, err := wgtypes.ParseKey(c.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse WireGuard private key: %w", err)
	}
	ns, err := newKernelNamespace()
	if err != nil {
		return nil, err
	}
	k := &kernelStack{ns: ns, public: key.PublicKey().String(), service: c.Addresses[0], log: s.log, ebpfMode: "disabled", sockets: make(map[io.Closer]struct{})}
	if err := ns.call(func() error { return k.setup(key, prefix, config.EBPF) }); err != nil {
		return nil, dataPlaneStartupError(err, k.Close())
	}
	k.bridge.bind = c.Bind
	k.bridge.publicPort = uint16(c.ListenPort)
	return k, nil
}

func (k *kernelStack) setup(key wgtypes.Key, prefix netip.Prefix, observe bool) error {
	var err error
	k.routes, err = netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("open route netlink: %w", err)
	}
	loopback, err := k.routes.LinkByName("lo")
	if err == nil {
		err = k.routes.LinkSetUp(loopback)
	}
	if err != nil {
		return fmt.Errorf("enable private loopback: %w", err)
	}
	if err := k.routes.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: kernelInterface, MTU: wgnet.DefaultMTU}}); err != nil {
		return fmt.Errorf("create private WireGuard interface: %w", err)
	}
	k.device, err = k.routes.LinkByName(kernelInterface)
	if err != nil {
		return fmt.Errorf("find private WireGuard interface: %w", err)
	}
	address := net.IPNet{IP: k.service.AsSlice(), Mask: net.CIDRMask(prefix.Bits(), k.service.BitLen())}
	if err := k.routes.AddrAdd(k.device, &netlink.Addr{IPNet: &address, Flags: unix.IFA_F_NODAD}); err != nil {
		return fmt.Errorf("assign tunnel address: %w", err)
	}
	k.firewall, err = newKernelFirewall(k.service)
	if err != nil {
		return fmt.Errorf("install private nftables rules: %w", err)
	}
	k.control, err = wgctrl.New()
	if err != nil {
		return fmt.Errorf("open WireGuard netlink: %w", err)
	}
	device, err := k.control.Device(kernelInterface)
	if err != nil {
		return fmt.Errorf("verify private kernel WireGuard device: %w", err)
	}
	if device.Type != wgtypes.LinuxKernel {
		return errors.New("private WireGuard device is not a Linux kernel device")
	}
	if err := k.control.ConfigureDevice(kernelInterface, wgtypes.Config{PrivateKey: &key}); err != nil {
		return fmt.Errorf("configure private WireGuard device: %w", err)
	}
	k.bridge = newKernelBridge(k.ns, k.log)
	if observe {
		k.ebpf, err = newKernelCounters(k.device.Attrs().Index)
		if err != nil {
			k.ebpfMode = "unavailable"
			k.log.Warn("eBPF acceleration counters unavailable", "error", err)
		} else {
			k.ebpfMode = "attached"
		}
	}
	return nil
}

func (k *kernelStack) activate() error {
	if err := k.ns.call(func() error {
		if k.failed {
			return errors.New("kernel data plane isolation failed during startup")
		}
		// The kernel chooses its private UDP port after the configured tunnel
		// listeners have bound theirs, avoiding a random virtual-port conflict.
		if err := k.routes.LinkSetUp(k.device); err != nil {
			return fmt.Errorf("bring up private WireGuard device: %w", err)
		}
		device, err := k.control.Device(kernelInterface)
		if err != nil {
			return fmt.Errorf("read private WireGuard listen port: %w", err)
		}
		if device.ListenPort == 0 {
			return errors.New("private WireGuard device has no listen port")
		}
		k.bridge.port = device.ListenPort
		return nil
	}); err != nil {
		return err
	}
	return k.bridge.start()
}

func (k *kernelStack) PublicKey() string { return k.public }

func (k *kernelStack) configurePeer(peer wgtypes.PeerConfig) error {
	return k.ns.call(func() error {
		if k.failed {
			return net.ErrClosed
		}
		err := k.control.ConfigureDevice(kernelInterface, wgtypes.Config{Peers: []wgtypes.PeerConfig{peer}})
		if err != nil {
			k.failClosed("could not reconcile WireGuard peer", err)
		}
		return err
	})
}

func (k *kernelStack) AddPeer(peer wgnet.Endpoint) error {
	key, err := wgtypes.ParseKey(peer.PublicKey)
	if err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(peer.Address)
	if err != nil {
		return err
	}
	allowed := net.IPNet{IP: prefix.Addr().AsSlice(), Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())}
	return k.configurePeer(wgtypes.PeerConfig{PublicKey: key, ReplaceAllowedIPs: true, AllowedIPs: []net.IPNet{allowed}})
}

func (k *kernelStack) RemovePeer(publicKey string) error {
	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return err
	}
	return k.configurePeer(wgtypes.PeerConfig{PublicKey: key, Remove: true})
}

func (k *kernelStack) UpdateEndpoint(publicKey, address string) error {
	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return err
	}
	endpoint, err := k.bridge.bind.ParseEndpoint(address)
	if err != nil {
		return err
	}
	mapping := k.bridge.mapping(endpoint.DstToString(), endpoint, true)
	if mapping == nil {
		return errors.New("no capacity for private WireGuard endpoint")
	}
	return k.configurePeer(wgtypes.PeerConfig{PublicKey: key, UpdateOnly: true, Endpoint: mapping.socket.LocalAddr().(*net.UDPAddr)})
}

func (k *kernelStack) peers() ([]wgtypes.Peer, error) {
	var peers []wgtypes.Peer
	err := k.ns.call(func() error {
		if k.failed {
			return net.ErrClosed
		}
		device, err := k.control.Device(kernelInterface)
		if err == nil {
			peers = device.Peers
		}
		return err
	})
	return peers, err
}

func (k *kernelStack) LastHandshakes() (map[string]time.Time, error) {
	peers, err := k.peers()
	if err != nil {
		return nil, err
	}
	out := make(map[string]time.Time, len(peers))
	for _, p := range peers {
		out[p.PublicKey.String()] = p.LastHandshakeTime
	}
	return out, nil
}

func (k *kernelStack) LastHandshake(key string) (time.Time, bool, error) {
	key, err := wgnet.CanonicalPublicKey(key)
	if err != nil {
		return time.Time{}, false, err
	}
	handshakes, err := k.LastHandshakes()
	t, ok := handshakes[key]
	return t, ok, err
}

func (k *kernelStack) PeerEndpoint(key string) (string, bool, error) {
	peers, err := k.peers()
	for _, p := range peers {
		if p.PublicKey.String() == key {
			var address string
			if p.Endpoint != nil {
				address = k.bridge.externalEndpoint(p.Endpoint.AddrPort())
			}
			return address, true, nil
		}
	}
	return "", false, err
}

func (k *kernelStack) listenAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if host != k.service.String() {
		return fmt.Errorf("address %s is outside the private tunnel listener", address)
	}
	return nil
}

func (k *kernelStack) Listen(network, address string) (net.Listener, error) {
	resolved, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}
	if err := k.listenAddress(resolved.String()); err != nil {
		return nil, err
	}
	var listener net.Listener
	err = k.ns.call(func() error {
		if k.failed {
			return net.ErrClosed
		}
		socket, err := net.ListenTCP(network, resolved)
		if err != nil {
			return err
		}
		port := uint16(socket.Addr().(*net.TCPAddr).Port)
		if err := k.updatePort(false, port, true); err != nil {
			_ = socket.Close()
			return err
		}
		if !k.trackSocket(socket) {
			_ = socket.Close()
			return net.ErrClosed
		}
		listener = &kernelListener{Listener: socket, close: k.closeListener(false, port, socket), stack: k}
		return nil
	})
	return listener, err
}

func (k *kernelStack) ListenUDP(network, address string) (net.PacketConn, error) {
	if err := k.listenAddress(address); err != nil {
		return nil, err
	}
	var listener net.PacketConn
	err := k.ns.call(func() error {
		if k.failed {
			return net.ErrClosed
		}
		socket, err := net.ListenPacket(network, address)
		if err != nil {
			return err
		}
		port := uint16(socket.LocalAddr().(*net.UDPAddr).Port)
		if err := k.updatePort(true, port, true); err != nil {
			_ = socket.Close()
			return err
		}
		if !k.trackSocket(socket) {
			_ = socket.Close()
			return net.ErrClosed
		}
		listener = &kernelPacketConn{PacketConn: socket, close: k.closeListener(true, port, socket)}
		return nil
	})
	return listener, err
}

type kernelListener struct {
	net.Listener
	close func() error
	stack *kernelStack
}

func (l *kernelListener) Close() error { return l.close() }

func (l *kernelListener) Accept() (net.Conn, error) {
	socket, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if !l.stack.trackSocket(socket) {
		_ = socket.Close()
		return nil, net.ErrClosed
	}
	return &kernelConn{TCPConn: socket.(*net.TCPConn), stack: l.stack}, nil
}

type kernelConn struct {
	*net.TCPConn
	stack *kernelStack
}

func (c *kernelConn) Close() error {
	err := c.TCPConn.Close()
	c.stack.forgetSocket(c.TCPConn)
	return err
}

func (k *kernelStack) trackSocket(socket io.Closer) bool {
	k.socketsMu.Lock()
	defer k.socketsMu.Unlock()
	if k.sockets == nil {
		return false
	}
	k.sockets[socket] = struct{}{}
	return true
}

func (k *kernelStack) forgetSocket(socket io.Closer) {
	k.socketsMu.Lock()
	delete(k.sockets, socket)
	k.socketsMu.Unlock()
}

type kernelPacketConn struct {
	net.PacketConn
	close func() error
}

func (l *kernelPacketConn) Close() error { return l.close() }

func (k *kernelStack) closeListener(udp bool, port uint16, socket io.Closer) func() error {
	return sync.OnceValue(func() error {
		defer k.forgetSocket(socket)
		var closed bool
		err := k.ns.call(func() error {
			defer func() { closed = true }()
			if k.failed {
				return socket.Close()
			}
			return errors.Join(k.updatePort(udp, port, false), socket.Close())
		})
		if !closed {
			return errors.Join(err, socket.Close())
		}
		return err
	})
}

func (k *kernelStack) updatePort(udp bool, port uint16, open bool) error {
	err := k.firewall.updatePort(udp, port, open)
	if err != nil {
		k.failClosed("could not update private nftables listener rules", err)
	}
	return err
}

// A failed peer mutation or firewall transaction must stop traffic even if
// the caller has already updated its application-level authorization state.
func (k *kernelStack) failClosed(reason string, err error) {
	k.failed = true
	k.log.Error("kernel data plane stopped", "reason", reason, "error", err)
	if err := k.routes.LinkSetDown(k.device); err != nil {
		k.log.Error("could not take private WireGuard link down", "error", err)
	}
	if k.bridge != nil {
		go k.bridge.close()
	}
}

func (k *kernelStack) writeMetrics(w io.Writer) {
	var drops, rxBytes, txBytes uint64
	var failed, available bool
	var buckets [2][kernelCounterBuckets]uint64
	err := k.ns.call(func() error {
		if k.routes == nil {
			return net.ErrClosed
		}
		failed = k.failed
		drops, available = k.firewall.drops()
		if link, err := k.routes.LinkByIndex(k.device.Attrs().Index); err == nil && link.Attrs().Statistics != nil {
			rxBytes, txBytes = link.Attrs().Statistics.RxBytes, link.Attrs().Statistics.TxBytes
		}
		if k.ebpf != nil {
			buckets = k.ebpf.snapshot()
		}
		return nil
	})
	if err != nil {
		return
	}
	fmt.Fprintf(w, "ntwire_acceleration_healthy %d\n", boolInt(!failed && !k.bridge.receiveError.Load()))
	fmt.Fprintf(w, "ntwire_acceleration_ebpf_info{status=%q} 1\n", k.ebpfMode)
	fmt.Fprintf(w, "ntwire_acceleration_wireguard_bytes_total{direction=\"ingress\"} %d\n", rxBytes)
	fmt.Fprintf(w, "ntwire_acceleration_wireguard_bytes_total{direction=\"egress\"} %d\n", txBytes)
	if available {
		fmt.Fprintf(w, "ntwire_acceleration_nftables_dropped_packets_total %d\n", drops)
	}
	if k.ebpfMode == "attached" {
		for direction, label := range []string{"ingress", "egress"} {
			for bucket, count := range buckets[direction] {
				fmt.Fprintf(w, "ntwire_acceleration_ebpf_packets_total{direction=%q,size_bucket=%q} %d\n",
					label, kernelBucketNames[bucket], count)
			}
		}
	}
	k.bridge.writeMetrics(w)
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func (k *kernelStack) Close() error {
	k.closeOnce.Do(func() { k.closeErr = k.close() })
	return k.closeErr
}

func (k *kernelStack) close() error {
	var err error
	if k.bridge != nil {
		err = k.bridge.close()
	}
	k.socketsMu.Lock()
	sockets := k.sockets
	k.sockets = nil
	k.socketsMu.Unlock()
	for socket := range sockets {
		if closeErr := socket.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			err = errors.Join(err, closeErr)
		}
	}
	cleanup := k.ns.call(func() error {
		// Calls already queued on the namespace thread must see teardown
		// even before the worker stops accepting calls.
		k.failed = true
		if k.ebpf != nil {
			err = errors.Join(err, k.ebpf.close())
		}
		if k.control != nil {
			err = errors.Join(err, k.control.Close())
		}
		if k.firewall != nil {
			err = errors.Join(err, k.firewall.conn.CloseLasting())
		}
		if k.routes != nil {
			if k.device != nil {
				err = errors.Join(err, k.routes.LinkDel(k.device))
			}
			k.routes.Close()
			k.routes = nil
		}
		return nil
	})
	k.ns.close()
	return errors.Join(err, cleanup)
}

// A locked namespace worker only runs socket setup. DNS resolution, service
// handlers and ordinary outbound dials always run in the original namespace.
func privateUDP(ip net.IP, targetPort int) (*net.UDPConn, error) {
	return net.DialUDP("udp4", &net.UDPAddr{IP: ip}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: targetPort})
}

func bridgeSource(sequence uint32) net.IP {
	return net.IPv4(127, byte(sequence>>16), byte(sequence>>8), byte(sequence))
}
