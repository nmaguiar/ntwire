package server

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

type dataPlane struct {
	stack     *wgnet.Stack
	serverIP  netip.Addr
	mu        sync.Mutex
	next      uint32
	listeners map[string]*tunnelListener // keyed by tunnel name
	stop      chan struct{}
	ws        *wstransport.Hybrid
}

// tunnelListener pairs a live listener with the tunnel config it was opened
// for, so a reload can detect a changed target/virtual_port and recycle it.
type tunnelListener struct {
	listener net.Listener
	config   TunnelConfig
}

// StartDataPlane starts an unprivileged WireGuard UDP endpoint and TCP
// virtual-port listeners inside its netstack. It must be called once at boot.
func (s *Server) StartDataPlane() error {
	prefix, err := netip.ParsePrefix(s.Config.Network.TunnelCIDR)
	if err != nil {
		return err
	}
	serverIP := prefix.Addr().Next()
	port, err := portOf(s.Config.Listen.WireGuard)
	if err != nil {
		return err
	}
	ws := wstransport.NewHybrid()
	st, err := wgnet.New(wgnet.Config{Addresses: []netip.Addr{serverIP}, ListenPort: port, Bind: ws})
	if err != nil {
		return err
	}
	d := &dataPlane{stack: st, serverIP: serverIP, next: 2, stop: make(chan struct{}), ws: ws, listeners: map[string]*tunnelListener{}}
	s.data = d
	for _, tunnel := range s.Config.Tunnels {
		if err := s.listenTunnel(d, tunnel); err != nil {
			s.Close()
			return err
		}
	}
	go s.reapLoop(d)
	return nil
}
func portOf(address string) (int, error) {
	_, p, e := net.SplitHostPort(address)
	if e != nil {
		return 0, e
	}
	var n int
	_, e = fmt.Sscanf(p, "%d", &n)
	return n, e
}
func (s *Server) listenTunnel(d *dataPlane, tunnel TunnelConfig) error {
	l, err := d.stack.Listen("tcp", net.JoinHostPort(d.serverIP.String(), fmt.Sprint(tunnel.VirtualPort)))
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.listeners[tunnel.Name] = &tunnelListener{listener: l, config: tunnel}
	d.mu.Unlock()
	s.log.Debug("tunnel listener opened", "tunnel", tunnel.Name, "virtual_port", tunnel.VirtualPort, "target", tunnel.Target)
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go s.proxy(tunnel, c)
		}
	}()
	return nil
}

// reloadTunnels reconciles the live listener set against the newly loaded
// tunnel configuration: listeners for removed tunnels, or tunnels whose
// target or virtual_port changed, are closed; listeners for added or
// changed tunnels are opened. Unchanged tunnels keep their listener and any
// in-flight connections untouched. A connection already accepted on a
// changed tunnel keeps proxying to its original target until it closes;
// only new connections observe the new target.
func (s *Server) reloadTunnels(newTunnels []TunnelConfig) {
	if s.data == nil {
		return
	}
	d := s.data
	wanted := make(map[string]TunnelConfig, len(newTunnels))
	for _, t := range newTunnels {
		wanted[t.Name] = t
	}
	d.mu.Lock()
	var toClose []*tunnelListener
	var toOpen []TunnelConfig
	for name, tl := range d.listeners {
		nt, ok := wanted[name]
		if !ok || nt.VirtualPort != tl.config.VirtualPort || nt.Target != tl.config.Target {
			toClose = append(toClose, tl)
			delete(d.listeners, name)
		}
	}
	for name, nt := range wanted {
		if _, exists := d.listeners[name]; !exists {
			toOpen = append(toOpen, nt)
		}
	}
	d.mu.Unlock()
	for _, tl := range toClose {
		s.log.Debug("tunnel listener closed", "tunnel", tl.config.Name)
		_ = tl.listener.Close()
	}
	for _, nt := range toOpen {
		if err := s.listenTunnel(d, nt); err != nil {
			s.log.Warn("failed to open tunnel listener on reload", "tunnel", nt.Name, "error", err)
		}
	}
}
func (s *Server) proxy(t TunnelConfig, in net.Conn) {
	defer in.Close()
	host, _, err := net.SplitHostPort(in.RemoteAddr().String())
	if err != nil {
		return
	}
	if !s.allowedIP(host, t.Name) {
		return
	}
	out, err := net.DialTimeout("tcp", t.Target, 10*time.Second)
	if err != nil {
		s.log.Debug("tunnel target dial failed", "tunnel", t.Name, "target", t.Target, "error", err)
		return
	}
	defer out.Close()
	started := time.Now()
	s.log.Debug("tunnel connection opened", "tunnel", t.Name, "client", host)
	stats := s.statsFor(host, t.Name)
	stats.connections.Add(1)
	stats.active.Add(1)
	defer stats.active.Add(-1)
	toStart, fromStart := stats.toTarget.Load(), stats.fromTarget.Load()
	go io.Copy(countingWriter{w: out, counter: &stats.toTarget}, in)
	io.Copy(countingWriter{w: in, counter: &stats.fromTarget}, out)
	s.log.Debug("tunnel connection closed", "tunnel", t.Name, "client", host,
		"bytes_to_target", stats.toTarget.Load()-toStart, "bytes_from_target", stats.fromTarget.Load()-fromStart, "duration", time.Since(started))
}

type countingWriter struct {
	w       io.Writer
	counter *atomic.Uint64
}

func (w countingWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if n > 0 {
		w.counter.Add(uint64(n))
	}
	return n, err
}
func (s *Server) allowedIP(ip, name string) bool {
	for _, v := range s.sessions.All() {
		if v.TunnelIP == ip {
			for _, t := range v.Tunnels {
				if t.Name == name {
					return true
				}
			}
		}
	}
	return false
}
func (s *Server) allocateIP() (string, error) {
	s.data.mu.Lock()
	defer s.data.mu.Unlock()
	p, _ := netip.ParsePrefix(s.Config.Network.TunnelCIDR)
	bits := p.Addr().As4()
	for tries := uint32(0); tries < 65534; tries++ {
		n := s.data.next
		s.data.next++
		bits[2] = byte(n >> 8)
		bits[3] = byte(n)
		ip := netip.AddrFrom4(bits)
		used := false
		for _, x := range s.sessions.All() {
			if x.TunnelIP == ip.String() {
				used = true
				break
			}
		}
		if !used && p.Contains(ip) {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("tunnel IP pool exhausted")
}
func (s *Server) addPeer(key, ip string) error {
	if s.data == nil {
		return nil
	}
	return s.data.stack.AddPeer(wgnet.Endpoint{PublicKey: key, Address: ip + "/32"})
}
func (s *Server) dropSession(v Session) {
	for _, tunnel := range v.Tunnels {
		s.tunnelStats.Delete(statsKey(v.TunnelIP, tunnel.Name))
	}
	if s.data != nil && v.WireGuardPublicKey != "" {
		_ = s.data.stack.RemovePeer(v.WireGuardPublicKey)
	}
	if s.data != nil && s.data.ws != nil && v.WireGuardPublicKey != "" {
		s.data.ws.WebSocket.CloseSession(v.WireGuardPublicKey)
	}
}

// reapLoop takes d explicitly (rather than reading s.data on each iteration)
// so it never races with Close() nilling s.data out from under it.
func (s *Server) reapLoop(d *dataPlane) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			for _, v := range s.sessions.Reap() {
				s.dropSession(v)
				s.log.Debug("session expired", "session", v.ID, "identity", v.Identity)
				s.audit("session_expired", v, "", 0)
			}
		case <-d.stop:
			return
		}
	}
}
func (s *Server) Close() {
	if s.data == nil {
		return
	}
	close(s.data.stop)
	s.data.mu.Lock()
	for _, tl := range s.data.listeners {
		_ = tl.listener.Close()
	}
	s.data.mu.Unlock()
	_ = s.data.stack.Close()
	s.data = nil
}
