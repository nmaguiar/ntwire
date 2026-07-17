package server

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/nmaguiar/nwire/pkg/wgnet"
)

type dataPlane struct {
	stack     *wgnet.Stack
	serverIP  netip.Addr
	mu        sync.Mutex
	next      uint32
	listeners []net.Listener
	stop      chan struct{}
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
	st, err := wgnet.New(wgnet.Config{Addresses: []netip.Addr{serverIP}, ListenPort: port})
	if err != nil {
		return err
	}
	d := &dataPlane{stack: st, serverIP: serverIP, next: 2, stop: make(chan struct{})}
	s.data = d
	for _, tunnel := range s.Config.Tunnels {
		if err := s.listenTunnel(d, tunnel); err != nil {
			s.Close()
			return err
		}
	}
	go s.reapLoop()
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
	d.listeners = append(d.listeners, l)
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
		return
	}
	defer out.Close()
	go io.Copy(out, in)
	io.Copy(in, out)
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
	if s.data != nil && v.WireGuardPublicKey != "" {
		_ = s.data.stack.RemovePeer(v.WireGuardPublicKey)
	}
}
func (s *Server) reapLoop() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			for _, v := range s.sessions.Reap() {
				s.dropSession(v)
				s.audit("session_expired", v, "", 0)
			}
		case <-s.data.stop:
			return
		}
	}
}
func (s *Server) Close() {
	if s.data == nil {
		return
	}
	close(s.data.stop)
	for _, l := range s.data.listeners {
		_ = l.Close()
	}
	_ = s.data.stack.Close()
	s.data = nil
}
