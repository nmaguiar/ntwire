package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nmaguiar/ntwire/pkg/socks"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"golang.zx2c4.com/wireguard/conn"
)

type dataPlane struct {
	stack     *wgnet.Stack
	serverIP  netip.Addr
	mu        sync.Mutex
	next      uint32
	listeners map[string]*tunnelListener // keyed by tunnel name
	stop      chan struct{}
	ws        *wstransport.Hybrid
	multipath *wstransport.ServerMultipathBind
}

// tunnelListener pairs a live listener with the tunnel config it was opened
// for, so a reload can detect a changed target/virtual_port/socks config and
// recycle it.
type tunnelListener struct {
	listener net.Listener
	config   TunnelConfig
	socks    *socksRuntime // non-nil only for config.IsSocks() tunnels
}

// socksRuntime is the live embedded-SOCKS-proxy state for one tunnel: the
// handler itself plus the background ASN index refresh it owns, if any.
type socksRuntime struct {
	server  *socks.Server
	stopASN chan struct{}
}

// newSocksRuntime builds the SOCKS proxy handler for a target: socks tunnel,
// starting a background ASN index refresh when the tunnel's filters need
// one. cfg.Socks must be non-empty; config validation guarantees this.
func (s *Server) newSocksRuntime(t TunnelConfig) *socksRuntime {
	sc := t.Socks
	log := s.log.With("tunnel", t.Name)
	if sc.deniesAllByDefault() {
		log.Warn("socks tunnel has no destination filters and no allow_all; it will deny every connection")
	}
	asnIdx := socks.NewASNIndex()
	stopASN := make(chan struct{})
	if sc.WantsASNUpdates() {
		go asnIdx.Refresh(sc.ASNURL, 0, log, stopASN)
	}
	sv, err := socks.New(socks.Config{
		Filter: socks.FilterConfig{
			OnlyLocal:      sc.OnlyLocal,
			CIDRs:          sc.Filters,
			DomainSuffixes: sc.DomainFilters,
			ASNs:           sc.ASNFilters,
			Invert:         sc.ReverseFilters,
			AllowAll:       sc.AllowAll,
		},
		ASNLookup:  asnIdx,
		DNSTimeout: sc.DNSTimeout,
		AllowBind:  sc.AllowBind,
		Logger:     log,
	})
	if err != nil {
		// Filters are already validated at config load time; this should be
		// unreachable, but fail closed rather than proxy unfiltered.
		log.Warn("failed to build socks server", "error", err)
		close(stopASN)
		return nil
	}
	return &socksRuntime{server: sv, stopASN: stopASN}
}

// socksConfigChanged reports whether a and b differ in a way that requires
// rebuilding a tunnel's socksRuntime.
func socksConfigChanged(a, b *SocksConfig) bool {
	if a == nil || b == nil {
		return a != b
	}
	return !reflect.DeepEqual(*a, *b)
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
	relayMode := s.Config.Relay.Enabled
	ws.WebSocket.OnPeerConnected = func(_ string, _ conn.Endpoint) {
		s.log.Info("transport event", "event", "websocket_connected", "transport", "websocket", "relay", relayMode)
	}
	ws.WebSocket.OnPeerDisconnected = func(_ string, _ conn.Endpoint) {
		s.log.Info("transport event", "event", "websocket_disconnected", "transport", "websocket", "relay", relayMode)
	}
	var bind conn.Bind = ws
	var multipath *wstransport.ServerMultipathBind
	if s.Config.Relay.Enabled {
		mc := s.Config.Relay.Multipath
		multipath = wstransport.NewServerMultipathBind(ws, wstransport.V2Options{
			MirrorRateBytesPerSec: mc.MirrorRateBytesPerSec, MinDeliveryRatio: mc.MinDeliveryRatio,
			SwitchMargin: mc.SwitchMargin, MinDwell: mc.MinDwell, ReportInterval: mc.ReportInterval,
		})
		bind = multipath
		// id is the connecting peer's WireGuardPublicKey (see the /v1/wg
		// handler's ServeHTTP call). Gate on that session's own negotiated
		// Multipath flag, not just Relay.Enabled: a peer that didn't
		// negotiate multipath-v1 (an older client, or one that simply
		// doesn't offer the capability) has no MultipathBind of its own and
		// will never understand a FramePathProbe sent to it -- registering
		// it here anyway would only add a phantom candidate this bind
		// probes forever for no one to answer.
		ws.WebSocket.OnPeerConnected = func(id string, ep conn.Endpoint) {
			s.log.Info("transport event", "event", "websocket_connected", "transport", "websocket", "relay", true)
			if sess, ok := s.sessions.FindWireGuardPublicKey(id); ok && sess.Multipath {
				multipath.RegisterPath(id, "wss", wstransport.PathWSS, ep, sess.MultipathV2)
			}
		}
		ws.UDP.(*wstransport.FilterBind).SetProbeHandler(multipath.HandlePathControl)
	}
	st, err := wgnet.New(wgnet.Config{Addresses: []netip.Addr{serverIP}, ListenPort: port, Bind: bind})
	if err != nil {
		return err
	}
	d := &dataPlane{stack: st, serverIP: serverIP, next: 2, stop: make(chan struct{}), ws: ws, multipath: multipath, listeners: map[string]*tunnelListener{}}
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
	tl := &tunnelListener{listener: l, config: tunnel}
	if tunnel.IsSocks() {
		tl.socks = s.newSocksRuntime(tunnel)
	}
	d.mu.Lock()
	d.listeners[tunnel.Name] = tl
	d.mu.Unlock()
	s.log.Debug("tunnel listener opened", "tunnel", tunnel.Name, "virtual_port", tunnel.VirtualPort, "target", tunnel.Target)
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go s.proxy(tl, c)
		}
	}()
	return nil
}

// closeTunnelListener closes tl's listener and, for a SOCKS tunnel, stops
// its background ASN index refresh.
func (s *Server) closeTunnelListener(tl *tunnelListener) {
	_ = tl.listener.Close()
	if tl.socks != nil {
		close(tl.socks.stopASN)
	}
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
		if !ok || nt.VirtualPort != tl.config.VirtualPort || nt.Target != tl.config.Target ||
			socksConfigChanged(nt.Socks, tl.config.Socks) {
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
		s.closeTunnelListener(tl)
	}
	for _, nt := range toOpen {
		if err := s.listenTunnel(d, nt); err != nil {
			s.log.Warn("failed to open tunnel listener on reload", "tunnel", nt.Name, "error", err)
		}
	}
}
func (s *Server) proxy(tl *tunnelListener, in net.Conn) {
	defer in.Close()
	t := tl.config
	host, _, err := net.SplitHostPort(in.RemoteAddr().String())
	if err != nil {
		return
	}
	if !s.allowedIP(host, t.Name) {
		return
	}
	if t.IsSocks() {
		s.proxySocks(tl, host, in)
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

// proxySocks serves the embedded SOCKS proxy for a target: socks tunnel on
// an already-accepted, already-authorized connection. Bytes are counted the
// same way a fixed-target tunnel's are: everything read from the client
// (destined for whatever target the client's SOCKS request names) counts as
// toTarget, everything written back to the client counts as fromTarget.
func (s *Server) proxySocks(tl *tunnelListener, host string, in net.Conn) {
	t := tl.config
	if tl.socks == nil {
		s.log.Warn("socks tunnel has no server instance", "tunnel", t.Name)
		return
	}
	started := time.Now()
	s.log.Debug("socks tunnel connection opened", "tunnel", t.Name, "client", host)
	stats := s.statsFor(host, t.Name)
	stats.connections.Add(1)
	stats.active.Add(1)
	defer stats.active.Add(-1)
	toStart, fromStart := stats.toTarget.Load(), stats.fromTarget.Load()
	tl.socks.server.ServeConn(context.Background(), countingConn{Conn: in, toTarget: &stats.toTarget, fromTarget: &stats.fromTarget})
	s.log.Debug("socks tunnel connection closed", "tunnel", t.Name, "client", host,
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

// countingConn wraps a net.Conn to tally bytes the same way countingWriter
// does for the fixed-target proxy path: Read (bytes from the SOCKS client,
// ultimately relayed to its requested destination) counts as toTarget,
// Write (bytes relayed back to the client) counts as fromTarget.
//
// CloseWrite is implemented explicitly rather than left to interface
// embedding: embedding the net.Conn *interface* only promotes methods
// declared on net.Conn itself, never optional ones (like CloseWrite) a
// particular concrete conn happens to also implement -- so without this,
// pkg/socks's relay half-close would silently degrade to a full Close on
// every SOCKS tunnel connection, cutting off any client upload still in
// flight when the target side finishes first.
type countingConn struct {
	net.Conn
	toTarget   *atomic.Uint64
	fromTarget *atomic.Uint64
}

func (c countingConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

func (c countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.toTarget.Add(uint64(n))
	}
	return n, err
}

func (c countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.fromTarget.Add(uint64(n))
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
	base := p.Addr().As16()
	is4 := p.Addr().Is4()
	for tries := uint32(0); tries < 65534; tries++ {
		n := s.data.next
		s.data.next++
		bits := base
		bits[14] = byte(n >> 8)
		bits[15] = byte(n)
		ip := netip.AddrFrom16(bits)
		if is4 {
			ip = ip.Unmap()
		}
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
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return err
	}
	mask := "/32"
	if addr.Is6() {
		mask = "/128"
	}
	return s.data.stack.AddPeer(wgnet.Endpoint{PublicKey: key, Address: ip + mask})
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
	if u := s.udpr.Load(); u != nil && v.WireGuardPublicKey != "" {
		u.release(v.WireGuardPublicKey)
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
		s.closeTunnelListener(tl)
	}
	s.data.mu.Unlock()
	_ = s.data.stack.Close()
	s.data = nil
}
