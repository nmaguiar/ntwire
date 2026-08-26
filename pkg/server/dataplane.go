package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	urlpkg "net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nmaguiar/ntwire/pkg/socks"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"golang.org/x/net/proxy"
	"golang.zx2c4.com/wireguard/conn"
)

type dataPlane struct {
	stack     *wgnet.Stack
	serverIP  netip.Addr
	mu        sync.Mutex
	next      uint32
	listeners map[string]*tunnelListener // keyed by tunnel name
	dnsConn   net.PacketConn
	portalSrv *http.Server
	portalLn  net.Listener
	stop      chan struct{}
	stopASN   chan struct{}
	ws        *wstransport.Hybrid
	multipath *wstransport.ServerMultipathBind
}

// tunnelListener pairs a live listener with the tunnel config it was opened
// for, so a reload can detect a changed target/virtual_port/socks config and
// recycle it.
type tunnelListener struct {
	listener   net.Listener
	packetConn net.PacketConn
	config     TunnelConfig
	socks      *socksRuntime // non-nil only for config.IsSocks() tunnels
}

type udpFlow struct {
	conn *net.UDPConn
}

// socksRuntime is the live embedded-SOCKS-proxy state for one tunnel.
type socksRuntime struct {
	server *socks.Server
}

// newSocksRuntime builds the SOCKS proxy handler for a target: socks tunnel,
// starting a background ASN index refresh when the tunnel's filters need
// one. cfg.Socks must be non-empty; config validation guarantees this.
func (s *Server) newSocksRuntime(t TunnelConfig, planes ...*dataPlane) *socksRuntime {
	var d *dataPlane
	if len(planes) > 0 {
		d = planes[0]
	}
	sc := t.Socks
	log := s.log.With("tunnel", t.Name)
	dial := (&net.Dialer{}).DialContext
	if sc.Upstream != "" {
		u, err := urlpkg.Parse(sc.Upstream)
		if err != nil {
			return nil
		}
		var auth *proxy.Auth
		if u.User != nil {
			password, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: password}
		}
		up, err := proxy.SOCKS5("tcp", u.Host, auth, proxy.Direct)
		if err != nil {
			return nil
		}
		dial = func(_ context.Context, network, address string) (net.Conn, error) { return up.Dial(network, address) }
	}
	if sc.deniesAllByDefault() {
		log.Warn("socks tunnel has no destination filters and no allow_all; it will deny every connection")
	}
	var sv *socks.Server
	var err error
	sv, err = socks.New(socks.Config{
		Filter: socks.FilterConfig{
			OnlyLocal:      sc.OnlyLocal,
			CIDRs:          sc.Filters,
			DomainSuffixes: sc.DomainFilters,
			ASNs:           sc.ASNFilters,
			Invert:         sc.ReverseFilters,
			AllowAll:       sc.AllowAll,
		},
		ASNLookup: s.asn,
		Authorize: func(ctx context.Context, hostname string, ip netip.Addr, port uint16, protocol string) bool {
			principal, ok := principalFromContext(ctx)
			return ok && s.destinationAllowed(ctx, principal, t, hostname, ip, port, protocol)
		},
		DNSTimeout: sc.DNSTimeout,
		AllowBind:  sc.AllowBind,
		UDPAssociate: func(ctx context.Context, _ string, _ netip.Addr, _ uint16) (*socks.UDPAssociation, bool) {
			if d == nil {
				return nil, false
			}
			principal, ok := principalFromContext(ctx)
			if !ok {
				return nil, false
			}
			pc, err := d.stack.ListenUDP("udp", net.JoinHostPort(d.serverIP.String(), "0"))
			if err != nil {
				return nil, false
			}
			addr, ok := netip.AddrPortFrom(netip.MustParseAddr("0.0.0.0"), 0), true
			if ua, e := netip.ParseAddrPort(pc.LocalAddr().String()); e == nil {
				addr = ua
				ok = true
			}
			if !ok {
				_ = pc.Close()
				return nil, false
			}
			stop := make(chan struct{})
			go s.proxySocksUDP(pc, principal, t, sv, stop)
			return &socks.UDPAssociation{Addr: addr.Addr(), Port: addr.Port(), Close: func() { close(stop); _ = pc.Close() }}, true
		},
		Logger: log,
		Dial:   dial,
	})
	if err != nil {
		// Filters are already validated at config load time; this should be
		// unreachable, but fail closed rather than proxy unfiltered.
		log.Warn("failed to build socks server", "error", err)
		return nil
	}
	return &socksRuntime{server: sv}
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
		s.observe("websocket_connected", "")
		s.log.Info("transport event", "event", "websocket_connected", "transport", "websocket", "relay", relayMode)
	}
	ws.WebSocket.OnPeerDisconnected = func(_ string, _ conn.Endpoint) {
		s.observe("websocket_disconnected", "")
		s.log.Info("transport event", "event", "websocket_disconnected", "transport", "websocket", "relay", relayMode)
	}
	var bind conn.Bind = ws
	var multipath *wstransport.ServerMultipathBind
	if s.Config.MultipathEnabled() {
		mc := s.Config.Relay.Multipath
		multipath = wstransport.NewServerMultipathBind(ws, wstransport.V2Options{
			MirrorRateBytesPerSec: mc.MirrorRateBytesPerSec, MinDeliveryRatio: mc.MinDeliveryRatio,
			SwitchMargin: mc.SwitchMargin, MinDwell: mc.MinDwell, ReportInterval: mc.ReportInterval,
		})
		multipath.SetForced(s.Config.Transport.Force)
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
			s.observe("websocket_connected", "")
			s.log.Info("transport event", "event", "websocket_connected", "transport", "websocket", "relay", true)
			if sess, ok := s.sessions.FindWireGuardPublicKey(id); ok && sess.Multipath {
				multipath.RegisterPath(id, "wss", wstransport.PathWSS, ep, sess.MultipathV2)
			}
		}
		ws.UDP.(*wstransport.FilterBind).SetProbeHandler(multipath.HandlePathControl)
		// Direct clients use this authenticated control-plane registration flow
		// to associate their reflected source address. Answer the reflection
		// request on the same UDP socket; responses and all other controls keep
		// their existing consumers (relay self-reflection, UDP relay binds).
		ws.UDP.(*wstransport.FilterBind).SetControlHandler(func(cp wstransport.ControlPacket) bool {
			if cp.Type != wstransport.FrameReflectRequest {
				return false
			}
			_ = ws.UDP.(*wstransport.FilterBind).SendControl(wstransport.FrameReflectResponse, []byte(cp.From.String()), cp.From.String())
			return true
		})
	}
	privateKey, err := s.wireGuardPrivateKey()
	if err != nil {
		return err
	}
	st, err := wgnet.New(wgnet.Config{PrivateKey: privateKey, Addresses: []netip.Addr{serverIP}, ListenPort: port, Bind: bind})
	if err != nil {
		return err
	}
	d := &dataPlane{stack: st, serverIP: serverIP, next: 2, stop: make(chan struct{}), stopASN: make(chan struct{}), ws: ws, multipath: multipath, listeners: map[string]*tunnelListener{}}
	s.data = d
	if url, ok := s.asnRefreshURL(); ok {
		go s.asn.Refresh(url, 0, s.log, d.stopASN)
	}
	if err := s.installNativePeers(); err != nil {
		s.Close()
		return err
	}
	for _, tunnel := range s.Config.Tunnels {
		if err := s.listenTunnel(d, tunnel); err != nil {
			s.Close()
			return err
		}
	}
	if s.Config.Network.DNS.IsEnabled() {
		if err := s.startDNS(d); err != nil {
			s.log.Warn("in-tunnel DNS server startup failed", "error", err)
		}
	}
	if s.Config.Portal.Enabled && s.Config.Portal.Web.Enabled && s.Config.Portal.Web.Listen != "" {
		if err := s.startWebPortal(d); err != nil {
			s.log.Warn("in-tunnel web portal startup failed", "error", err)
		}
	}
	go s.reapLoop(d)
	return nil
}

func (s *Server) asnRefreshURL() (string, bool) {
	for _, policy := range s.Config.DestinationPolicies {
		if len(policy.ASNFilters) > 0 {
			return "", true
		}
	}
	for _, tunnel := range s.Config.Tunnels {
		if tunnel.Socks != nil && tunnel.Socks.WantsASNUpdates() {
			return tunnel.Socks.ASNURL, true
		}
	}
	return "", false
}

// EnableNativeWireGuardRelay associates the existing server UDP bind with a
// tenant-dedicated relay endpoint. The opaque token was issued over the
// authenticated control connection; no WireGuard key ever reaches the relay.
func (s *Server) EnableNativeWireGuardRelay(addr, token string) {
	s.nativeRelayMu.Lock()
	if s.nativeRelayStop != nil {
		close(s.nativeRelayStop)
		s.nativeRelayStop = nil
	}
	if addr == "" || token == "" || s.data == nil || !s.Config.NativeWireGuard.Enabled {
		s.nativeRelayMu.Unlock()
		return
	}
	bind, ok := s.data.ws.UDP.(*wstransport.FilterBind)
	if !ok {
		s.nativeRelayMu.Unlock()
		return
	}
	stop := make(chan struct{})
	s.nativeRelayStop = stop
	s.nativeRelayMu.Unlock()
	send := func() {
		if err := bind.SendControl(wstransport.FrameNativeWireGuardAssociate, []byte(token), addr); err != nil {
			s.log.Debug("native WireGuard relay association failed", "error", err)
		}
	}
	send()
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				send()
			case <-stop:
				return
			}
		}
	}()
}

// wireGuardPrivateKey preserves the server identity only when explicitly
// configured. Existing deployments retain their historical ephemeral key
// behavior unless they opt in (native peers should always opt in).
func (s *Server) wireGuardPrivateKey() (string, error) {
	path := s.Config.Network.WireGuardPrivateKeyFile
	if path == "" {
		return "", nil
	}
	if b, err := os.ReadFile(path); err == nil {
		key := strings.TrimSpace(string(b))
		if err := wgnet.ValidatePublicKey(key); err != nil {
			return "", fmt.Errorf("network.wireguard_private_key_file: %w", err)
		}
		return key, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	key, err := wgnet.GenerateKey()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(key.Private), 0600); err != nil {
		return "", err
	}
	return key.Private, nil
}

func (s *Server) installNativePeers() error {
	if s.data == nil || !s.Config.NativeWireGuard.Enabled {
		return nil
	}
	for _, peer := range s.Config.NativeWireGuard.Peers {
		ip, _ := netip.ParseAddr(peer.TunnelIP)
		mask := "/32"
		if ip.Is6() {
			mask = "/128"
		}
		if err := s.data.stack.AddPeer(wgnet.Endpoint{PublicKey: peer.PublicKey, Address: ip.String() + mask}); err != nil {
			return fmt.Errorf("install native WireGuard peer %q: %w", peer.Name, err)
		}
	}
	return nil
}

func (s *Server) reconcileNativePeers(old, next []NativeWireGuardPeer) {
	if s.data == nil {
		return
	}
	for _, peer := range old {
		_ = s.data.stack.RemovePeer(peer.PublicKey)
	}
	for _, peer := range next {
		ip, _ := netip.ParseAddr(peer.TunnelIP)
		mask := "/32"
		if ip.Is6() {
			mask = "/128"
		}
		if err := s.data.stack.AddPeer(wgnet.Endpoint{PublicKey: peer.PublicKey, Address: ip.String() + mask}); err != nil {
			s.log.Warn("native WireGuard peer reload failed", "peer", peer.Name, "error", err)
		}
	}
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
	if tunnel.Protocol == "udp" {
		pc, err := d.stack.ListenUDP("udp", net.JoinHostPort(d.serverIP.String(), fmt.Sprint(tunnel.VirtualPort)))
		if err != nil {
			return err
		}
		tl := &tunnelListener{packetConn: pc, config: tunnel}
		d.mu.Lock()
		d.listeners[tunnel.Name] = tl
		d.mu.Unlock()
		s.log.Debug("UDP tunnel listener opened", "tunnel", tunnel.Name, "virtual_port", tunnel.VirtualPort, "target", tunnel.Target)
		go s.proxyUDP(tl, pc)
		return nil
	}
	l, err := d.stack.Listen("tcp", net.JoinHostPort(d.serverIP.String(), fmt.Sprint(tunnel.VirtualPort)))
	if err != nil {
		return err
	}
	tl := &tunnelListener{listener: l, config: tunnel}
	if tunnel.IsSocks() {
		tl.socks = s.newSocksRuntime(tunnel, d)
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

// closeTunnelListener closes tl's listener.
func (s *Server) closeTunnelListener(tl *tunnelListener) {
	if tl.listener != nil {
		_ = tl.listener.Close()
	}
	if tl.packetConn != nil {
		_ = tl.packetConn.Close()
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
		if !ok || nt.VirtualPort != tl.config.VirtualPort || nt.Target != tl.config.Target || nt.Protocol != tl.config.Protocol || nt.UDPIdleTimeout != tl.config.UDPIdleTimeout ||
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

// proxyUDP keeps a separate connected upstream socket for every authenticated
// tunnel source tuple. This prevents replies for one client/application from
// being delivered to another while retaining UDP's connectionless API.
func (s *Server) proxyUDP(tl *tunnelListener, pc net.PacketConn) {
	t := tl.config
	idle := t.UDPIdleTimeout
	if idle <= 0 {
		idle = 2 * time.Minute
	}
	flows := map[string]*udpFlow{}
	var mu sync.Mutex
	closeFlow := func(key string) {
		mu.Lock()
		f := flows[key]
		delete(flows, key)
		mu.Unlock()
		if f != nil {
			_ = f.conn.Close()
		}
	}
	defer func() {
		mu.Lock()
		for _, f := range flows {
			_ = f.conn.Close()
		}
		mu.Unlock()
	}()
	for {
		buf := make([]byte, 65535)
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		host, _, err := net.SplitHostPort(src.String())
		if err != nil {
			continue
		}
		principal, ok := s.principalForIP(host)
		if !ok || !principal.Tunnels[t.Name] {
			continue
		}
		key := src.String()
		mu.Lock()
		f := flows[key]
		mu.Unlock()
		if f == nil {
			out, err := s.dialFixedUDP(principal, t)
			if err != nil {
				continue
			}
			f = &udpFlow{conn: out}
			mu.Lock()
			flows[key] = f
			mu.Unlock()
			stats := s.statsFor(host, t.Name)
			stats.connections.Add(1)
			stats.active.Add(1)
			go func(key string, src net.Addr, f *udpFlow, stats *serverTunnelStats) {
				defer stats.active.Add(-1)
				defer closeFlow(key)
				b := make([]byte, 65535)
				for {
					_ = f.conn.SetReadDeadline(time.Now().Add(idle))
					n, e := f.conn.Read(b)
					if e != nil {
						return
					}
					if _, e = pc.WriteTo(b[:n], src); e != nil {
						return
					}
					stats.fromTarget.Add(uint64(n))
				}
			}(key, src, f, stats)
		}
		_ = f.conn.SetReadDeadline(time.Now().Add(idle))
		if n, err = f.conn.Write(buf[:n]); err == nil {
			s.statsFor(host, t.Name).toTarget.Add(uint64(n))
		}
	}
}

func (s *Server) dialFixedUDP(principal DataPlanePrincipal, t TunnelConfig) (*net.UDPConn, error) {
	host, portText, err := net.SplitHostPort(t.Target)
	if err != nil {
		return nil, err
	}
	port64, err := net.LookupPort("udp", portText)
	if err != nil {
		return nil, err
	}
	port := uint16(port64)
	var ips []netip.Addr
	if ip, e := netip.ParseAddr(host); e == nil {
		ips = []netip.Addr{ip}
	} else {
		ips, err = net.DefaultResolver.LookupNetIP(context.Background(), "ip", host)
		if err != nil {
			return nil, err
		}
	}
	for _, ip := range ips {
		if !s.destinationAllowed(context.Background(), principal, t, host, ip, port, "udp") {
			continue
		}
		c, e := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip.Unmap(), port)))
		if e == nil {
			return c, nil
		}
	}
	return nil, fmt.Errorf("no permitted UDP destination address for %s", host)
}

// proxySocksUDP implements RFC 1928 UDP relay framing for one control-owned
// association. The listener is private to that association and accepts only
// the authenticated tunnel IP that opened its TCP control connection.
func (s *Server) proxySocksUDP(pc net.PacketConn, principal DataPlanePrincipal, t TunnelConfig, sv *socks.Server, stop <-chan struct{}) {
	idle := t.Socks.UDPIdleTimeout
	if idle <= 0 {
		idle = 2 * time.Minute
	}
	type flow struct{ c *net.UDPConn }
	flows := map[string]flow{}
	var mu sync.Mutex
	defer func() {
		mu.Lock()
		for _, f := range flows {
			_ = f.c.Close()
		}
		mu.Unlock()
	}()
	for {
		b := make([]byte, 65535)
		n, src, e := pc.ReadFrom(b)
		if e != nil {
			return
		}
		select {
		case <-stop:
			return
		default:
		}
		host, _, e := net.SplitHostPort(src.String())
		if e != nil || host != principal.TunnelIP.String() {
			continue
		}
		hostname, ip, port, payload, ok := parseSocksUDP(b[:n])
		if !ok {
			continue
		}
		key := net.JoinHostPort(ip.String(), fmt.Sprint(port))
		if hostname != "" {
			key = hostname + ":" + fmt.Sprint(port)
		}
		mu.Lock()
		f, exists := flows[key]
		mu.Unlock()
		if !exists {
			resolved, allowed := sv.AuthorizeUDP(context.Background(), hostname, ip, port)
			if !allowed {
				continue
			}
			out, e := s.dialSocksUDP(principal, t, "", resolved, port)
			if e != nil {
				continue
			}
			f = flow{out}
			mu.Lock()
			flows[key] = f
			mu.Unlock()
			go func(key string, f flow, src net.Addr) {
				defer f.c.Close()
				defer func() { mu.Lock(); delete(flows, key); mu.Unlock() }()
				rb := make([]byte, 65535)
				for {
					_ = f.c.SetReadDeadline(time.Now().Add(idle))
					n, e := f.c.Read(rb)
					if e != nil {
						return
					}
					frame := socksUDPFrame(f.c.RemoteAddr().(*net.UDPAddr).AddrPort(), rb[:n])
					if _, e = pc.WriteTo(frame, src); e != nil {
						return
					}
				}
			}(key, f, src)
		}
		_ = f.c.SetReadDeadline(time.Now().Add(idle))
		_, _ = f.c.Write(payload)
	}
}

func (s *Server) dialSocksUDP(p DataPlanePrincipal, t TunnelConfig, hostname string, ip netip.Addr, port uint16) (*net.UDPConn, error) {
	if !ip.IsValid() {
		var e error
		ips, e := net.DefaultResolver.LookupNetIP(context.Background(), "ip", hostname)
		if e != nil {
			return nil, e
		}
		for _, candidate := range ips {
			if s.destinationAllowed(context.Background(), p, t, hostname, candidate, port, "udp") {
				ip = candidate
				break
			}
		}
	} else if !s.destinationAllowed(context.Background(), p, t, "", ip, port, "udp") {
		return nil, fmt.Errorf("destination policy denied")
	}
	if !ip.IsValid() {
		return nil, fmt.Errorf("no permitted destination")
	}
	return net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip.Unmap(), port)))
}

func parseSocksUDP(b []byte) (string, netip.Addr, uint16, []byte, bool) {
	if len(b) < 4 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
		return "", netip.Addr{}, 0, nil, false
	}
	i := 4
	var host string
	var ip netip.Addr
	switch b[3] {
	case 1:
		if len(b) < i+4+2 {
			return "", ip, 0, nil, false
		}
		var x [4]byte
		copy(x[:], b[i:i+4])
		ip = netip.AddrFrom4(x)
		i += 4
	case 4:
		if len(b) < i+16+2 {
			return "", ip, 0, nil, false
		}
		var x [16]byte
		copy(x[:], b[i:i+16])
		ip = netip.AddrFrom16(x)
		i += 16
	case 3:
		if len(b) < i+1 {
			return "", ip, 0, nil, false
		}
		l := int(b[i])
		i++
		if len(b) < i+l+2 || l == 0 {
			return "", ip, 0, nil, false
		}
		host = string(b[i : i+l])
		i += l
	default:
		return "", ip, 0, nil, false
	}
	port := uint16(b[i])<<8 | uint16(b[i+1])
	return host, ip, port, b[i+2:], true
}
func socksUDPFrame(ap netip.AddrPort, p []byte) []byte {
	ip := ap.Addr().Unmap()
	if ip.Is4() {
		a := ip.As4()
		b := make([]byte, 10+len(p))
		b[3] = 1
		copy(b[4:8], a[:])
		b[8] = byte(ap.Port() >> 8)
		b[9] = byte(ap.Port())
		copy(b[10:], p)
		return b
	}
	a := ip.As16()
	b := make([]byte, 22+len(p))
	b[3] = 4
	copy(b[4:20], a[:])
	b[20] = byte(ap.Port() >> 8)
	b[21] = byte(ap.Port())
	copy(b[22:], p)
	return b
}
func (s *Server) proxy(tl *tunnelListener, in net.Conn) {
	defer in.Close()
	t := tl.config
	host, _, err := net.SplitHostPort(in.RemoteAddr().String())
	if err != nil {
		return
	}
	principal, ok := s.principalForIP(host)
	if !ok || !principal.Tunnels[t.Name] {
		return
	}
	if t.IsSocks() {
		s.proxySocks(tl, principal, host, in)
		return
	}
	out, err := s.dialFixedTarget(principal, t)
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
func (s *Server) proxySocks(tl *tunnelListener, principal DataPlanePrincipal, host string, in net.Conn) {
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
	tl.socks.server.ServeConn(context.WithValue(context.Background(), principalContextKey{}, principal), countingConn{Conn: in, toTarget: &stats.toTarget, fromTarget: &stats.fromTarget})
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

type principalContextKey struct{}

func principalFromContext(ctx context.Context) (DataPlanePrincipal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(DataPlanePrincipal)
	return p, ok
}

func (s *Server) principalForIP(ip string) (DataPlanePrincipal, bool) {
	for _, v := range s.sessions.All() {
		if v.TunnelIP == ip {
			addr, _ := netip.ParseAddr(ip)
			grants := map[string]bool{}
			for _, t := range v.Tunnels {
				grants[t.Name] = true
			}
			return DataPlanePrincipal{Method: v.Method, Identity: v.Identity, TunnelIP: addr, Tunnels: grants}, true
		}
	}
	for _, peer := range s.Config.NativeWireGuard.Peers {
		if peer.TunnelIP == ip {
			addr, _ := netip.ParseAddr(ip)
			grants := map[string]bool{}
			for _, tunnel := range peer.Tunnels {
				grants[tunnel] = true
			}
			return DataPlanePrincipal{Method: "native-wireguard", Identity: peer.Name, TunnelIP: addr, Tunnels: grants, Policy: peer.DestinationPolicy}, true
		}
	}
	return DataPlanePrincipal{}, false
}

// allowedIP remains the narrow compatibility helper used by older callers;
// all new data-plane paths should retain the principal and use it for the
// subsequent destination decision.
func (s *Server) allowedIP(ip, tunnel string) bool {
	p, ok := s.principalForIP(ip)
	return ok && p.Tunnels[tunnel]
}

// dialFixedTarget resolves once, evaluates the selected address, then dials
// that exact address. This prevents DNS rebinding between policy evaluation
// and the actual outbound connection.
func (s *Server) dialFixedTarget(principal DataPlanePrincipal, t TunnelConfig) (net.Conn, error) {
	host, portText, err := net.SplitHostPort(t.Target)
	if err != nil {
		return nil, err
	}
	port64, err := net.LookupPort("tcp", portText)
	if err != nil {
		return nil, err
	}
	port := uint16(port64)
	if ip, err := netip.ParseAddr(host); err == nil {
		if !s.destinationAllowed(context.Background(), principal, t, "", ip, port, "tcp") {
			return nil, fmt.Errorf("destination policy denied")
		}
		return net.DialTimeout("tcp", netip.AddrPortFrom(ip.Unmap(), port).String(), 10*time.Second)
	}
	addrs, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", host)
	if err != nil {
		return nil, err
	}
	for _, ip := range addrs {
		if !s.destinationAllowed(context.Background(), principal, t, host, ip, port, "tcp") {
			continue
		}
		conn, err := net.DialTimeout("tcp", netip.AddrPortFrom(ip.Unmap(), port).String(), 10*time.Second)
		if err == nil {
			return conn, nil
		}
	}
	return nil, fmt.Errorf("no permitted destination address for %s", host)
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
		for _, peer := range s.Config.NativeWireGuard.Peers {
			if peer.TunnelIP == ip.String() {
				used = true
				break
			}
		}
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
			s.reapSessions()
		case <-d.stop:
			return
		}
	}
}

// reapSessions owns one complete expiry transition. It is intentionally
// separate from the ticker so tests and controlled shutdown paths can drive
// expiration deterministically rather than waiting for wall-clock polling.
func (s *Server) reapSessions() {
	// Expiry may remove a WireGuard peer. Serialize it with renewal and reload
	// so an expiring old session cannot tear down the peer a just-completed
	// renewal deliberately preserved.
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	for _, v := range s.sessions.Reap() {
		s.dropSession(v)
		s.log.Debug("session expired", "session", v.ID, "identity", v.Identity)
		s.observe("session_expired", v.Method)
		s.audit("session_expired", v, "", 0)
	}
}
func (s *Server) Close() {
	if s.data == nil {
		return
	}
	s.nativeRelayMu.Lock()
	if s.nativeRelayStop != nil {
		close(s.nativeRelayStop)
		s.nativeRelayStop = nil
	}
	s.nativeRelayMu.Unlock()
	close(s.data.stop)
	close(s.data.stopASN)
	s.data.mu.Lock()
	for _, tl := range s.data.listeners {
		s.closeTunnelListener(tl)
	}
	s.data.mu.Unlock()
	if s.data.dnsConn != nil {
		_ = s.data.dnsConn.Close()
	}
	if s.data.portalSrv != nil {
		_ = s.data.portalSrv.Close()
	}
	if s.data.portalLn != nil {
		_ = s.data.portalLn.Close()
	}
	_ = s.data.stack.Close()
	s.data = nil
}
