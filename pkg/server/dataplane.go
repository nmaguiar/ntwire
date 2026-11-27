package server

import (
	"context"
	"errors"
	"fmt"
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

	"github.com/nmaguiar/ntwire/internal/localproxy"
	"github.com/nmaguiar/ntwire/pkg/socks"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"golang.org/x/net/proxy"
	"golang.zx2c4.com/wireguard/conn"
)

type dataPlane struct {
	stack     serverStack
	serverIP  netip.Addr
	mu        sync.Mutex
	nextIP    netip.Addr
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
	conn         *net.UDPConn
	peerLifetime string
	lifetime     context.Context
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
	if sc.Transparent {
		return nil
	}
	log := s.log.With("tunnel", t.Name)
	dial := (&net.Dialer{}).DialContext
	dialRemoteHostname := false
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
		dialRemoteHostname = u.Scheme == "socks5h"
		dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			if contextDialer, ok := up.(proxy.ContextDialer); ok {
				return contextDialer.DialContext(ctx, network, address)
			}
			return up.Dial(network, address)
		}
	}
	if sc.deniesAllByDefault() {
		log.Warn("socks tunnel has no destination filters and no allow_all; it will deny every connection")
	}
	var sv *socks.Server
	var err error
	var binding func(context.Context) bool
	if t.nativeSOCKSEgress() && sc.AllowDestinationBinding {
		binding = func(ctx context.Context) bool {
			principal, valid := principalFromContext(ctx)
			if !valid {
				return false
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			current, granted := s.principalForIPLocked(principal.TunnelIP.String())
			tunnel, configured := s.tunnelConfigLocked(t.Name)
			return granted && current.peerLifetime == principal.peerLifetime && current.Identity == principal.Identity &&
				current.Method == principal.Method && current.Policy == principal.Policy && current.Tunnels[t.Name] &&
				configured && tunnel.nativeSOCKSEgress() && tunnel.Socks.AllowDestinationBinding && reflect.DeepEqual(tunnel, t)
		}
	}
	sv, err = socks.New(socks.Config{
		AllowDestinationBinding: binding,
		Filter: socks.FilterConfig{
			AllowLocalEgress: t.Socks.AllowLocalEgress,
			OnlyLocal:        sc.OnlyLocal,
			CIDRs:            sc.Filters,
			DomainSuffixes:   sc.DomainFilters,
			ASNs:             sc.ASNFilters,
			Invert:           sc.ReverseFilters,
			AllowAll:         sc.AllowAll,
		},
		ASNLookup: s.asn,
		AuthorizeDestination: func(ctx context.Context, hostname, literal string, ip netip.Addr, port uint16, protocol string) bool {
			principal, ok := principalFromContext(ctx)
			// Accepted SOCKS sockets can outlive their listener across reload.
			// Resolve the attachment for every new destination command.
			current, exists := s.tunnelConfig(t.Name)
			return ok && exists && current.IsSocks() && s.destinationAllowedRequest(ctx, principal, current, hostname, literal, ip, port, protocol)
		},
		DNSTimeout:         sc.DNSTimeout,
		AllowBind:          sc.AllowBind,
		DialRemoteHostname: dialRemoteHostname,
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
			lifetime, endRelay := context.WithCancel(ctx)
			go func() {
				defer endRelay()
				s.proxySocksUDP(pc, principal, t, sv, lifetime.Done())
			}()
			return &socks.UDPAssociation{Addr: addr.Addr(), Port: addr.Port(), Lifetime: lifetime, Close: func() { endRelay(); _ = pc.Close() }}, true
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

// startDataPlane starts WireGuard and its virtual-port listeners at boot.
func (s *Server) startDataPlane(newStack func(wgnet.Config) (serverStack, error)) error {
	prefix, err := netip.ParsePrefix(s.Config.Network.TunnelCIDR)
	if err != nil {
		return err
	}
	serverIP := prefix.Masked().Addr().Next()
	port, err := portOf(s.Config.Listen.WireGuard)
	if err != nil {
		return err
	}
	privateKey, err := s.wireGuardPrivateKey()
	if err != nil {
		return err
	}
	ws := wstransport.NewHybrid(s.log)
	udp, _ := ws.UDP.(*wstransport.FilterBind).Unwrap().(*wstransport.UDPBind)
	if s.Config.Transport.SampleWSS {
		ws.WebSocket.EnableQueuePerformance()
	}
	if s.Config.Listen.WireGuardAlt != "" {
		alt, err := portOf(s.Config.Listen.WireGuardAlt)
		if err != nil {
			return err
		}
		if udp != nil {
			udp.SetAltPort(uint16(alt))
			s.log.Info("alternate WireGuard UDP port enabled", "port", alt)
		}
	}
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
		multipath = wstransport.NewServerMultipathBind(ws, wstransport.MultipathOptions{
			DuplicateRateBytesPerSec: mc.DuplicateRateBytesPerSec,
			MTUAware:                 s.Config.Transport.MTUAware,
		})
		multipath.SetForced(s.Config.Transport.Force)
		if s.Config.Transport.Metrics {
			// Keep totals across data-plane restarts within one process.
			s.transportSwitches.CompareAndSwap(nil, newTransportSwitchCounters())
			multipath.SetSwitchObserver(s.transportSwitches.Load().observe)
		}
		bind = multipath
		// id is the connecting peer's WireGuardPublicKey (see the /v1/wg
		// handler's ServeHTTP call). Gate on that session's own negotiated
		// Multipath flag, not just Relay.Enabled: a peer that didn't
		// negotiate multipath-v3 (an older client, or one that simply
		// doesn't offer the capability) has no MultipathBind of its own and
		// will never understand a FramePathProbe sent to it -- registering
		// it here anyway would only add a phantom candidate this bind
		// probes forever for no one to answer.
		ws.WebSocket.OnPeerConnected = func(id string, ep conn.Endpoint) {
			s.operationMu.Lock()
			defer s.operationMu.Unlock()
			s.observe("websocket_connected", "")
			s.log.Info("transport event", "event", "websocket_connected", "transport", "websocket", "relay", true)
			if sess, ok := s.sessions.FindWireGuardPublicKey(id); ok && sess.Multipath {
				multipath.RegisterPath(id, "wss", wstransport.PathWSS, ep, sess.PathMTU)
				multipath.ActivatePath(id, "wss")
			}
		}
		ws.WebSocket.OnPeerDisconnected = func(id string, _ conn.Endpoint) {
			s.observe("websocket_disconnected", "")
			s.log.Info("transport event", "event", "websocket_disconnected", "transport", "websocket", "relay", true)
			multipath.DeactivatePath(id, "wss")
		}
		ws.WebSocket.OnWriteFailure = func(id string, _ conn.Endpoint) {
			multipath.DeactivatePath(id, "wss")
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
	st, err := newStack(wgnet.Config{PrivateKey: privateKey, Addresses: []netip.Addr{serverIP}, ListenPort: port, Bind: bind})
	if err != nil {
		return dataPlaneStartupError(err, bind.Close())
	}
	d := &dataPlane{stack: st, serverIP: serverIP, stop: make(chan struct{}), stopASN: make(chan struct{}), ws: ws, multipath: multipath, listeners: map[string]*tunnelListener{}}
	s.data = d
	fail := func(err error) error {
		return dataPlaneStartupError(err, s.closeDataPlane())
	}
	if err := s.installNativePeers(); err != nil {
		return fail(err)
	}
	for _, tunnel := range s.Config.Tunnels {
		if err := s.listenTunnel(d, tunnel); err != nil {
			return fail(err)
		}
	}
	if s.Config.Network.DNS.IsEnabled() {
		if err := s.startDNS(d); err != nil {
			s.log.Warn("in-tunnel DNS server startup failed", "error", err)
		}
	}
	if s.Config.Portal.Enabled && s.Config.Portal.Web.Enabled && s.Config.Portal.Web.Listen != "" {
		if err := s.startWebPortal(d, true); err != nil {
			s.log.Warn("in-tunnel web portal startup failed", "error", err)
		}
	}
	if s.Config.Transport.Adaptive {
		s.adaptive, err = s.startAdaptiveServerPlane(wgnet.Config{PrivateKey: privateKey, Addresses: []netip.Addr{serverIP}})
		if err != nil {
			return fail(fmt.Errorf("start adaptive carrier data plane: %w", err))
		}
	}
	if staged, ok := st.(interface{ activate() error }); ok {
		if err := staged.activate(); err != nil {
			return fail(err)
		}
	}
	if url, ok := s.asnRefreshURL(); ok {
		go s.asn.Refresh(url, 0, s.log, d.stopASN)
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

// NativeAssociation is one relay's tenant-dedicated native WireGuard endpoint
// and the token that authorizes this server to claim it.
type NativeAssociation struct{ Addr, Token string }

// EnableNativeWireGuardRelay associates the existing server UDP bind with a
// single tenant-dedicated relay endpoint; see EnableNativeWireGuardRelays.
func (s *Server) EnableNativeWireGuardRelay(addr, token string) {
	if addr == "" || token == "" {
		s.EnableNativeWireGuardRelays(nil)
		return
	}
	s.EnableNativeWireGuardRelays([]NativeAssociation{{addr, token}})
}

// EnableNativeWireGuardRelays associates the existing server UDP bind with
// every given relay endpoint (one per registered relay). The opaque tokens
// were issued over authenticated control connections; no WireGuard key ever
// reaches a relay. A hostname endpoint (a wildcard relay listener advertises
// tenant.domain:port) is resolved on every refresh so a relay address change
// heals without a restart. Passing nil stops all associations.
func (s *Server) EnableNativeWireGuardRelays(assocs []NativeAssociation) {
	s.relayLifecycleMu.Lock()
	defer s.relayLifecycleMu.Unlock()
	s.nativeRelayMu.Lock()
	if s.nativeRelayStop != nil {
		close(s.nativeRelayStop)
		s.nativeRelayStop = nil
	}
	if len(assocs) == 0 || s.data == nil || !s.Config.NativeWireGuard.Enabled {
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
	assocs = append([]NativeAssociation(nil), assocs...)
	failing := map[string]bool{}
	send := func() {
		var reserved []string
		defer func() {
			if s.data != nil && s.data.multipath != nil {
				s.data.multipath.ReserveSources(reserved)
			}
		}()
		for _, a := range assocs {
			target := a.Addr
			if _, err := netip.ParseAddrPort(target); err != nil {
				ua, rerr := net.ResolveUDPAddr("udp", target)
				if rerr != nil {
					if !failing[a.Addr] {
						s.log.Warn("native WireGuard relay endpoint did not resolve", "addr", a.Addr, "error", rerr)
					}
					failing[a.Addr] = true
					continue
				}
				target = ua.AddrPort().String()
			}
			if ap, perr := netip.ParseAddrPort(target); perr == nil {
				reserved = append(reserved, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String())
			}
			if err := bind.SendControl(wstransport.FrameNativeWireGuardAssociate, []byte(a.Token), target); err != nil {
				if !failing[a.Addr] {
					s.log.Warn("native WireGuard relay association failed", "addr", a.Addr, "error", err)
				}
				failing[a.Addr] = true
				continue
			}
			delete(failing, a.Addr)
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
	s.reloadPlaneTunnels(s.data, newTunnels)
	if s.adaptive != nil {
		s.reloadPlaneTunnels(s.adaptive.data, newTunnels)
	}
}

func (s *Server) reloadPlaneTunnels(d *dataPlane, newTunnels []TunnelConfig) {
	if d == nil {
		return
	}
	wanted := make(map[string]TunnelConfig, len(newTunnels))
	for _, t := range newTunnels {
		wanted[t.Name] = t
	}
	d.mu.Lock()
	var toClose []*tunnelListener
	var toOpen []TunnelConfig
	for name, tl := range d.listeners {
		nt, ok := wanted[name]
		if !ok || nt.DestinationPolicy != tl.config.DestinationPolicy || nt.VirtualPort != tl.config.VirtualPort || nt.Target != tl.config.Target || nt.Protocol != tl.config.Protocol || nt.UDPIdleTimeout != tl.config.UDPIdleTimeout ||
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
	closeFlow := func(key string, f *udpFlow) {
		mu.Lock()
		if flows[key] == f {
			delete(flows, key)
		}
		mu.Unlock()
		_ = f.conn.Close()
	}
	defer func() {
		mu.Lock()
		for _, f := range flows {
			_ = f.conn.Close()
		}
		mu.Unlock()
	}()
	buf := make([]byte, 65535)
	for {
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
		if f != nil && (f.lifetime != nil || principal.flowLifetime != nil) && f.peerLifetime != principal.peerLifetime {
			closeFlow(key, f)
			f = nil
		}
		if f == nil {
			out, err := s.dialFixedUDP(principal, t)
			if err != nil {
				continue
			}
			f = &udpFlow{conn: out, peerLifetime: principal.peerLifetime, lifetime: principal.flowLifetime}
			mu.Lock()
			flows[key] = f
			mu.Unlock()
			stats := s.statsFor(host, t.Name)
			stats.connections.Add(1)
			stats.active.Add(1)
			go func(key string, src net.Addr, f *udpFlow, stats *serverTunnelStats) {
				defer stats.active.Add(-1)
				defer closeFlow(key, f)
				if f.lifetime != nil {
					stop := context.AfterFunc(f.lifetime, func() { _ = f.conn.Close() })
					defer stop()
				}
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
		if f.lifetime != nil && f.lifetime.Err() != nil {
			continue
		}
		_ = f.conn.SetReadDeadline(time.Now().Add(idle))
		if n, err = f.conn.Write(buf[:n]); err == nil {
			s.statsFor(host, t.Name).toTarget.Add(uint64(n))
		}
	}
}

func (s *Server) dialFixedUDP(principal DataPlanePrincipal, t TunnelConfig) (*net.UDPConn, error) {
	ctx := principalFlowContext(principal)
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
		ips, err = net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
	}
	for _, ip := range ips {
		if ctx.Err() != nil || !s.destinationAllowed(ctx, principal, t, host, ip, port, "udp") {
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
	defer pc.Close()
	idle := t.Socks.UDPIdleTimeout
	if idle <= 0 {
		idle = 2 * time.Minute
	}
	type flow struct {
		c  *net.UDPConn
		ip netip.Addr
	}
	type destinationKey struct {
		host string
		ip   netip.Addr
		port uint16
	}
	flows := map[destinationKey]flow{}
	ownerIP := principal.TunnelIP.String()
	// The TCP association has already registered this forwarding counter.
	// Keep that lifetime's pointer instead of recreating a deleted entry.
	entry, _ := s.tunnelStats.Load(statsKey(ownerIP, t.Name))
	stats, _ := entry.(*serverTunnelStats)
	currentOwner := func() (DataPlanePrincipal, TunnelConfig, bool) {
		s.mu.Lock()
		defer s.mu.Unlock()
		current, granted := s.principalForIPLocked(ownerIP)
		if !granted || !current.Tunnels[t.Name] || current.peerLifetime != principal.peerLifetime ||
			current.Identity != principal.Identity || current.Method != principal.Method {
			return DataPlanePrincipal{}, TunnelConfig{}, false
		}
		tunnel, configured := s.tunnelConfigLocked(t.Name)
		return current, tunnel, configured && tunnel.IsSocks() && reflect.DeepEqual(tunnel.Socks, t.Socks) && tunnel.VirtualPort == t.VirtualPort
	}
	var mu sync.Mutex
	defer func() {
		mu.Lock()
		for _, f := range flows {
			_ = f.c.Close()
		}
		mu.Unlock()
	}()
	b := make([]byte, 65535)
	for {
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
		if e != nil || host != ownerIP {
			continue
		}
		dst, offset, err := socks.DatagramDestination(b[:n])
		if err != nil {
			continue
		}
		current, tunnel, owned := currentOwner()
		if !owned {
			return
		}
		ctx := context.WithValue(context.Background(), principalContextKey{}, current)
		key := destinationKey{ip: dst.IP(), port: dst.Port}
		if !key.ip.IsValid() {
			key.host = dst.Host
		}
		mu.Lock()
		f, exists := flows[key]
		count := len(flows)
		mu.Unlock()
		if exists {
			// A cached binary flow does not carry the legacy suffix check
			// required for a domain-form literal addressed to that same IP.
			if dst.NumericDomain() {
				if _, allowed := sv.AuthorizeDatagram(ctx, dst); !allowed {
					continue
				}
			} else if !s.destinationAllowed(ctx, current, tunnel, key.host, f.ip, dst.Port, "udp") {
				continue
			}
		} else {
			const maxSOCKSUDPFlows = 64
			if count >= maxSOCKSUDPFlows {
				continue
			}
			resolved, allowed := sv.AuthorizeDatagram(ctx, dst)
			if !allowed {
				continue
			}
			out, e := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(resolved.Unmap(), dst.Port)))
			if e != nil {
				continue
			}
			f = flow{c: out, ip: resolved}
			mu.Lock()
			flows[key] = f
			mu.Unlock()
			go func(key destinationKey, f flow, src net.Addr) {
				defer f.c.Close()
				defer func() { mu.Lock(); delete(flows, key); mu.Unlock() }()
				rb := make([]byte, 65535)
				for {
					_ = f.c.SetReadDeadline(time.Now().Add(idle))
					n, e := f.c.Read(rb)
					if e != nil {
						return
					}
					if _, _, owned := currentOwner(); !owned {
						_ = pc.Close()
						return
					}
					frame := socksUDPFrame(f.c.RemoteAddr().(*net.UDPAddr).AddrPort(), rb[:n])
					written, err := pc.WriteTo(frame, src)
					if err != nil {
						return
					}
					if stats != nil {
						stats.fromTarget.Add(uint64(written))
					}
				}
			}(key, f, src)
		}
		_ = f.c.SetReadDeadline(time.Now().Add(idle))
		if _, err := f.c.Write(b[offset:n]); err == nil && stats != nil {
			stats.toTarget.Add(uint64(n))
		}
	}
}

func socksUDPFrame(ap netip.AddrPort, p []byte) []byte { return socks.DatagramFrame(ap, p) }
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
	if principal.flowLifetime != nil {
		if principal.flowLifetime.Err() != nil {
			return
		}
		stop := context.AfterFunc(principal.flowLifetime, func() { _ = in.Close() })
		defer stop()
	}
	if t.IsSocks() {
		s.proxySocks(tl, principal, host, in)
		return
	}
	out, err := s.dialFixedTargetContext(principalFlowContext(principal), principal, t)
	if err != nil {
		s.log.Debug("tunnel target dial failed", "tunnel", t.Name, "target", t.Target, "error", err)
		return
	}
	defer out.Close()
	if principal.flowLifetime != nil {
		stop := context.AfterFunc(principal.flowLifetime, func() { _ = out.Close() })
		defer stop()
	}
	started := time.Now()
	s.log.Debug("tunnel connection opened", "tunnel", t.Name, "client", host)
	stats := s.statsFor(host, t.Name)
	stats.connections.Add(1)
	stats.active.Add(1)
	defer stats.active.Add(-1)
	toStart, fromStart := stats.toTarget.Load(), stats.fromTarget.Load()
	localproxy.RelayCounted(in, out, &stats.toTarget, &stats.fromTarget)
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
	if t.Socks.Transparent {
		s.proxyTransparentSocks(t, principal, host, in)
		return
	}
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
	tl.socks.server.ServeConn(context.WithValue(principalFlowContext(principal), principalContextKey{}, principal), countingConn{Conn: in, toTarget: &stats.toTarget, fromTarget: &stats.fromTarget})
	s.log.Debug("socks tunnel connection closed", "tunnel", t.Name, "client", host,
		"bytes_to_target", stats.toTarget.Load()-toStart, "bytes_from_target", stats.fromTarget.Load()-fromStart, "duration", time.Since(started))
}

// proxyTransparentSocks carries the client's SOCKS protocol unchanged to the
// configured upstream. The upstream, rather than ntwire, resolves requested
// hostnames and applies destination authorization.
func (s *Server) proxyTransparentSocks(t TunnelConfig, principal DataPlanePrincipal, host string, in net.Conn) {
	u, err := urlpkg.Parse(t.Socks.Upstream)
	if err != nil {
		return
	}
	out, err := s.dialTargetContext(principalFlowContext(principal), principal, t, u.Host)
	if err != nil {
		s.log.Debug("transparent SOCKS upstream dial failed", "tunnel", t.Name, "target", u.Host, "error", err)
		return
	}
	defer out.Close()
	if principal.flowLifetime != nil {
		stop := context.AfterFunc(principal.flowLifetime, func() { _ = out.Close() })
		defer stop()
	}
	started := time.Now()
	stats := s.statsFor(host, t.Name)
	stats.connections.Add(1)
	stats.active.Add(1)
	defer stats.active.Add(-1)
	toStart, fromStart := stats.toTarget.Load(), stats.fromTarget.Load()
	localproxy.RelayCounted(in, out, &stats.toTarget, &stats.fromTarget)
	s.log.Debug("transparent SOCKS tunnel connection closed", "tunnel", t.Name, "client", host,
		"bytes_to_target", stats.toTarget.Load()-toStart, "bytes_from_target", stats.fromTarget.Load()-fromStart, "duration", time.Since(started))
}

func principalFlowContext(principal DataPlanePrincipal) context.Context {
	if principal.flowLifetime != nil {
		return principal.flowLifetime
	}
	return context.Background()
}

// countingConn tallies bytes for the embedded SOCKS handler. Read (bytes
// from the SOCKS client,
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
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.principalForIPLocked(ip)
}

func (s *Server) principalForIPLocked(ip string) (DataPlanePrincipal, bool) {
	if s.adaptive != nil && s.adaptive.isQuarantinedIP(ip) {
		return DataPlanePrincipal{}, false
	}
	if principal, ok := s.sessions.principalForIP(ip); ok {
		return principal, true
	}
	for _, peer := range s.Config.NativeWireGuard.Peers {
		if peer.TunnelIP == ip {
			addr, _ := netip.ParseAddr(ip)
			grants := map[string]bool{}
			for _, tunnel := range peer.Tunnels {
				grants[tunnel] = true
			}
			return DataPlanePrincipal{peerLifetime: s.nativePeerLifetime, Method: "native-wireguard", Identity: peer.Name, TunnelIP: addr, Tunnels: grants, Policy: peer.DestinationPolicy}, true
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
	return s.dialTarget(principal, t, t.Target)
}

func (s *Server) dialFixedTargetContext(ctx context.Context, principal DataPlanePrincipal, t TunnelConfig) (net.Conn, error) {
	return s.dialTargetContext(ctx, principal, t, t.Target)
}

// dialTarget resolves once, evaluates the selected address, then dials that
// exact TCP target. Transparent SOCKS uses it to protect the configured
// upstream endpoint while leaving destinations inside SOCKS opaque.
func (s *Server) dialTarget(principal DataPlanePrincipal, t TunnelConfig, target string) (net.Conn, error) {
	return s.dialTargetContext(context.Background(), principal, t, target)
}
func (s *Server) dialTargetContext(ctx context.Context, principal DataPlanePrincipal, t TunnelConfig, target string) (net.Conn, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port64, err := net.LookupPort("tcp", portText)
	if err != nil {
		return nil, err
	}
	port := uint16(port64)
	if ip, err := netip.ParseAddr(host); err == nil {
		if !s.destinationAllowed(ctx, principal, t, "", ip, port, "tcp") {
			return nil, fmt.Errorf("destination policy denied")
		}
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", netip.AddrPortFrom(ip.Unmap(), port).String())
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	for _, ip := range addrs {
		if !s.destinationAllowed(ctx, principal, t, host, ip, port, "tcp") {
			continue
		}
		conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", netip.AddrPortFrom(ip.Unmap(), port).String())
		if err == nil {
			return conn, nil
		}
	}
	return nil, fmt.Errorf("no permitted destination address for %s", host)
}
func (s *Server) allocateIP() (string, error) {
	s.data.mu.Lock()
	defer s.data.mu.Unlock()
	p, err := netip.ParsePrefix(s.Config.Network.TunnelCIDR)
	if err != nil {
		return "", err
	}
	p = p.Masked()
	used := map[netip.Addr]bool{p.Addr(): true, p.Addr().Next(): true, s.data.serverIP: true}
	if p.Addr().Is4() {
		last := p.Addr().As4()
		for bit := p.Bits(); bit < 32; bit++ {
			last[bit/8] |= 1 << (7 - bit%8)
		}
		used[netip.AddrFrom4(last)] = true
	}
	for _, peer := range s.Config.NativeWireGuard.Peers {
		if ip, err := netip.ParseAddr(peer.TunnelIP); err == nil {
			used[ip.Unmap()] = true
		}
	}
	for _, session := range s.sessions.All() {
		if ip, err := netip.ParseAddr(session.TunnelIP); err == nil {
			used[ip.Unmap()] = true
		}
		for _, child := range session.children {
			if ip, err := netip.ParseAddr(child.ip); err == nil {
				used[ip.Unmap()] = true
			}
		}
	}
	if s.adaptive != nil {
		for address := range s.adaptive.retired {
			if ip, err := netip.ParseAddr(address); err == nil {
				used[ip.Unmap()] = true
			}
		}
	}
	// At most len(used) consecutive candidates can be occupied. This bounds
	// the scan even for IPv6, without restricting allocation to a 16-bit pool.
	for tries := 0; tries <= len(used); tries++ {
		ip := s.data.nextIP
		if !ip.IsValid() || !p.Contains(ip) {
			ip = p.Addr()
		}
		s.data.nextIP = ip.Next()
		if !used[ip] {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("tunnel IP pool exhausted")
}
func (s *Server) addPeer(key, ip string) error {
	if s.data == nil {
		return nil
	}
	return addDataPlanePeer(s.data, key, ip, "")
}

func addDataPlanePeer(d *dataPlane, key, ip, endpoint string) error {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return err
	}
	mask := "/32"
	if addr.Is6() {
		mask = "/128"
	}
	address := ip + mask
	if endpoint != "" {
		address += "@" + endpoint
	}
	return d.stack.AddPeer(wgnet.Endpoint{PublicKey: key, Address: address})
}
func (s *Server) dropSession(v Session) {
	// Cancel and serialize relay allocations before removing their endpoints.
	if u := s.udpr.Load(); u != nil && v.WireGuardPublicKey != "" {
		u.release(v.WireGuardPublicKey)
	}

	s.clearLaneStats(v.Tunnels, v.TunnelIP)
	if v.Adaptive != nil {
		for _, child := range v.children {
			s.clearLaneStats(v.Tunnels, child.ip)
		}
		if s.adaptive != nil {
			s.adaptive.remove(v)
		}
		return
	}
	if s.data != nil && v.WireGuardPublicKey != "" {
		_ = s.data.stack.RemovePeer(v.WireGuardPublicKey)
	}
	if s.data != nil && s.data.multipath != nil && v.WireGuardPublicKey != "" {
		s.data.multipath.RemovePeer(v.WireGuardPublicKey)
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
	s.reapSessionsLocked()
}

// reapSessionsLocked requires operationMu, including when called before reconnect.
func (s *Server) reapSessionsLocked() {
	for _, v := range s.sessions.Reap() {
		s.dropSession(v)
		s.log.Debug("session expired", "session", v.ID, "identity", v.Identity)
		s.observe("session_expired", v.Method)
		s.audit("session_expired", v, "", 0)
	}
	s.reapUnconfirmedLanes(time.Now())
	s.reapRelayAllocations(time.Now())
}
func (s *Server) Close() {
	if err := s.closeDataPlane(); err != nil {
		s.log.Error("data plane cleanup failed", "error", err)
	}
}

func (s *Server) closeDataPlane() error {
	s.relayLifecycleMu.Lock()
	defer s.relayLifecycleMu.Unlock()
	if u := s.udpr.Swap(nil); u != nil {
		u.stopAll()
	}
	s.operationMu.Lock()
	s.mu.Lock()
	direct := s.direct
	s.direct = nil
	d := s.data
	adaptive := s.adaptive
	s.data, s.adaptive = nil, nil
	if adaptive != nil {
		for _, v := range s.sessions.All() {
			if v.Adaptive != nil {
				s.sessions.Delete(v.Token)
			}
		}
		for _, lane := range adaptive.lanes {
			adaptive.retireRelayAllocations(lane)
		}
	}
	s.mu.Unlock()
	s.operationMu.Unlock()
	if direct != nil {
		close(direct.stop)
	}
	s.nativeRelayMu.Lock()
	if s.nativeRelayStop != nil {
		close(s.nativeRelayStop)
		s.nativeRelayStop = nil
	}
	s.nativeRelayMu.Unlock()
	if adaptive != nil {
		for _, lane := range adaptive.lanes {
			lane.cancel()
		}
		return errors.Join(s.closePlane(adaptive.data), adaptive.quic.close(), adaptive.http3.close(), s.closePlane(d))
	}
	return s.closePlane(d)
}

func (s *Server) closePlane(d *dataPlane) error {
	if d == nil {
		return nil
	}
	close(d.stop)
	close(d.stopASN)
	d.mu.Lock()
	for _, tl := range d.listeners {
		s.closeTunnelListener(tl)
	}
	d.mu.Unlock()
	if d.dnsConn != nil {
		_ = d.dnsConn.Close()
	}
	if d.portalSrv != nil {
		_ = d.portalSrv.Close()
	}
	if d.portalLn != nil {
		_ = d.portalLn.Close()
	}
	return d.stack.Close()
}
