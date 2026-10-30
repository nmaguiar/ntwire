package client

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

// connectionNetwork owns one generation of the client data plane.
type connectionNetwork struct {
	stack                            *wgnet.Stack
	hybrid                           *wstransport.Hybrid
	multipath                        *wstransport.MultipathBind
	clientIP, serverIP               netip.Addr
	udpEndpoint, mismatch, transport string
	useWS, multipathV3               bool
	response                         protocol.AuthResponse
}

func (n *connectionNetwork) matches(r protocol.AuthResponse) bool {
	old := n.response
	return old.TunnelIP == r.TunnelIP && old.ServerTunnelIP == r.ServerTunnelIP &&
		old.ServerPublicKey == r.ServerPublicKey && old.UDP == r.UDP && old.WebSocket == r.WebSocket &&
		old.Multipath == r.Multipath &&
		hasTransportCapability(old.TransportCapabilities, protocol.CapabilityMultipathV3) == hasTransportCapability(r.TransportCapabilities, protocol.CapabilityMultipathV3) &&
		hasTransportCapability(old.TransportCapabilities, protocol.CapabilityPathMTUV1) == hasTransportCapability(r.TransportCapabilities, protocol.CapabilityPathMTUV1)
}

// applyReconnectedSession is called with networkMu held. Carrier setup steps
// finish before replacement, and status readers see only a complete generation.
func (c *Connection) applyReconnectedSession(auth authResult) error {
	c.transportMu.Lock()
	defer c.transportMu.Unlock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return fmt.Errorf("connection is closed")
	}
	previous, privateKey := c.network, c.networkKey
	existing := append([]*localTunnel(nil), c.tunnels...)
	forced := ""
	if c.multipath != nil {
		forced = c.multipath.Forced()
	}
	c.mu.Unlock()

	next := previous
	replaced := previous == nil || !previous.matches(auth.response)
	if replaced {
		if privateKey == "" {
			return fmt.Errorf("connection has no WireGuard key for recovery")
		}
		var err error
		next, err = newConnectionNetwork(auth.response, privateKey, c.http, c.options)
		if err != nil {
			return fmt.Errorf("rebuild tunnel: %w", err)
		}
		if next.multipath != nil && forced != "" {
			next.multipath.SetForced(forced)
		}
	}
	byName := make(map[string]*localTunnel, len(existing))
	for _, lt := range existing {
		byName[lt.name] = lt
	}
	var tunnels, opened []*localTunnel
	committed := false
	defer func() {
		if !committed {
			for _, lt := range opened {
				closeLocalTunnel(lt)
			}
			if replaced {
				_ = next.stack.Close()
			}
		}
	}()
	for _, grant := range auth.response.Tunnels {
		lt := byName[grant.Name]
		proto := "tcp"
		if grant.Protocol == "udp" {
			proto = "udp"
		}
		if lt == nil || lt.protocol != proto {
			var err error
			lt, err = c.openReconnectedTunnel(grant, lt)
			if err != nil {
				return err
			}
			opened = append(opened, lt)
		} else {
			delete(byName, grant.Name)
		}
		tunnels = append(tunnels, lt)
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return fmt.Errorf("connection is closed")
	}
	oldStack := c.Stack
	if replaced {
		if c.dataStop != nil {
			close(c.dataStop)
		}
		c.dataStop = make(chan struct{})
		c.Stack, c.hybrid, c.multipath = next.stack, next.hybrid, next.multipath
		c.network, c.serverTunnelIP = next, next.serverIP
		c.lastRelayUDPToken = ""
		c.relayHopStats.Store(nil)
		c.transport.Store(uint32(initialTransportState(next.useWS, auth.response.UDP).connectionTransport()))
	}
	c.tunnels, c.LocalAddresses = tunnels, nil
	for i, lt := range tunnels {
		grant := auth.response.Tunnels[i]
		lt.virtualPort, lt.socks = grant.VirtualPort, protocol.IsBrowserSocksTarget(grant.TargetHint)
		lt.target = net.JoinHostPort(next.serverIP.String(), strconv.Itoa(grant.VirtualPort))
		lt.idleTimeout = grant.UDPIdleTimeout
		c.LocalAddresses = append(c.LocalAddresses, lt.localAddr)
	}
	c.Response, c.token = auth.response, auth.response.Token
	c.method, c.issuer = auth.method, auth.issuer
	c.expiresAt = time.Time{}
	if auth.response.TTLSeconds > 0 {
		c.expiresAt = time.Now().Add(time.Duration(auth.response.TTLSeconds) * time.Second)
	}
	hybrid, stop := c.hybrid, c.dataStop
	c.mu.Unlock()
	committed = true
	if hybrid != nil {
		hybrid.WebSocket.SetHeader(http.Header{"Authorization": {"Bearer " + auth.response.Token}})
	}
	for _, lt := range byName {
		closeLocalTunnel(lt)
	}
	if replaced && oldStack != nil {
		_ = oldStack.Close()
	}
	for _, lt := range opened {
		if lt.protocol == "udp" {
			go c.forwardUDP(lt, lt.packetConn, "", 0)
		} else {
			go c.forward(lt, lt.listener, "")
		}
	}
	if replaced {
		c.startTransportWorkers(next, stop)
	}
	return nil
}

func closeLocalTunnel(lt *localTunnel) {
	if lt.listener != nil {
		_ = lt.listener.Close()
	}
	if lt.packetConn != nil {
		_ = lt.packetConn.Close()
	}
}

func (c *Connection) openReconnectedTunnel(grant protocol.Tunnel, old *localTunnel) (*localTunnel, error) {
	port, explicitPort := c.options.Ports[grant.Name]
	if !explicitPort {
		port = grant.LocalPort
	}
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid local port for tunnel %q", grant.Name)
	}
	host, softHost, _ := resolveTunnelHost(grant.Name, grant.LocalHost, c.options.Hosts, c.options.BindAddress != "", c.bindAddr)
	if old != nil {
		oldHost, oldPort, err := net.SplitHostPort(old.localAddr)
		if err != nil {
			return nil, err
		}
		host, softHost, explicitPort = oldHost, false, true
		port, err = strconv.Atoi(oldPort)
		if err != nil {
			return nil, err
		}
	}
	lt := &localTunnel{name: grant.Name, protocol: "tcp"}
	if grant.Protocol == "udp" {
		pc, _, err := listenLocalUDP(host, port, softHost, !explicitPort)
		if err != nil {
			return nil, err
		}
		lt.protocol, lt.packetConn, lt.localAddr = "udp", pc, pc.LocalAddr().String()
	} else {
		ln, _, err := listenLocal(host, port, softHost, !explicitPort, nil)
		if err != nil {
			return nil, err
		}
		lt.listener, lt.localAddr = ln, ln.Addr().String()
	}
	return lt, nil
}

func (c *Connection) startTransportWorkers(n *connectionNetwork, stop chan struct{}) {
	if n.multipath != nil && shouldBootstrapDirectMultipath(n.multipathV3, n.udpEndpoint, c.options.UseWebSocket) {
		go func() {
			c.transportMu.RLock()
			defer c.transportMu.RUnlock()
			if c.transportGenerationCurrent(stop) {
				c.bootstrapDirectMultipath(n.udpEndpoint)
			}
		}()
	}
	if n.hybrid != nil && n.udpEndpoint == "" && !c.options.NoDirectUpgrade && n.transport != string(wstransport.PathWSS) {
		go c.directUpgradeLoopFor(stop)
	}
}

func (c *Connection) transportGenerationCurrent(stop chan struct{}) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.closed && c.dataStop == stop
}

func (c *Connection) watchForward(stop chan struct{}, in, out net.Conn) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-stop:
		case <-c.stop:
		case <-done:
			return
		}
		_ = in.Close()
		_ = out.Close()
	}()
	return func() { close(done) }
}

func copyClientStream(dst, src net.Conn, counter *atomic.Uint64) {
	_, err := io.Copy(countingWriter{w: dst, counter: counter}, src)
	if err == nil {
		if cw, ok := dst.(interface{ CloseWrite() error }); ok && cw.CloseWrite() == nil {
			return
		}
	}
	_ = dst.Close()
	_ = src.Close()
}

func newConnectionNetwork(r protocol.AuthResponse, privateKey string, h *http.Client, options Options) (*connectionNetwork, error) {
	clientIP, err := netip.ParseAddr(r.TunnelIP)
	if err != nil {
		return nil, fmt.Errorf("server did not return a tunnel IP: %w", err)
	}
	// A direct UDP endpoint of the wrong family is treated as if the server
	// hadn't advertised one at all: selectTransport falls back to WebSocket
	// rather than dialing a family the caller explicitly excluded. mismatch
	// only feeds the transportReason banner below -- the actual UDP data
	// plane (direct or via the WebSocket-fallback's opportunistic upgrade
	// ladder) is restricted to options.IPVersion structurally, via
	// pkg/ipfamily, regardless of this check.
	udpEndpoint, mismatch := r.UDP, ""
	if r.UDP != "" && !matchesIPVersion(r.UDP, options.IPVersion) {
		mismatch = fmt.Sprintf("server's direct UDP endpoint (%s) is not IPv%s", r.UDP, options.IPVersion)
		udpEndpoint = ""
	}
	transport, err := normalizeTransportPreference(options.UseWebSocket, options.Transport)
	if err != nil {
		return nil, err
	}
	// v3 is the complete and sole multipath contract. A server offering only
	// retired v1/v2 identifiers is treated as a legacy single-path peer.
	multipathV3 := r.Multipath && hasTransportCapability(r.TransportCapabilities, protocol.CapabilityMultipathV3)
	pathMTU := multipathV3 && hasTransportCapability(r.TransportCapabilities, protocol.CapabilityPathMTUV1)
	useWS, err := selectTransport(options.UseWebSocket, transport, multipathV3, udpEndpoint, r.WebSocket)
	if err != nil {
		return nil, err
	}
	serverIP, err := resolveServerTunnelIP(r.ServerTunnelIP, clientIP)
	if err != nil {
		return nil, err
	}
	stackConfig := wgnet.Config{PrivateKey: privateKey, Addresses: []netip.Addr{clientIP}, DNSServers: []netip.Addr{serverIP}, IPVersion: options.IPVersion, UDPBufferLogger: options.Logger}
	// hybrid is non-nil only in WebSocket-fallback mode; it is what the
	// opportunistic direct-UDP upgrade (directupgrade.go) uses to
	// self-reflect, prime, and move the peer's endpoint between transports.
	// A direct-UDP session (useWS false) already has the best available
	// path and has nothing to upgrade to.
	var hybrid *wstransport.Hybrid
	var multipath *wstransport.MultipathBind
	if useWS {
		if multipathV3 {
			// V3 deliberately uses sticky carrier/probe health and never samples
			// a standby by mirroring ordinary tunnel payload.
			hybrid, multipath = wstransport.NewMultipathHybridClient(r.WebSocket, h, http.Header{"Authorization": {"Bearer " + r.Token}}, pathMTU, resolveMultipathOptions(options.Multipath), options.IPVersion, options.Logger)
			stackConfig.Bind = multipath
		} else {
			hybrid = wstransport.NewHybridClient(r.WebSocket, h, http.Header{"Authorization": {"Bearer " + r.Token}}, options.IPVersion, options.Logger)
			stackConfig.Bind = hybrid
		}
	}
	st, err := wgnet.New(stackConfig)
	if err != nil {
		if multipath != nil {
			_ = multipath.Close()
		} else if hybrid != nil {
			_ = hybrid.Close()
		}
		return nil, err
	}
	endpoint := r.UDP
	if useWS {
		if multipath != nil {
			endpoint = wstransport.MultipathSentinel
		} else {
			endpoint = wstransport.WSSentinel
		}
	}
	if err = st.AddPeer(wgnet.Endpoint{PublicKey: r.ServerPublicKey, Address: allowedIPsForFamily(clientIP) + "@" + endpoint}); err != nil {
		st.Close()
		return nil, err
	}

	if multipath != nil && transport != "" {
		multipath.SetForced(transport)
	}
	return &connectionNetwork{stack: st, hybrid: hybrid, multipath: multipath, clientIP: clientIP, serverIP: serverIP, udpEndpoint: udpEndpoint, mismatch: mismatch, transport: transport, useWS: useWS, multipathV3: multipathV3, response: r}, nil
}
