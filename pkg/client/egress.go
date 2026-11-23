package client

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nmaguiar/ntwire/internal/localproxy"
	"github.com/nmaguiar/ntwire/pkg/egressrouter"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/socks"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
)

var egressSequence atomic.Uint64

type egressGrant struct {
	class        string
	udp          bool
	owner        *Connection
	name, target string
	stack        *wgnet.Stack
	generation   string
	lifetime     context.Context
	invalidate   context.CancelFunc
}

func (c *Connection) egressTargetLocked(name string) string {
	for _, g := range c.Response.Tunnels {
		if g.Name == name && protocol.IsBrowserSocksTarget(g.TargetHint) &&
			(g.Protocol == "" || g.Protocol == "tcp") && g.VirtualPort > 0 && g.VirtualPort <= 65535 && c.serverTunnelIP.IsValid() {
			return net.JoinHostPort(c.serverTunnelIP.String(), strconv.Itoa(g.VirtualPort))
		}
	}
	return ""
}

func (c *Connection) egressAvailableLocked() bool {
	return !c.closed && c.Stack != nil && !c.egressDenied && !c.expiresAt.IsZero() && time.Now().Before(c.expiresAt)
}

// reconcileEgressLocked runs whenever effective session authority changes.
func (c *Connection) reconcileEgressLocked() {
	if c.egressTimer != nil {
		c.egressTimer.Stop()
	}
	for name, g := range c.egressGrants {
		if !c.egressAvailableLocked() || g.stack != c.Stack || g.target != c.egressTargetLocked(name) || g.class != c.egressClassLocked(name) || g.udp != c.egressUDPLocked(name) {
			g.invalidate()
			delete(c.egressGrants, name)
		}
	}
	if len(c.egressGrants) > 0 {
		c.egressTimer = time.AfterFunc(time.Until(c.expiresAt), func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.reconcileEgressLocked()
		})
	}
}

// SOCKSEgress returns a dialer bound to a current TCP SOCKS grant.
func (c *Connection) SOCKSEgress(name string) (egressrouter.Egress, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	grant, err := c.socksEgressLocked(name)
	if err != nil {
		return nil, err
	}
	return grant, nil
}
func (c *Connection) socksEgressLocked(name string) (*egressGrant, error) {
	if c.egressDenied {
		return nil, &egressrouter.Failure{Class: "authorization", Code: 2}
	}
	if c.closed || c.Stack == nil || c.reconnectState.Reconnecting {
		return nil, &egressrouter.Failure{Class: "transport", Retry: true}
	}
	if !c.egressAvailableLocked() {
		return nil, &egressrouter.Failure{Class: "expired", Retry: true}
	}
	target := c.egressTargetLocked(name)
	if target == "" {
		return nil, &egressrouter.Failure{Class: "grant_unavailable", Code: 2}
	}
	if g := c.egressGrants[name]; g != nil {
		return g, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	g := &egressGrant{class: c.egressClassLocked(name), udp: c.egressUDPLocked(name), owner: c, name: name, target: target, stack: c.Stack,
		generation: strconv.FormatUint(egressSequence.Add(1), 10), lifetime: ctx, invalidate: cancel}
	if c.egressGrants == nil {
		c.egressGrants = map[string]*egressGrant{}
	}
	c.egressGrants[name] = g
	c.reconcileEgressLocked()
	return g, nil
}

// EgressCandidate reports sanitized router metadata for one approved member.
func (c *Connection) EgressCandidate(member egressrouter.Member) egressrouter.Candidate {
	want, err := NormalizeServerURL(member.ExpectedServer)
	if err != nil || want != c.base {
		return egressrouter.Candidate{Reason: "server_identity_changed"}
	}
	c.mu.Lock()
	grant, err := c.socksEgressLocked(member.Tunnel)
	c.mu.Unlock()
	if err == nil && member.EgressClass != "" && (!c.canDiscoverEgress() || grant.class != member.EgressClass) {
		return egressrouter.Candidate{Reason: "egress_class_changed"}
	}
	if err != nil {
		var f *egressrouter.Failure
		errors.As(err, &f)
		return egressrouter.Candidate{Reason: f.Class}
	}
	state := c.State()
	candidate := egressrouter.Candidate{UDP: grant.udp, Preparation: true, Dialer: grant, Generation: grant.generation, Transport: string(state.Transport.Mode),
		ControlMillis: state.LatencyMillis, Reconnections: state.Reconnections}
	for _, p := range state.Transport.Paths {
		if p.Primary || string(p.Kind) == string(state.Transport.Mode) {
			candidate.RTT, candidate.Loss = p.RTT, p.Loss
			break
		}
	}
	for _, t := range state.Tunnels {
		if t.Name == member.Tunnel {
			candidate.LocalAddress = t.LocalAddress
			break
		}
	}
	req, err := http.NewRequest(http.MethodGet, c.base, nil)
	if err == nil {
		if c.options.HTTPSProxy != "" {
			if p, e := http.NewRequest(http.MethodGet, c.options.HTTPSProxy, nil); e == nil {
				candidate.ControlProxy = p.URL.Host
			}
		} else if !c.options.NoSystemProxy {
			if u, _ := http.ProxyFromEnvironment(req); u != nil {
				candidate.ControlProxy = u.Host
			}
		}
	}
	return candidate
}

func (g *egressGrant) valid() error {
	c := g.owner
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.Stack == nil {
		return &egressrouter.Failure{Class: "transport", Retry: true}
	}
	if c.egressDenied {
		return &egressrouter.Failure{Class: "authorization", Code: 2}
	}
	if !c.egressAvailableLocked() {
		return &egressrouter.Failure{Class: "expired", Retry: true}
	}
	if c.egressGrants[g.name] != g || g.target != c.egressTargetLocked(g.name) || g.class != c.egressClassLocked(g.name) || g.udp != c.egressUDPLocked(g.name) {
		return &egressrouter.Failure{Class: "grant_revoked", Code: 2}
	}
	if c.reconnectState.Reconnecting {
		return &egressrouter.Failure{Class: "transport", Retry: true}
	}
	return nil
}

func (g *egressGrant) DialDestination(ctx context.Context, dst egressrouter.Destination) (net.Conn, error) {
	prepared, err := g.Prepare(ctx)
	if err != nil {
		return nil, err
	}
	defer prepared.Close()
	return prepared.DialDestination(ctx, dst)
}

// Prepare opens only the virtual TCP service. No SOCKS request or destination
// is sent until the router commits to this candidate.
func (g *egressGrant) Prepare(ctx context.Context) (egressrouter.PreparedEgress, error) {
	if err := g.valid(); err != nil {
		return nil, err
	}
	setup, cancel := context.WithCancel(ctx)
	defer cancel()
	stopSetup := context.AfterFunc(g.lifetime, cancel)
	defer stopSetup()
	started := time.Now()
	conn, err := g.stack.DialContext(setup, "tcp", g.target)
	if err != nil {
		if invalid := g.valid(); invalid != nil {
			return nil, invalid
		}
		if isEgressTimeout(setup, err) {
			return nil, &egressrouter.Failure{Class: "timeout", Stage: "virtual_service", Code: 6, Retry: true}
		}
		return nil, &egressrouter.Failure{Class: "transport", Stage: "virtual_service", Retry: true}
	}
	stop := context.AfterFunc(g.lifetime, func() { _ = conn.Close() })
	return &preparedGrant{grant: g, conn: &grantConn{Conn: conn, stop: stop, timing: egressrouter.SetupTiming{Service: time.Since(started)}}}, nil
}

type preparedGrant struct {
	grant *egressGrant
	conn  *grantConn
}

func (p *preparedGrant) Close() error {
	if p.conn != nil {
		return p.conn.Close()
	}
	return nil
}
func (p *preparedGrant) DialDestination(ctx context.Context, dst egressrouter.Destination) (net.Conn, error) {
	g := p.grant
	if p.conn == nil {
		return nil, net.ErrClosed
	}
	address, err := dst.Address()
	if err != nil {
		return nil, &egressrouter.Failure{Class: "invalid_destination"}
	}
	if err = g.valid(); err != nil {
		return nil, err
	}
	setup, cancel := context.WithCancel(ctx)
	defer cancel()
	stopSetup := context.AfterFunc(g.lifetime, cancel)
	defer stopSetup()
	started := time.Now()
	if err = socks.Connect(setup, p.conn, address); err != nil {
		var reply *socks.ConnectError
		if errors.As(err, &reply) {
			if reply.Auth {
				return nil, &egressrouter.Failure{Class: "upstream_authentication"}
			}
			if reply.Code != 0 {
				class := "ambiguous"
				switch reply.Code {
				case 2:
					class = "policy_denied"
				case 3:
					class = "network_unreachable"
				case 4:
					class = "host_unreachable_or_dns"
				case 5:
					class = "destination_refused"
				case 6:
					class = "destination_timeout"
				}
				return nil, &egressrouter.Failure{Class: class, Stage: "socks_connect", Code: reply.Code}
			}
			if invalid := g.valid(); invalid != nil && !reply.Submitted {
				return nil, invalid
			}
			if isEgressTimeout(setup, err) {
				stage := "socks_greeting"
				if reply.Submitted {
					stage = "socks_connect"
				}
				return nil, &egressrouter.Failure{Class: "timeout", Stage: stage, Code: 6, Retry: !reply.Submitted}
			}
			if reply.Retryable {
				return nil, &egressrouter.Failure{Class: "transport", Retry: true}
			}
		}
		return nil, &egressrouter.Failure{Class: "ambiguous"}
	}
	if err = g.valid(); err != nil {
		var f *egressrouter.Failure
		if errors.As(err, &f) {
			return nil, &egressrouter.Failure{Class: f.Class, Code: f.Code}
		}
		return nil, err
	}
	conn := p.conn
	conn.timing.SOCKS = time.Since(started)
	p.conn = nil
	return conn, nil
}

func isEgressTimeout(ctx context.Context, err error) bool {
	var ne net.Error
	return errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout()
}

type grantConn struct {
	timing egressrouter.SetupTiming
	net.Conn
	once sync.Once
	stop func() bool
}

func (c *grantConn) Close() error      { c.once.Do(func() { c.stop() }); return c.Conn.Close() }
func (c *grantConn) CloseWrite() error { return localproxy.CloseWrite(c.Conn) }

func (c *grantConn) SetupTiming() egressrouter.SetupTiming { return c.timing }

// AssociateUDP opens a SOCKS UDP association inside the current WireGuard peer.
// The bound relay must be on this peer's virtual IP.
func (g *egressGrant) AssociateUDP(ctx context.Context) (net.Conn, error) {
	if !g.udp {
		return nil, &egressrouter.Failure{Class: "udp_unsupported", Code: 7, Retry: true}
	}
	if err := g.valid(); err != nil {
		return nil, err
	}
	setup, cancel := context.WithCancel(ctx)
	defer cancel()
	stopSetup := context.AfterFunc(g.lifetime, cancel)
	defer stopSetup()
	control, err := g.stack.DialContext(setup, "tcp", g.target)
	if err != nil {
		if invalid := g.valid(); invalid != nil {
			return nil, invalid
		}
		if isEgressTimeout(setup, err) {
			return nil, &egressrouter.Failure{Class: "timeout", Stage: "virtual_service", Code: 6, Retry: true}
		}
		return nil, &egressrouter.Failure{Class: "transport", Stage: "virtual_service", Retry: true}
	}
	stopControl := context.AfterFunc(g.lifetime, func() { _ = control.Close() })
	committed := false
	defer func() {
		if !committed {
			stopControl()
			_ = control.Close()
		}
	}()
	relay, err := socks.Associate(setup, control)
	if err != nil {
		var reply *socks.ConnectError
		if errors.As(err, &reply) {
			if reply.Code != 0 {
				class := "udp_associate_failed"
				if reply.Code == 2 {
					class = "policy_denied"
				}
				return nil, &egressrouter.Failure{Class: class, Stage: "udp_associate", Code: reply.Code, Retry: reply.Code == 7}
			}
			if isEgressTimeout(setup, err) {
				return nil, &egressrouter.Failure{Class: "timeout", Stage: "udp_associate", Code: 6, Retry: !reply.Submitted}
			}
		}
		return nil, &egressrouter.Failure{Class: "ambiguous", Stage: "udp_associate"}
	}
	virtual, err := netip.ParseAddrPort(g.target)
	if err != nil || (relay.Addr() != virtual.Addr().Unmap() && !relay.Addr().IsUnspecified()) {
		return nil, &egressrouter.Failure{Class: "invalid_udp_relay", Stage: "udp_associate"}
	}
	target := netip.AddrPortFrom(virtual.Addr().Unmap(), relay.Port())
	udp, err := g.stack.DialContext(setup, "udp", target.String())
	if err != nil {
		return nil, &egressrouter.Failure{Class: "udp_associate_failed"}
	}
	if err = g.valid(); err != nil {
		_ = udp.Close()
		return nil, &egressrouter.Failure{Class: "authorization", Code: 2, Stage: "udp_associate"}
	}
	association := &udpAssociation{Conn: udp, control: control, stop: stopControl}
	go func() {
		_, _ = io.Copy(io.Discard, control)
		_ = association.Close()
	}()
	committed = true
	return association, nil
}

type udpAssociation struct {
	net.Conn
	control net.Conn
	stop    func() bool
	once    sync.Once
}

func (c *udpAssociation) Close() error {
	c.once.Do(func() { c.stop(); _ = c.control.Close(); _ = c.Conn.Close() })
	return nil
}

func (c *Connection) egressClassLocked(name string) string {
	for _, t := range c.Response.Tunnels {
		if t.Name == name {
			return t.EgressClass
		}
	}
	return ""
}

func (c *Connection) egressUDPLocked(name string) bool {
	for _, t := range c.Response.Tunnels {
		if t.Name == name {
			return t.EgressUDP
		}
	}
	return false
}

func (c *Connection) canDiscoverEgress() bool {
	return strings.HasPrefix(c.base, "https://") && !c.options.Insecure
}

// DiscoverEgress returns grants carrying the operator-approved class from
// the current verified HTTPS session. Older servers advertise no class.
func (c *Connection) DiscoverEgress(enrollment egressrouter.Enrollment) []string {
	expected, err := NormalizeServerURL(enrollment.ExpectedServer)
	if err != nil || expected != c.base || !c.canDiscoverEgress() || !protocol.ValidEgressClass(enrollment.EgressClass) {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.egressAvailableLocked() || c.reconnectState.Reconnecting {
		return nil
	}
	var names []string
	for _, t := range c.Response.Tunnels {
		if len(names) >= 64 {
			break
		}
		if t.EgressClass == enrollment.EgressClass && protocol.IsBrowserSocksTarget(t.TargetHint) &&
			(t.Protocol == "" || t.Protocol == "tcp") && t.VirtualPort > 0 && t.VirtualPort <= 65535 {
			names = append(names, t.Name)
		}
	}
	return names
}
