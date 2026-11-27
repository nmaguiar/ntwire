package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/internal/egressattach"
	"github.com/nmaguiar/ntwire/pkg/egressrouter"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/relay"
	"github.com/nmaguiar/ntwire/pkg/server"
	"github.com/nmaguiar/ntwire/pkg/socks"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"golang.org/x/net/proxy"
)

func startEgressServer(f *reconnectFixture, transport string, deny, two bool) {
	startEgressServerWithFaults(f, transport, deny, two, nil)
}

func startEgressServerWithFaults(f *reconnectFixture, transport string, deny, two bool, fault *udpFault, configure ...func(*server.Config)) {
	f.t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		f.t.Fatal(err)
	}
	address := pc.LocalAddr().String()
	_ = pc.Close()
	cfg := server.Config{}
	cfg.Auth.AuthorizedKeysDir, cfg.Auth.SessionTTL = f.keysDir, time.Hour
	cfg.Network.TunnelCIDR = "100.70.20.0/24"
	cfg.Listen.WireGuard = address
	if transport == "direct-udp" {
		cfg.Network.AdvertisedEndpoint = address
		if fault != nil {
			cfg.Network.AdvertisedEndpoint = fault.forward(f.t, address)
		}
	}
	multipath := transport == "udp-relay"
	cfg.Transport.Multipath = &multipath
	cfg.Relay.Enabled = transport == "udp-relay"
	if multipath {
		cfg.Transport.Force = "udp-relay"
	}
	grant := func(name string, port int) server.TunnelConfig {
		return server.TunnelConfig{Name: name, Target: "socks", VirtualPort: port, Allow: []string{"*"},
			Socks: &server.SocksConfig{AllowAll: !deny, AllowLocalEgress: !deny}}
	}
	cfg.Tunnels = []server.TunnelConfig{grant("internet", 10080)}
	if two {
		upstream := startTestSOCKS5Server(f.t, "", "")
		f.t.Cleanup(upstream.Close)
		secondary := grant("secondary", 10081)
		secondary.Socks = &server.SocksConfig{Transparent: true, Upstream: "socks5h://" + upstream.Addr()}
		cfg.Tunnels = append(cfg.Tunnels, secondary)
	}
	for _, apply := range configure {
		apply(&cfg)
	}
	s := server.New(cfg, slog.New(slog.DiscardHandler))
	if err = s.StartDataPlane(); err != nil {
		f.t.Fatal(err)
	}
	f.current.Store(s)
	f.t.Cleanup(s.Close)
	if transport == "udp-relay" {
		attachTestUDPRelay(f, s)
	}
}

func TestSmartProxyTwoServers(t *testing.T) {
	for _, name := range []string{"direct-udp", "wss", "udp-relay"} {
		t.Run(name, func(t *testing.T) {
			a, b := newReconnectFixture(t), newReconnectFixture(t)
			startEgressServer(a, name, true, false)
			startEgressServer(b, name, false, true)
			ca, cb := connectEgress(a, name), connectEgress(b, name)
			if name == "udp-relay" {
				testUDPRelayBaseline(t, cb, b.tcpTarget)
				testEgressInternalDial(t, cb, b.tcpTarget)
			}
			root := filepath.Join(t.TempDir(), "egress")
			for id, c := range map[string]*Connection{"a": ca, "b": cb} {
				path, _ := egressattach.ProfilePath(root, id)
				publisher, err := egressattach.Start(path, c.EgressCandidate, nil)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(publisher.Close)
			}
			members := []egressrouter.Member{
				{ProfileID: "a", Tunnel: "internet", ExpectedServer: a.http.URL, Priority: 100},
				{ProfileID: "b", Tunnel: "internet", ExpectedServer: b.http.URL, Priority: 90},
				{ProfileID: "b", Tunnel: "secondary", ExpectedServer: b.http.URL, Priority: 80},
			}
			registry := egressattach.NewRegistry(root)
			discovery, stop := context.WithTimeout(t.Context(), 20*time.Second)
			defer stop()
			for {
				registry.Refresh(discovery, members)
				all := true
				for _, member := range members {
					if c := registry.Candidate(member); c.Dialer == nil {
						all = false
						if discovery.Err() != nil {
							t.Fatalf("missing %v: %+v", member, c)
						}
						break
					}
				}
				if all {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := listener.Addr().String()
			listener.Close()
			router := egressrouter.New(registry.Candidate)
			defer router.Close()
			if err = router.Apply(egressrouter.Config{Enabled: true, Listen: addr,
				Egress:   egressrouter.Membership{Selection: "priority", Members: members},
				Failover: egressrouter.Failover{AttemptTimeout: 8 * time.Second, TotalTimeout: 10 * time.Second},
			}, nil); err != nil {
				t.Fatal(err)
			}
			dial := func() (net.Conn, error) {
				ctx, cancel := context.WithTimeout(t.Context(), 11*time.Second)
				defer cancel()
				c, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
				if err != nil {
					return nil, err
				}
				if err = socks.Connect(ctx, c, a.tcpTarget); err != nil {
					_ = c.Close()
					return nil, err
				}
				return c, nil
			}
			c, err := dial()
			if c != nil {
				c.Close()
			}
			var denial *socks.ConnectError
			if !errors.As(err, &denial) || denial.Code != 2 {
				t.Fatalf("expected an explicit policy denial, got %v (status %+v)", err, router.Status())
			}
			if router.Status().Failovers != 0 {
				t.Fatal("denial triggered a retry")
			}
			ca.Close()
			// Leave the old registry snapshot in place. The publishing process
			// discovers loss of authority at attempt time, before sending CONNECT.
			conn, err := dial()
			if err != nil {
				t.Fatalf("backup dial: %v, router=%+v carrier=%+v", err, router.Status(), cb.TransportInfo())
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err = io.WriteString(conn, "through backup"); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len("through backup"))
			if _, err = io.ReadFull(conn, got); err != nil || string(got) != "through backup" {
				t.Fatalf("reply %q, %v", got, err)
			}
			if router.Status().Recovered != 1 || router.Status().Listening != addr {
				t.Fatalf("unexpected status %+v", router.Status())
			}
			member := members[1]
			old := cb.EgressCandidate(member)
			if err = cb.renew(); err != nil {
				t.Fatal(err)
			}
			if fresh := cb.EgressCandidate(member); fresh.Generation != old.Generation {
				t.Fatal("equivalent renewal invalidated the grant")
			}
			owner := b.current.Load()
			narrowed := owner.Config
			narrowed.Tunnels = narrowed.Tunnels[1:]
			owner.Reload(narrowed)
			if err = cb.renew(); err != nil {
				if err = cb.reconnect(); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			_, err = old.Dialer.DialDestination(ctx, egressrouter.Destination{Host: "example.invalid", Port: 443})
			var failure *egressrouter.Failure
			if !errors.As(err, &failure) || failure.Class != "grant_revoked" {
				t.Fatalf("stale grant returned %v", err)
			}
			if _, err = conn.Read(got); err == nil {
				t.Fatal("revoked flow stayed open")
			}
			updated, stopUpdate := context.WithTimeout(t.Context(), 20*time.Second)
			defer stopUpdate()
			for {
				registry.Refresh(updated, members)
				if registry.Candidate(members[2]).Dialer != nil && registry.Candidate(members[1]).Dialer == nil {
					break
				}
				if updated.Err() != nil {
					t.Fatal("publisher did not reflect the revoked grant")
				}
				time.Sleep(20 * time.Millisecond)
			}
			newConn, err := dial()
			if err != nil {
				t.Fatalf("transparent sibling did not accept a new connection: %v", err)
			}
			defer newConn.Close()
			if selected := router.Status().Selected; selected == nil || *selected != members[2].ID() {
				t.Fatalf("selected %+v instead of the remaining SOCKS grant", selected)
			}
		})
	}
}

func startClientTestUDPRelay(f *reconnectFixture, configure ...func(*relay.Config)) (*relay.Relay, func() error) {
	f.t.Helper()
	pub, err := os.ReadFile(f.key + ".pub")
	if err != nil {
		f.t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		f.t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	cfg := relay.Config{Domain: "relay.test", Registrations: []relay.RegistrationConfig{{Name: "home", PublicKey: string(pub)}}}
	cfg.Listen.Public, cfg.Listen.Agents = "127.0.0.1:0", "127.0.0.1:0"
	cfg.Listen.UDPRelay = "127.0.0.1:0"
	cfg.Listen.UDPRelayPorts = fmt.Sprintf("%d-%d", port, port)
	cfg.TLS.Ephemeral = true
	cfg.Limits.HandshakeTimeout = 5 * time.Second
	cfg.Limits.DialBackTimeout = 3 * time.Second
	cfg.Limits.MaxPendingPerServer = 32
	cfg.Limits.MaxConnsPerServer = 256
	cfg.Limits.MaxNewConnsPerMinute = 1000
	cfg.Limits.MaxUDPRelaySessionsPerServer = 4
	cfg.Limits.UDPRelayIdleTimeout = time.Minute
	for _, apply := range configure {
		apply(&cfg)
	}
	rl, err := relay.New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		f.t.Fatal(err)
	}
	if err = rl.Start(); err != nil {
		f.t.Fatal(err)
	}
	stop := sync.OnceValue(rl.Close)
	f.t.Cleanup(func() { _ = stop() })
	return rl, stop
}

func attachTestUDPRelay(f *reconnectFixture, s *server.Server) {
	f.t.Helper()
	rl, _ := startClientTestUDPRelay(f)
	agent, err := server.NewRelayAgent(server.RelayConfig{Enabled: true, URL: "wss://" + rl.AgentsAddr().String(),
		Name: "home", IdentityFile: f.key, Fingerprint: rl.Fingerprint()}, slog.New(slog.DiscardHandler))
	if err != nil {
		f.t.Fatal(err)
	}
	registered := make(chan struct{}, 1)
	agent.OnRegistration = func(response protocol.RelayRegisterResponse) {
		s.EnableUDPRelay(agent, response.UDPRelayAddr)
		select {
		case registered <- struct{}{}:
		default:
		}
	}
	ctx, cancel := context.WithCancel(f.t.Context())
	f.t.Cleanup(func() { cancel(); agent.Close() })
	go agent.Run(ctx)
	select {
	case <-registered:
	case <-time.After(5 * time.Second):
		f.t.Fatal("UDP relay did not register")
	}
}

func connectEgress(f *reconnectFixture, transport string) *Connection {
	f.t.Helper()
	if transport != "udp-relay" {
		return f.connect()
	}
	client, err := ConnectWithOptions(f.http.URL, f.key, protocol.ClientInfo{}, Options{
		NoWebUI: true, NoBrowser: true, NoSystemProxy: true, Transport: "udp-relay",
		DirectUpgradeTiming: &DirectUpgradeTiming{RetryInterval: time.Second, ProbeTimeout: 8 * time.Second},
		StatusFile:          filepath.Join(f.dir, "status.json"), Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(client.Close)
	// Establish the initial WireGuard handshake over WSS before the
	// relay upgrade. This avoids conflating cold peer establishment with
	// an egress setup deadline.
	ctx, cancel := context.WithTimeout(f.t.Context(), 8*time.Second)
	defer cancel()
	grant := client.EgressCandidate(egressrouter.Member{Tunnel: "internet", ExpectedServer: f.http.URL})
	if grant.Dialer == nil {
		f.t.Fatal("missing baseline SOCKS grant")
	}
	host, portText, _ := net.SplitHostPort(f.tcpTarget)
	port, _ := strconv.ParseUint(portText, 10, 16)
	probe, err := grant.Dialer.DialDestination(ctx, egressrouter.Destination{Host: host, Port: uint16(port)})
	if err != nil {
		var failure *egressrouter.Failure
		if !errors.As(err, &failure) || failure.Code != 2 {
			f.t.Fatalf("WSS baseline dial failed before relay upgrade: %v", err)
		}
	} else {
		probe.Close()
	}
	deadline := time.Now().Add(35 * time.Second)
	for time.Now().Before(deadline) {
		if client.State().Transport.Mode == TransportUDPRelay {
			return client
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.t.Fatalf("client did not switch to udp-relay: %+v", client.State().Transport)
	return nil
}

func testUDPRelayBaseline(t testing.TB, c *Connection, target string) {
	t.Helper()
	addr := c.State().Tunnels[0].LocalAddress
	dialer, err := proxy.SOCKS5("tcp", addr, nil, &net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	conn, err := dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatalf("UDP relay individual SOCKS baseline failed: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = io.WriteString(conn, "baseline"); err != nil {
		t.Fatal(err)
	}
	var echo [8]byte
	if _, err = io.ReadFull(conn, echo[:]); err != nil || string(echo[:]) != "baseline" {
		t.Fatalf("UDP relay baseline echo %q: %v", echo, err)
	}
	if got := c.State().Transport.Mode; got != TransportUDPRelay {
		t.Fatalf("UDP relay baseline used %s", got)
	}
}

func testEgressInternalDial(t testing.TB, c *Connection, target string) {
	t.Helper()
	grant, err := c.SOCKSEgress("internet")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	host, portText, _ := net.SplitHostPort(target)
	port, _ := strconv.ParseUint(portText, 10, 16)
	conn, err := grant.DialDestination(ctx, egressrouter.Destination{Host: host, Port: uint16(port)})
	if err != nil {
		var failure *egressrouter.Failure
		if errors.As(err, &failure) {
			t.Fatalf("internal egress dial failed: %+v stage=%s", failure, failure.Stage)
		}
		t.Fatal(err)
	}
	conn.Close()
}

// udpFault is a loopback UDP hop for carrier impairment tests. It never
// changes host routes or requires elevated networking privileges.
type udpFault struct {
	delay     time.Duration
	blackhole atomic.Bool
	dropped   atomic.Uint64
}

func (f *udpFault) forward(t testing.TB, serverAddr string) string {
	t.Helper()
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		socket.Close()
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var client net.Addr
		packet := make([]byte, 65535)
		for {
			n, from, err := socket.ReadFrom(packet)
			if err != nil {
				return
			}
			if f.blackhole.Load() {
				f.dropped.Add(1)
				continue
			}
			target := net.Addr(server)
			if from.String() == serverAddr {
				target = client
			} else {
				client = from
			}
			if target != nil {
				time.Sleep(f.delay)
				_, _ = socket.WriteTo(packet[:n], target)
			}
		}
	}()
	t.Cleanup(func() { _ = socket.Close(); <-done })
	return socket.LocalAddr().String()
}

func TestSmartProxyFailoverWithDatagramLoss(t *testing.T) {
	a, b := newReconnectFixture(t), newReconnectFixture(t)
	fault := &udpFault{delay: 2 * time.Millisecond}
	startEgressServerWithFaults(a, "direct-udp", false, false, fault)
	startEgressServer(b, "direct-udp", false, false)
	ca, cb := a.connect(), b.connect()
	// Warm the WireGuard paths before starting the failure deadline.
	testEgressInternalDial(t, ca, a.tcpTarget)
	testEgressInternalDial(t, cb, b.tcpTarget)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	members := []egressrouter.Member{
		{ProfileID: "a", Tunnel: "internet", ExpectedServer: a.http.URL, Priority: 100},
		{ProfileID: "b", Tunnel: "internet", ExpectedServer: b.http.URL, Priority: 90},
	}
	router := egressrouter.New(func(m egressrouter.Member) egressrouter.Candidate {
		if m.ProfileID == "a" {
			return ca.EgressCandidate(m)
		}
		return cb.EgressCandidate(m)
	})
	defer router.Close()
	if err := router.Apply(egressrouter.Config{
		Enabled: true, Listen: addr, Egress: egressrouter.Membership{Selection: "priority", Members: members},
		Failover: egressrouter.Failover{AttemptTimeout: time.Second, TotalTimeout: 5 * time.Second},
	}, nil); err != nil {
		t.Fatal(err)
	}
	// Drop the preferred carrier's UDP traffic without disconnecting its
	// authenticated session. Failover must use the existing listener.
	fault.blackhole.Store(true)
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = socks.Connect(ctx, conn, b.tcpTarget); err != nil {
		t.Fatal(err)
	}
	status := router.Status()
	if status.Listening != addr || status.Recovered != 1 || status.Selected == nil ||
		*status.Selected != members[1].ID() || fault.dropped.Load() == 0 {
		t.Fatalf("unexpected failover result %+v (dropped datagrams %d)", status, fault.dropped.Load())
	}
}

func TestSmartProxyGrantLifetime(t *testing.T) {
	c := &Connection{
		Stack:          &wgnet.Stack{},
		serverTunnelIP: netip.MustParseAddr("100.64.0.1"),
		expiresAt:      time.Now().Add(time.Minute),
		Response: protocol.AuthResponse{Tunnels: []protocol.Tunnel{
			{Name: "internet", VirtualPort: 1080, TargetHint: "socks"},
		}},
	}
	grant, err := c.SOCKSEgress("internet")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.closed = true
		c.reconcileEgressLocked()
	})
	c.mu.Lock()
	c.expiresAt = time.Now().Add(2 * time.Minute)
	c.reconcileEgressLocked()
	c.mu.Unlock()
	renewed, err := c.SOCKSEgress("internet")
	if err != nil || renewed != grant {
		t.Fatalf("equivalent renewal changed the grant: %v", err)
	}
	c.mu.Lock()
	c.expiresAt = time.Now().Add(-time.Second)
	c.reconcileEgressLocked()
	c.mu.Unlock()
	select {
	case <-grant.(*egressGrant).lifetime.Done():
	default:
		t.Fatal("expired generation still live")
	}
	if _, err = c.SOCKSEgress("internet"); err == nil {
		t.Fatal("expired session still admits dials")
	}
}
