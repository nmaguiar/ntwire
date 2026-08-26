package relay

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const defaultUDPBufferBytes = 4 << 20

type udpBufferTuner interface {
	SetReadBuffer(bytes int) error
	SetWriteBuffer(bytes int) error
}

// tuneUDPBuffers asks the kernel for equal read/write capacity. It is
// deliberately best effort: systems commonly clamp socket buffers to an
// administrator-controlled ceiling, and losing a performance optimisation
// must never prevent a relay from starting.
func tuneUDPBuffers(pc net.PacketConn, requested int) error {
	tuner, ok := pc.(udpBufferTuner)
	if !ok {
		return nil
	}
	return tuneUDPBufferTuner(tuner, requested)
}

func tuneUDPBufferTuner(tuner udpBufferTuner, requested int) error {
	if requested <= 0 {
		requested = defaultUDPBufferBytes
	}
	if err := tuner.SetReadBuffer(requested); err != nil {
		return err
	}
	return tuner.SetWriteBuffer(requested)
}

// Relay wires the registry, agents control/data endpoints, and the public
// TLS-passthrough listener into one runnable unit.
type Relay struct {
	cfg      Config
	registry *Registry
	agents   *agentServer
	public   *publicListener
	log      *slog.Logger

	mu          sync.Mutex
	publicLn    net.Listener
	agentsLn    net.Listener
	agentsSrv   *http.Server
	tlsFP       string
	reflectLn   net.PacketConn
	reflectAddr string

	udpRelayLn       net.PacketConn            // shared client-facing socket
	udpRelayPool     map[uint16]net.PacketConn // pooled server-leg sockets, one per listen.udp_relay_ports port
	udpRelayAddr     string
	udpSessions      *udpSessionTable
	udpSweepStop     chan struct{}
	nativeWG         map[string]*nativeWGRelay
	tenantLns        map[string]net.Listener
	kubernetesCancel context.CancelFunc
}

// New constructs a Relay from a loaded Config. It performs no I/O; call
// Start to bind listeners.
func New(cfg Config, log *slog.Logger) (*Relay, error) {
	if log == nil {
		log = slog.Default()
	}
	regs, err := ParseRegistrations(cfg.Registrations)
	if err != nil {
		return nil, err
	}
	limits := Limits{
		HandshakeTimeout:             cfg.Limits.HandshakeTimeout,
		DialBackTimeout:              cfg.Limits.DialBackTimeout,
		MaxPendingPerServer:          cfg.Limits.MaxPendingPerServer,
		MaxConnsPerServer:            cfg.Limits.MaxConnsPerServer,
		UDPRelayIdleTimeout:          cfg.Limits.UDPRelayIdleTimeout,
		MaxUDPRelaySessionsPerServer: cfg.Limits.MaxUDPRelaySessionsPerServer,
	}
	registry := NewRegistry(regs, limits)
	return &Relay{
		cfg:      cfg,
		registry: registry,
		agents:   newAgentServer(registry, cfg.Domain, limits, log),
		public:   newPublicListener(registry, cfg.Domain, limits, cfg.Limits.MaxNewConnsPerMinute, log),
		log:      log,
	}, nil
}

// Start binds listen.public and listen.agents and begins serving in
// background goroutines. It returns once both listeners are bound.
func (r *Relay) Start() error {
	pair, err := loadTLSCertificate(r.cfg)
	if err != nil {
		return fmt.Errorf("relay TLS: %w", err)
	}
	fp := fingerprint(pair)

	var publicLn net.Listener
	var agentsLn net.Listener
	var reflectLn net.PacketConn
	var udpRelayLn net.PacketConn
	var udpRelayPool map[uint16]net.PacketConn
	nativeWG := map[string]*nativeWGRelay{}
	tenantLns := map[string]net.Listener{}

	abortAll := func() {
		if publicLn != nil {
			_ = publicLn.Close()
		}
		if agentsLn != nil {
			_ = agentsLn.Close()
		}
		if reflectLn != nil {
			_ = reflectLn.Close()
		}
		if udpRelayLn != nil {
			_ = udpRelayLn.Close()
		}
		for _, pc := range udpRelayPool {
			_ = pc.Close()
		}
		for _, native := range nativeWG {
			_ = native.conn.Close()
		}
		for _, ln := range tenantLns {
			_ = ln.Close()
		}
	}

	publicLn, err = net.Listen("tcp", r.cfg.Listen.Public)
	if err != nil {
		return fmt.Errorf("listen.public: %w", err)
	}
	agentsLn, err = net.Listen("tcp", r.cfg.Listen.Agents)
	if err != nil {
		abortAll()
		return fmt.Errorf("listen.agents: %w", err)
	}
	tlsAgentsLn := tls.NewListener(agentsLn, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})

	var reflectAddr string
	if r.cfg.Listen.Reflect != "" {
		reflectLn, err = net.ListenPacket("udp", r.cfg.Listen.Reflect)
		if err != nil {
			abortAll()
			return fmt.Errorf("listen.reflect: %w", err)
		}
		if err := tuneUDPBuffers(reflectLn, r.cfg.Listen.UDPBufferBytes); err != nil {
			r.log.Warn("could not tune UDP reflector socket buffers", "error", err)
		}
		reflectAddr = reflectLn.LocalAddr().String()
	}

	var udpRelayAddr string
	if r.cfg.Listen.UDPRelay != "" {
		minPort, maxPort, perr := parsePortRange(r.cfg.Listen.UDPRelayPorts)
		if perr != nil {
			abortAll()
			return fmt.Errorf("listen.udp_relay_ports: %w", perr)
		}
		udpRelayLn, err = net.ListenPacket("udp", r.cfg.Listen.UDPRelay)
		if err != nil {
			abortAll()
			return fmt.Errorf("listen.udp_relay: %w", err)
		}
		if err := tuneUDPBuffers(udpRelayLn, r.cfg.Listen.UDPBufferBytes); err != nil {
			r.log.Warn("could not tune UDP relay socket buffers", "error", err)
		}
		udpRelayAddr = udpRelayLn.LocalAddr().String()
		udpRelayPool = make(map[uint16]net.PacketConn, int(maxPort-minPort)+1)
		for port := minPort; ; port++ {
			poolAddr, perr := udpRelayPoolListenAddr(r.cfg.Listen.UDPRelay, port)
			if perr != nil {
				abortAll()
				return fmt.Errorf("listen.udp_relay_ports: %w", perr)
			}
			pc, perr := net.ListenPacket("udp", poolAddr)
			if perr != nil {
				abortAll()
				return fmt.Errorf("listen.udp_relay_ports: binding port %d: %w", port, perr)
			}
			if err := tuneUDPBuffers(pc, r.cfg.Listen.UDPBufferBytes); err != nil {
				r.log.Warn("could not tune UDP relay pool socket buffers", "port", port, "error", err)
			}
			udpRelayPool[port] = pc
			if port == maxPort {
				break
			}
		}
	}
	for _, reg := range r.cfg.Registrations {
		if reg.NativeWireGuard.Listen == "" {
			continue
		}
		listenAddr, e := resolveNativeWGListenAddr(reg.NativeWireGuard.Listen)
		if e != nil {
			abortAll()
			return fmt.Errorf("registration %q native_wireguard.listen: %w", reg.Name, e)
		}
		pc, e := net.ListenPacket("udp", listenAddr)
		if e != nil {
			abortAll()
			return fmt.Errorf("registration %q native_wireguard.listen: %w", reg.Name, e)
		}
		if err := tuneUDPBuffers(pc, r.cfg.Listen.UDPBufferBytes); err != nil {
			r.log.Warn("could not tune native WireGuard relay socket buffers", "tenant", reg.Name, "error", err)
		}
		advertise, e := nativeWGAdvertiseAddr(reg.Name, r.cfg.Domain, reg.NativeWireGuard.Listen, pc.LocalAddr())
		if e != nil {
			_ = pc.Close()
			abortAll()
			return fmt.Errorf("registration %q native_wireguard.listen: %w", reg.Name, e)
		}
		nativeWG[reg.Name] = newNativeWGRelay(pc, advertise)
	}

	for _, reg := range r.cfg.Registrations {
		if reg.Listen == "" {
			continue
		}
		ln, e := net.Listen("tcp", reg.Listen)
		if e != nil {
			abortAll()
			return fmt.Errorf("registration %q listen: %w", reg.Name, e)
		}
		tenantLns[reg.Name] = ln
	}

	srv := &http.Server{Handler: r.agents.Handler(), ReadHeaderTimeout: 10 * time.Second}

	var udpSessions *udpSessionTable
	var udpSweepStop chan struct{}
	if udpRelayLn != nil {
		alloc := newPortAllocator(udpRelayPool)
		udpSessions = newUDPSessionTable(alloc, Limits{MaxUDPRelaySessionsPerServer: r.cfg.Limits.MaxUDPRelaySessionsPerServer})
		udpSweepStop = make(chan struct{})
	}

	r.mu.Lock()
	r.publicLn, r.agentsLn, r.agentsSrv, r.tlsFP = publicLn, agentsLn, srv, fp
	r.reflectLn, r.reflectAddr = reflectLn, reflectAddr
	r.udpRelayLn, r.udpRelayPool, r.udpRelayAddr, r.udpSessions, r.udpSweepStop, r.nativeWG, r.tenantLns = udpRelayLn, udpRelayPool, udpRelayAddr, udpSessions, udpSweepStop, nativeWG, tenantLns
	r.mu.Unlock()
	r.agents.setReflectAddr(reflectAddr)
	r.agents.setUDPRelayAddr(udpRelayAddr)
	r.agents.setUDPSessions(udpSessions)
	r.agents.setNative(nativeWG)
	if r.cfg.Kubernetes.Enabled {
		ctx, cancel := context.WithCancel(context.Background())
		if _, err := startInClusterKubernetesDiscovery(ctx, r.cfg.Kubernetes, r.registry, r.log); err != nil {
			cancel()
			abortAll()
			return err
		}
		r.mu.Lock()
		r.kubernetesCancel = cancel
		r.mu.Unlock()
		r.log.Info("Kubernetes Service discovery enabled", "namespace_mode", r.cfg.Kubernetes.Namespaces.Mode, "service_selector", r.cfg.Kubernetes.Service.Selector)
	}

	go r.public.serve(publicLn)
	go func() {
		if err := srv.Serve(tlsAgentsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			r.log.Error("relay agents listener stopped", "error", err)
		}
	}()
	if reflectLn != nil {
		go newReflector(reflectLn, r.cfg.Limits.MaxNewConnsPerMinute, r.log).serve()
		r.log.Info("ntwire-relay UDP reflector listening", "reflect", reflectAddr)
	} else {
		r.log.Debug("ntwire-relay UDP reflector disabled; direct-UDP upgrade unavailable to relayed servers")
	}
	if udpRelayLn != nil {
		dr := newDatagramRelay(udpSessions, udpRelayLn, r.cfg.Limits.MaxNewConnsPerMinute, r.log)
		go udpSessions.runIdleSweep(udpSweepStop, r.cfg.Limits.UDPRelayIdleTimeout)
		go dr.serveClientLeg()
		for port, pc := range udpRelayPool {
			go dr.serveServerLeg(pc, port)
		}
		r.log.Info("ntwire-relay UDP-relay tier listening", "udp_relay", udpRelayAddr, "port_pool", r.cfg.Listen.UDPRelayPorts, "pool_size", len(udpRelayPool))
	} else {
		r.log.Debug("ntwire-relay UDP-relay tier disabled; relayed servers only offer WebSocket and (if enabled) direct-UDP upgrade")
	}
	for name, native := range nativeWG {
		go native.serve()
		r.log.Info("ntwire-relay native WireGuard listener", "tenant", name, "address", native.conn.LocalAddr())
	}
	for name, ln := range tenantLns {
		go r.public.serveTenant(ln, name)
		r.log.Info("ntwire-relay tenant public TCP listener", "tenant", name, "address", ln.Addr())
	}
	r.log.Info("ntwire-relay listening", "public", r.cfg.Listen.Public, "agents", r.cfg.Listen.Agents, "domain", r.cfg.Domain, "tls_fingerprint", fp)
	return nil
}

// resolveNativeWGListenAddr turns an explicit DNS host into the concrete
// address/interface to bind. Wildcard binds stay wildcards; they are handled
// separately when deriving the address advertised to the server.
func resolveNativeWGListenAddr(addr string) (string, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	if host == "" || net.ParseIP(host) != nil {
		return addr, nil
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return "", fmt.Errorf("resolve host %q: %w", host, err)
	}
	return udpAddr.String(), nil
}

// nativeWGAdvertiseAddr returns an address the remote ntwire-server can send
// its association frame to. LocalAddr is intentionally not used for wildcard
// listeners: it is 0.0.0.0/[::], neither of which is a relay destination.
func nativeWGAdvertiseAddr(tenant, domain, configured string, bound net.Addr) (string, error) {
	host, _, err := net.SplitHostPort(configured)
	if err != nil {
		return "", err
	}
	_, port, err := net.SplitHostPort(bound.String())
	if err != nil {
		return "", fmt.Errorf("bound UDP address %q: %w", bound, err)
	}
	ip := net.ParseIP(host)
	if host == "" || (ip != nil && ip.IsUnspecified()) {
		return net.JoinHostPort(tenant+"."+domain, port), nil
	}
	return bound.String(), nil
}

// udpRelayPoolListenAddr returns the server-leg address for a pooled relay
// port. It must retain listen.udp_relay's host: the allocated address is sent
// to the relayed server, which uses it as a real UDP destination. Binding a
// pool port to ":<port>" and advertising LocalAddr instead leaks an
// unspecified address (0.0.0.0 or [::]) to that server.
func udpRelayPoolListenAddr(udpRelay string, port uint16) (string, error) {
	host, _, err := net.SplitHostPort(udpRelay)
	if err != nil {
		return "", fmt.Errorf("parse listen.udp_relay %q: %w", udpRelay, err)
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// PublicAddr returns the bound address of listen.public, useful for tests
// and operator logging when the configured address uses an ephemeral port.
func (r *Relay) PublicAddr() net.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.publicLn == nil {
		return nil
	}
	return r.publicLn.Addr()
}

// TenantAddr returns the bound address of a tenant's dedicated TCP listener
// (registrations[].listen), or nil if it is not configured.
func (r *Relay) TenantAddr(tenant string) net.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ln, ok := r.tenantLns[tenant]; ok {
		return ln.Addr()
	}
	return nil
}

// AgentsAddr returns the bound address of listen.agents.
func (r *Relay) AgentsAddr() net.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.agentsLn == nil {
		return nil
	}
	return r.agentsLn.Addr()
}

// ReflectAddr returns the bound address of listen.reflect, or "" if it is
// not configured.
func (r *Relay) ReflectAddr() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reflectAddr
}

// UDPRelayAddr returns the bound address of the UDP-relay tier's shared
// client-facing socket (listen.udp_relay), or "" if it is not configured.
func (r *Relay) UDPRelayAddr() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.udpRelayAddr
}

// Fingerprint returns the relay's own listen.agents TLS certificate
// fingerprint. This is never pinned by an ntwire client (clients always pin
// the origin server's certificate through the blind splice); it is exposed
// purely for operator troubleshooting.
func (r *Relay) Fingerprint() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tlsFP
}

// ReloadRegistrations replaces the configured tenant name/key set. See
// Registry.ReplaceRegistrations for eviction semantics.
func (r *Relay) ReloadRegistrations(cfgs []RegistrationConfig) error {
	regs, err := ParseRegistrations(cfgs)
	if err != nil {
		return err
	}
	r.registry.ReplaceRegistrations(regs)
	return nil
}

// Close shuts down both listeners. Already-spliced public<->data-conn
// connections are not forcibly torn down; they end when either side closes.
func (r *Relay) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.kubernetesCancel != nil {
		r.kubernetesCancel()
		r.kubernetesCancel = nil
	}
	if r.publicLn != nil {
		_ = r.publicLn.Close()
	}
	for _, ln := range r.tenantLns {
		_ = ln.Close()
	}
	if r.agentsSrv != nil {
		_ = r.agentsSrv.Close()
	}
	if r.reflectLn != nil {
		_ = r.reflectLn.Close()
	}
	if r.udpSweepStop != nil {
		close(r.udpSweepStop)
	}
	if r.udpRelayLn != nil {
		_ = r.udpRelayLn.Close()
	}
	for _, pc := range r.udpRelayPool {
		_ = pc.Close()
	}
	for _, native := range r.nativeWG {
		_ = native.conn.Close()
	}
	return nil
}
