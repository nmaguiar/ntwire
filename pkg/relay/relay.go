package relay

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// Relay wires the registry, agents control/data endpoints, and the public
// TLS-passthrough listener into one runnable unit.
type Relay struct {
	cfg      Config
	registry *Registry
	agents   *agentServer
	public   *publicListener
	log      *slog.Logger

	mu        sync.Mutex
	publicLn  net.Listener
	agentsLn  net.Listener
	agentsSrv *http.Server
	tlsFP     string
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
		HandshakeTimeout:    cfg.Limits.HandshakeTimeout,
		DialBackTimeout:     cfg.Limits.DialBackTimeout,
		MaxPendingPerServer: cfg.Limits.MaxPendingPerServer,
		MaxConnsPerServer:   cfg.Limits.MaxConnsPerServer,
	}
	registry := NewRegistry(regs, limits)
	return &Relay{
		cfg:      cfg,
		registry: registry,
		agents:   newAgentServer(registry, cfg.Domain),
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

	publicLn, err := net.Listen("tcp", r.cfg.Listen.Public)
	if err != nil {
		return fmt.Errorf("listen.public: %w", err)
	}
	agentsLn, err := net.Listen("tcp", r.cfg.Listen.Agents)
	if err != nil {
		_ = publicLn.Close()
		return fmt.Errorf("listen.agents: %w", err)
	}
	tlsAgentsLn := tls.NewListener(agentsLn, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})

	srv := &http.Server{Handler: r.agents.Handler(), ReadHeaderTimeout: 10 * time.Second}

	r.mu.Lock()
	r.publicLn, r.agentsLn, r.agentsSrv, r.tlsFP = publicLn, agentsLn, srv, fp
	r.mu.Unlock()

	go r.public.serve(publicLn)
	go func() {
		if err := srv.Serve(tlsAgentsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			r.log.Error("relay agents listener stopped", "error", err)
		}
	}()
	r.log.Info("ntwire-relay listening", "public", r.cfg.Listen.Public, "agents", r.cfg.Listen.Agents, "domain", r.cfg.Domain, "tls_fingerprint", fp)
	return nil
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

// AgentsAddr returns the bound address of listen.agents.
func (r *Relay) AgentsAddr() net.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.agentsLn == nil {
		return nil
	}
	return r.agentsLn.Addr()
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
	if r.publicLn != nil {
		_ = r.publicLn.Close()
	}
	if r.agentsSrv != nil {
		_ = r.agentsSrv.Close()
	}
	return nil
}
