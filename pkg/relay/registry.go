package relay

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
	"golang.org/x/crypto/ssh"
)

// Registration is one relay.yaml registrations[] entry, resolved to a parsed
// public key at load time.
type Registration struct {
	Name      string
	PublicKey ssh.PublicKey
	Listen    string
}

// Limits bounds resource usage per tenant; DialBackTimeout doubles as the
// conn_id TTL, since both describe the same window: how long the relay waits
// for a server to redeem a minted capability before giving up.
// HandshakeTimeout is used only by the public listener (see public.go), not
// the Registry itself, but lives here so callers construct one Limits value.
type Limits struct {
	HandshakeTimeout    time.Duration
	DialBackTimeout     time.Duration
	MaxPendingPerServer int
	MaxConnsPerServer   int
	// UDPRelayIdleTimeout and MaxUDPRelaySessionsPerServer belong to the
	// UDP-relay forwarding tier (see udpsession.go); they are not used by
	// Registry itself, but live here so callers construct one Limits value,
	// matching HandshakeTimeout's existing precedent of living here despite
	// only the public listener using it.
	UDPRelayIdleTimeout          time.Duration
	MaxUDPRelaySessionsPerServer int
}

// Agent is a live control connection for one registered tenant name.
type Agent struct {
	Name string
	// Fingerprint is the registering key's fingerprint, recorded so a
	// config reload can evict this agent if its name's registration has
	// since been rebound to a different key (see ReplaceRegistrations).
	Fingerprint string
	// Push delivers a RelayOpen over the control connection.
	Push func(protocol.RelayOpen) error
	// Close tears down the control connection. Idempotent.
	Close func()
}

// RegistrationSource identifies how a route entered the relay. Static routes
// authorize outbound agents; Kubernetes routes are direct Service endpoints.
type RegistrationSource string

const (
	SourceStatic     RegistrationSource = "static"
	SourceOutbound   RegistrationSource = "outbound"
	SourceKubernetes RegistrationSource = "kubernetes"
)

// ServerEndpoint is a non-secret routing target. Kubernetes endpoints use
// Service DNS, never pod IPs.
type ServerEndpoint struct {
	Hostname  string
	Address   string
	Namespace string
	Service   string
	Tenant    string
	Source    RegistrationSource
	ID        string // stable source identity, e.g. Service UID
}

// RegisterError is a machine-readable registration failure, mirroring the
// shape of protocol.Error used by the client-facing /v1/auth endpoint.
type RegisterError struct {
	Code    string
	Message string
}

func (e *RegisterError) Error() string { return e.Message }

type tenantState struct {
	agent   *Agent
	pending int
	live    int
}

type pendingConn struct {
	name    string
	ch      chan net.Conn
	done    chan struct{} // closed by Open if it abandons before Redeem delivers
	expires time.Time
}

// Handoff is what Redeem hands the agents listener: the channel to deliver
// the freshly dialed-back connection on, and a signal that the original
// Open has already given up (timed out or had its context canceled) and
// will never read from Deliver again.
type Handoff struct {
	Deliver chan<- net.Conn
	Done    <-chan struct{}
}

// Registry tracks configured tenant registrations, their live control
// connections, per-tenant connection accounting, and in-flight conn_id
// capabilities. It is the single synchronization point between the agents
// listener (registration, RelayOpen push, data-conn redemption) and the
// public listener (minting conn_ids and awaiting their redemption).
type Registry struct {
	mu            sync.Mutex
	byFingerprint map[string]Registration
	tenants       map[string]*tenantState
	pending       map[string]*pendingConn
	nonces        map[string]time.Time
	kubernetes    map[string]ServerEndpoint
	conflicts     map[string]map[string]ServerEndpoint
	limits        Limits
}

func NewRegistry(registrations []Registration, limits Limits) *Registry {
	r := &Registry{
		byFingerprint: map[string]Registration{},
		tenants:       map[string]*tenantState{},
		pending:       map[string]*pendingConn{},
		nonces:        map[string]time.Time{},
		kubernetes:    map[string]ServerEndpoint{},
		conflicts:     map[string]map[string]ServerEndpoint{},
		limits:        limits,
	}
	for _, reg := range registrations {
		r.byFingerprint[sshkey.Fingerprint(reg.PublicKey)] = reg
		r.tenants[reg.Name] = &tenantState{}
	}
	return r
}

// UpsertKubernetes adds or updates a Service endpoint. Multiple distinct
// Services claiming one hostname deliberately make that hostname unavailable
// until the conflict is resolved; routing never makes an arbitrary choice.
func (r *Registry) UpsertKubernetes(ep ServerEndpoint) error {
	if ep.Source != SourceKubernetes || ep.Hostname == "" || ep.Address == "" || ep.ID == "" {
		return fmt.Errorf("invalid Kubernetes endpoint")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.kubernetes[ep.Hostname]; ok && old.ID != ep.ID {
		if r.conflicts[ep.Hostname] == nil {
			r.conflicts[ep.Hostname] = map[string]ServerEndpoint{old.ID: old}
		}
		r.conflicts[ep.Hostname][ep.ID] = ep
		delete(r.kubernetes, ep.Hostname)
		return fmt.Errorf("duplicate Kubernetes hostname %q", ep.Hostname)
	}
	if c := r.conflicts[ep.Hostname]; c != nil {
		c[ep.ID] = ep
		return fmt.Errorf("duplicate Kubernetes hostname %q", ep.Hostname)
	}
	r.kubernetes[ep.Hostname] = ep
	return nil
}

// RemoveKubernetes removes only the source object that created an endpoint.
func (r *Registry) RemoveKubernetes(hostname, id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ep, ok := r.kubernetes[hostname]; ok && ep.ID == id {
		delete(r.kubernetes, hostname)
	}
	if c := r.conflicts[hostname]; c != nil {
		delete(c, id)
		if len(c) == 1 {
			for _, ep := range c {
				r.kubernetes[hostname] = ep
			}
			delete(r.conflicts, hostname)
		} else if len(c) == 0 {
			delete(r.conflicts, hostname)
		}
	}
}

func (r *Registry) Lookup(hostname string) (ServerEndpoint, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ep, ok := r.kubernetes[hostname]
	return ep, ok
}

func (r *Registry) List() []ServerEndpoint {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]ServerEndpoint, 0, len(r.kubernetes))
	for _, ep := range r.kubernetes {
		out = append(out, ep)
	}
	return out
}

// maxNonces backstops useNonceLocked's normal 5-minute expiry: it bounds
// memory if an authenticated peer (the only kind that can reach this point
// post-reorder, see Register) registers with an unusual number of distinct
// nonces within one window.
const maxNonces = 4096

// useNonceLocked records n as seen, evicting expired entries and -- if still
// over maxNonces afterward -- the single oldest surviving entry as a
// backstop.
func (r *Registry) useNonceLocked(n string) bool {
	if n == "" {
		return false
	}
	if _, ok := r.nonces[n]; ok {
		return false
	}
	now := time.Now()
	r.nonces[n] = now
	var oldestKey string
	var oldestTime time.Time
	haveOldest := false
	for k, v := range r.nonces {
		if now.Sub(v) > 5*time.Minute {
			delete(r.nonces, k)
			continue
		}
		if !haveOldest || v.Before(oldestTime) {
			oldestKey, oldestTime, haveOldest = k, v, true
		}
	}
	if len(r.nonces) > maxNonces && haveOldest {
		delete(r.nonces, oldestKey)
	}
	return true
}

// Register verifies a RelayRegisterRequest against the configured
// registrations and returns the authoritative tenant name and the
// registering key's fingerprint on success. The verification order is:
// protocol version, timestamp window, fingerprint known, signature valid,
// nonce replay, then the wire-supplied name checked against the
// fingerprint's configured name (never the reverse). Nonce replay is
// checked only after the signature verifies, not before: consuming a nonce
// slot for an unauthenticated request would let anyone who can merely reach
// listen.agents exhaust the (5-minute, size-capped) nonce cache without
// ever presenting a valid key.
func (r *Registry) Register(req protocol.RelayRegisterRequest) (name, fingerprint string, regErr *RegisterError) {
	if req.Version != protocol.Version {
		return "", "", &RegisterError{Code: protocol.ErrorInvalidRequest, Message: "unsupported protocol version"}
	}
	if err := protocol.ValidateRequiredCapabilities(relayCapabilities(), req.RequiredCapabilities); err != nil {
		return "", "", &RegisterError{Code: protocol.ErrorUnsupportedCapability, Message: err.Error()}
	}
	ts, err := protocol.ParseTimestamp(req.Timestamp)
	if err != nil || time.Since(ts) > 2*time.Minute || time.Until(ts) > 2*time.Minute {
		return "", "", &RegisterError{Code: protocol.ErrorClockSkew, Message: "timestamp outside permitted window"}
	}
	key, _, err := sshkey.ParsePublicString(req.PublicKey)
	if err != nil {
		return "", "", &RegisterError{Code: protocol.ErrorUnknownKey, Message: "unrecognized public key"}
	}
	fp := sshkey.Fingerprint(key)
	r.mu.Lock()
	reg, known := r.byFingerprint[fp]
	r.mu.Unlock()
	if !known {
		return "", "", &RegisterError{Code: protocol.ErrorUnknownKey, Message: "unknown public key"}
	}
	payload, err := protocol.RelayRegisterPayload(req)
	if err != nil || sshkey.Verify(reg.PublicKey, payload, req.Signature) != nil {
		return "", "", &RegisterError{Code: protocol.ErrorBadSignature, Message: "invalid signature"}
	}
	r.mu.Lock()
	nonceOK := r.useNonceLocked(req.Nonce)
	r.mu.Unlock()
	if !nonceOK {
		return "", "", &RegisterError{Code: protocol.ErrorReplayedNonce, Message: "replayed nonce"}
	}
	if req.Name != reg.Name {
		return "", "", &RegisterError{Code: protocol.ErrorRelayNameNotAllowed, Message: "name does not match this key's registration"}
	}
	return reg.Name, fp, nil
}

// relayCapabilities lists optional features implemented by the relay control
// protocol. Unknown optional server offers are ignored; only an explicit
// RequiredCapabilities request reaches the failure path above.
func relayCapabilities() []string {
	return []string{protocol.CapabilityMultipathV3, protocol.CapabilityNativeWireGuardRelay}
}

// RegisterAgent binds agent as the live control connection for name,
// evicting and closing any prior agent for that name (last-writer-wins).
// This is both how a duplicate claim is rejected and how a server
// reconnecting after a drop replaces its own stale connection.
func (r *Registry) RegisterAgent(name string, agent *Agent) {
	r.mu.Lock()
	t := r.tenants[name]
	if t == nil {
		t = &tenantState{}
		r.tenants[name] = t
	}
	old := t.agent
	t.agent = agent
	r.mu.Unlock()
	if old != nil {
		old.Close()
	}
}

// DeregisterAgent clears the live agent for name, but only if agent is still
// the current one (a natural disconnect must not clobber a newer
// registration that already replaced it).
func (r *Registry) DeregisterAgent(name string, agent *Agent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t := r.tenants[name]; t != nil && t.agent == agent {
		t.agent = nil
	}
}

var (
	// ErrTenantUnknown covers both an unregistered name and a registered but
	// currently offline one; the two are deliberately indistinguishable to a
	// public-listener caller (see docs/SECURITY.md on tenant enumeration).
	ErrTenantUnknown    = fmt.Errorf("unknown or offline tenant")
	ErrTenantAtCapacity = fmt.Errorf("tenant connection capacity exceeded")
)

// Open mints a single-use conn_id for name, pushes a RelayOpen over its live
// control connection, and blocks until either the server redeems it with a
// data connection, the dial-back timeout elapses, or ctx is canceled. The
// returned net.Conn is already accounted as one of the tenant's live
// connections; call Release when it is done to free that slot.
func (r *Registry) Open(ctx context.Context, name, clientAddr, sni string) (net.Conn, error) {
	r.mu.Lock()
	t := r.tenants[name]
	if t == nil || t.agent == nil {
		r.mu.Unlock()
		return nil, ErrTenantUnknown
	}
	if t.pending >= r.limits.MaxPendingPerServer || t.pending+t.live >= r.limits.MaxConnsPerServer {
		r.mu.Unlock()
		return nil, ErrTenantAtCapacity
	}
	connID, err := randomConnID()
	if err != nil {
		r.mu.Unlock()
		return nil, err
	}
	ch := make(chan net.Conn, 1)
	done := make(chan struct{})
	r.pending[connID] = &pendingConn{name: name, ch: ch, done: done, expires: time.Now().Add(r.limits.DialBackTimeout)}
	t.pending++
	agent := t.agent
	r.mu.Unlock()

	if err := agent.Push(protocol.RelayOpen{ConnID: connID, ClientAddr: clientAddr, SNI: sni}); err != nil {
		r.cancelPending(connID)
		return nil, fmt.Errorf("pushing relay open: %w", err)
	}

	timer := time.NewTimer(r.limits.DialBackTimeout)
	defer timer.Stop()
	select {
	case conn := <-ch:
		// Redeem already decremented pending for this conn_id; only account
		// the new live connection here.
		r.mu.Lock()
		if ts := r.tenants[name]; ts != nil {
			ts.live++
		}
		r.mu.Unlock()
		return conn, nil
	case <-timer.C:
		r.cancelPending(connID)
		drainPending(ch)
		close(done)
		return nil, fmt.Errorf("dial-back timed out")
	case <-ctx.Done():
		r.cancelPending(connID)
		drainPending(ch)
		close(done)
		return nil, ctx.Err()
	}
}

// OpenSNI applies source precedence: an authenticated outbound registration
// for the configured tenant wins, then an unambiguous discovered Service,
// then the legacy static/outbound lookup. A Kubernetes Service is dialed only
// after SNI has been validated by the caller.
func (r *Registry) OpenSNI(ctx context.Context, tenant, hostname, clientAddr, sni string) (net.Conn, string, error) {
	r.mu.Lock()
	active := tenant != "" && r.tenants[tenant] != nil && r.tenants[tenant].agent != nil
	ep, found := r.kubernetes[hostname]
	r.mu.Unlock()
	if active {
		c, err := r.Open(ctx, tenant, clientAddr, sni)
		return c, tenant, err
	}
	if found {
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", ep.Address)
		if err != nil {
			return nil, ep.Hostname, fmt.Errorf("dial Kubernetes service %s/%s: %w", ep.Namespace, ep.Service, err)
		}
		return c, ep.Hostname, nil
	}
	if tenant == "" {
		return nil, "", ErrTenantUnknown
	}
	c, err := r.Open(ctx, tenant, clientAddr, sni)
	return c, tenant, err
}

func drainPending(ch chan net.Conn) {
	select {
	case c := <-ch:
		_ = c.Close()
	default:
	}
}

// Release accounts for a previously Open-ed connection ending, freeing its
// live slot against the tenant's max_conns_per_server cap.
func (r *Registry) Release(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t := r.tenants[name]; t != nil {
		t.live--
	}
}

func (r *Registry) cancelPending(connID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.pending[connID]
	if !ok {
		return
	}
	delete(r.pending, connID)
	if t := r.tenants[p.name]; t != nil {
		t.pending--
	}
}

// ReplaceRegistrations swaps the configured name/key set for a config
// reload. A live agent is evicted immediately if its name disappears from
// the new set, or if its name is rebound to a different key -- mirroring
// pkg/server's Reload, which drops sessions for a fingerprint no longer
// authorized rather than waiting for a future touch. Evicting by name alone
// would leave a compromised server's control connection live indefinitely
// across a key rotation that kept the same name, since it never
// re-registers on its own.
func (r *Registry) ReplaceRegistrations(registrations []Registration) {
	r.mu.Lock()
	byFP := map[string]Registration{}
	fpByName := map[string]string{}
	for _, reg := range registrations {
		fp := sshkey.Fingerprint(reg.PublicKey)
		byFP[fp] = reg
		fpByName[reg.Name] = fp
	}
	r.byFingerprint = byFP
	var evicted []*Agent
	for name, t := range r.tenants {
		if t.agent == nil {
			continue
		}
		newFP, stillRegistered := fpByName[name]
		if !stillRegistered || newFP != t.agent.Fingerprint {
			evicted = append(evicted, t.agent)
			t.agent = nil
		}
	}
	r.mu.Unlock()
	for _, a := range evicted {
		a.Close()
	}
}

// Redeem consumes a single-use conn_id, returning a Handoff carrying the
// channel to deliver the freshly dialed-back data connection to and a
// signal for whether the original Open has already given up. It fails for
// an unknown, already redeemed, or expired conn_id.
func (r *Registry) Redeem(connID string) (Handoff, bool) {
	r.mu.Lock()
	p, exists := r.pending[connID]
	if exists {
		delete(r.pending, connID)
		if t := r.tenants[p.name]; t != nil {
			t.pending--
		}
	}
	r.mu.Unlock()
	if !exists || time.Now().After(p.expires) {
		return Handoff{}, false
	}
	return Handoff{Deliver: p.ch, Done: p.done}, true
}

func randomConnID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
