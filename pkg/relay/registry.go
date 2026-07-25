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
}

// Agent is a live control connection for one registered tenant name.
type Agent struct {
	Name string
	// Push delivers a RelayOpen over the control connection.
	Push func(protocol.RelayOpen) error
	// Close tears down the control connection. Idempotent.
	Close func()
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
	limits        Limits
}

func NewRegistry(registrations []Registration, limits Limits) *Registry {
	r := &Registry{
		byFingerprint: map[string]Registration{},
		tenants:       map[string]*tenantState{},
		pending:       map[string]*pendingConn{},
		nonces:        map[string]time.Time{},
		limits:        limits,
	}
	for _, reg := range registrations {
		r.byFingerprint[sshkey.Fingerprint(reg.PublicKey)] = reg
		r.tenants[reg.Name] = &tenantState{}
	}
	return r
}

func (r *Registry) useNonceLocked(n string) bool {
	if n == "" {
		return false
	}
	if _, ok := r.nonces[n]; ok {
		return false
	}
	now := time.Now()
	r.nonces[n] = now
	for k, v := range r.nonces {
		if now.Sub(v) > 5*time.Minute {
			delete(r.nonces, k)
		}
	}
	return true
}

// Register verifies a RelayRegisterRequest against the configured
// registrations and returns the authoritative tenant name on success. The
// verification order is: protocol version, timestamp window, nonce replay,
// fingerprint known, signature valid, then the wire-supplied name checked
// against the fingerprint's configured name (never the reverse).
func (r *Registry) Register(req protocol.RelayRegisterRequest) (string, *RegisterError) {
	if req.Version != protocol.Version {
		return "", &RegisterError{Code: protocol.ErrorInvalidRequest, Message: "unsupported protocol version"}
	}
	ts, err := protocol.ParseTimestamp(req.Timestamp)
	if err != nil || time.Since(ts) > 2*time.Minute || time.Until(ts) > 2*time.Minute {
		return "", &RegisterError{Code: protocol.ErrorClockSkew, Message: "timestamp outside permitted window"}
	}
	r.mu.Lock()
	nonceOK := r.useNonceLocked(req.Nonce)
	r.mu.Unlock()
	if !nonceOK {
		return "", &RegisterError{Code: protocol.ErrorReplayedNonce, Message: "replayed nonce"}
	}
	key, _, err := sshkey.ParsePublicString(req.PublicKey)
	if err != nil {
		return "", &RegisterError{Code: protocol.ErrorUnknownKey, Message: "unrecognized public key"}
	}
	fp := sshkey.Fingerprint(key)
	r.mu.Lock()
	reg, known := r.byFingerprint[fp]
	r.mu.Unlock()
	if !known {
		return "", &RegisterError{Code: protocol.ErrorUnknownKey, Message: "unknown public key"}
	}
	payload, err := protocol.RelayRegisterPayload(req)
	if err != nil || sshkey.Verify(reg.PublicKey, payload, req.Signature) != nil {
		return "", &RegisterError{Code: protocol.ErrorBadSignature, Message: "invalid signature"}
	}
	if req.Name != reg.Name {
		return "", &RegisterError{Code: protocol.ErrorRelayNameNotAllowed, Message: "name does not match this key's registration"}
	}
	return reg.Name, nil
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
// reload. A name that disappears from the new set has its live agent (if
// any) evicted immediately, mirroring pkg/server's Reload, which drops
// sessions for a fingerprint no longer in authorized_keys_dir rather than
// waiting for a future touch.
func (r *Registry) ReplaceRegistrations(registrations []Registration) {
	r.mu.Lock()
	byFP := map[string]Registration{}
	names := map[string]bool{}
	for _, reg := range registrations {
		byFP[sshkey.Fingerprint(reg.PublicKey)] = reg
		names[reg.Name] = true
	}
	r.byFingerprint = byFP
	var evicted []*Agent
	for name, t := range r.tenants {
		if !names[name] && t.agent != nil {
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
