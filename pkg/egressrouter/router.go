package egressrouter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nmaguiar/ntwire/internal/localproxy"
	"github.com/nmaguiar/ntwire/pkg/socks"
)

type Destination struct {
	Host string
	Port uint16
}

func (d Destination) Address() (string, error) { return socks.Address(d.Host, d.Port) }
func destination(address string) (Destination, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return Destination{}, err
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return Destination{}, err
	}
	d := Destination{host, uint16(n)}
	_, err = d.Address()
	return d, err
}

type Egress interface {
	DialDestination(context.Context, Destination) (net.Conn, error)
}

// SetupTiming is optional timing reported by a supported egress backend.
type SetupTiming struct {
	Service time.Duration `json:"service"`
	SOCKS   time.Duration `json:"socks"`
}
type TimedConn interface{ SetupTiming() SetupTiming }

type Failure struct {
	Class string `json:"class"`
	Stage string `json:"stage,omitempty"`
	Code  byte   `json:"code,omitempty"`
	Retry bool   `json:"retry,omitempty"`
}

func (f *Failure) Error() string { return "smart proxy: " + f.Class }

type Candidate struct {
	Preparation   bool          `json:"preparation,omitempty"`
	UDP           bool          `json:"udp_associate,omitempty"`
	Dialer        Egress        `json:"-"`
	Generation    string        `json:"generation,omitempty"`
	Reason        string        `json:"reason,omitempty"`
	Transport     string        `json:"transport,omitempty"`
	RTT           time.Duration `json:"carrier_rtt,omitempty"`
	Loss          float64       `json:"carrier_loss,omitempty"`
	ControlMillis uint64        `json:"control_latency_millis,omitempty"`
	Reconnections uint64        `json:"reconnections,omitempty"`
	LocalAddress  string        `json:"local_address,omitempty"`
	ControlProxy  string        `json:"-"`
}
type Source func(Member) Candidate

type Router struct {
	probing  bool
	source   Source
	selector Selector
	discover Discover
	now      func() time.Time
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	// apply serializes configuration and listener replacements.
	apply         sync.Mutex
	mu            sync.Mutex
	state         *routeState
	listener      net.Listener
	preferred     MemberID
	lastSelection MemberID
	lastReason    string
	excluded      map[MemberID]bool
	inbound       sync.Map
	lastActive    atomic.Int64
	active        atomic.Int64
	attempts      atomic.Int64
	failovers     atomic.Uint64
	recovered     atomic.Uint64
	raceAttempts  atomic.Uint64
	raceBackups   atomic.Uint64
}

type routeState struct {
	probeCtx     context.Context
	cancelProbes context.CancelFunc
	config       Config
	health       map[MemberID]*memberHealth
	affinity     map[string]affinity
	sequence     uint64
	destinations map[observationKey]destinationObservation
}

func New(source Source) *Router { return NewWithSelector(source, nil) }

// NewWithSelector supplies a ranking strategy for the approved candidate set.
func NewWithSelector(source Source, selector Selector) *Router {
	ctx, cancel := context.WithCancel(context.Background())
	return &Router{source: source, selector: selector, ctx: ctx, cancel: cancel, now: time.Now, excluded: map[MemberID]bool{}}
}

// Apply prepares the listener and commits only after save succeeds.
func (r *Router) Apply(config Config, save func(Config) error) error {
	cfg, err := config.Normalized()
	if err != nil {
		return err
	}
	r.apply.Lock()
	defer r.apply.Unlock()
	if r.ctx.Err() != nil {
		return net.ErrClosed
	}
	if len(cfg.Groups) > 0 || cfg.PACListen != "" {
		return errors.New("named proxy groups and PAC require a GroupSet")
	}
	next, err := r.prepare(cfg)
	if err != nil {
		return err
	}
	if save != nil {
		if err = save(cfg); err != nil {
			r.discardPrepared(next)
			return err
		}
	}
	r.commit(cfg, next)
	return nil
}

// prepare, discardPrepared, and commit run while the caller owns the router.
func (r *Router) prepare(cfg Config) (net.Listener, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if r.listener != nil && r.listener.Addr().String() == cfg.Listen {
		return r.listener, nil
	}
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("smart proxy bind %s: %w", cfg.Listen, err)
	}
	return listener, nil
}
func (r *Router) discardPrepared(next net.Listener) {
	if next != nil && next != r.listener {
		_ = next.Close()
	}
}
func (r *Router) commit(cfg Config, next net.Listener) {
	old := r.listener
	r.mu.Lock()
	previous := r.state
	probeCtx, cancelProbes := context.WithCancel(r.ctx)
	r.state = &routeState{probeCtx: probeCtx, cancelProbes: cancelProbes, config: cfg, health: map[MemberID]*memberHealth{}, affinity: map[string]affinity{}}
	if previous != nil {
		previous.cancelProbes()
		for _, member := range cfg.Egress.Members {
			if slices.Contains(previous.config.Egress.Members, member) {
				if h := previous.health[member.ID()]; h != nil {
					r.state.health[member.ID()] = h
				}
			}
		}
	}
	r.preferred = MemberID{}
	r.lastSelection = MemberID{}
	r.lastReason = ""
	clear(r.excluded)
	r.listener = next
	if !cfg.Enabled {
		r.inbound.Range(func(_, cancel any) bool { cancel.(context.CancelFunc)(); return true })
	}
	r.mu.Unlock()
	if old != nil && old != next {
		_ = old.Close()
	}
	if next != nil && old != next {
		r.wg.Go(func() { r.serve(next) })
	}
	if cfg.Enabled && !r.probing {
		r.probing = true
		r.wg.Go(r.probeLoop)
	}
}

func (r *Router) Close() {
	r.apply.Lock()
	r.cancel()
	if r.listener != nil {
		_ = r.listener.Close()
	}
	r.mu.Lock()
	r.listener = nil
	r.state = nil
	r.mu.Unlock()
	r.apply.Unlock()
	r.wg.Wait()
}

func (r *Router) SetPreference(id MemberID, exclude *bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state == nil {
		return errors.New("smart proxy is unavailable")
	}
	if id != (MemberID{}) &&
		!slices.ContainsFunc(r.state.config.Egress.Members, func(m Member) bool { return m.ID() == id }) &&
		!slices.ContainsFunc(r.state.config.Egress.Enroll, func(e Enrollment) bool { return e.ProfileID == id.ProfileID }) {
		return errors.New("unknown smart proxy member")
	}
	if exclude == nil {
		r.preferred = id
	} else if id != (MemberID{}) {
		if *exclude {
			r.excluded[id] = true
		} else {
			delete(r.excluded, id)
		}
	}
	return nil
}

func claim(counter *atomic.Int64, max int) bool {
	if counter.Add(1) <= int64(max) {
		return true
	}
	counter.Add(-1)
	return false
}

func (r *Router) serve(listener net.Listener) {
	for {
		in, err := listener.Accept()
		if err != nil {
			return
		}
		r.mu.Lock()
		state := r.state
		if state == nil || r.listener != listener || !claim(&r.active, state.config.Limits.Connections) {
			r.mu.Unlock()
			_ = in.Close()
			continue
		}
		// Each accepted socket attaches to a single lifetime. Address changes drain
		// existing sockets, while disable cancels them through their state generation.
		ctx, cancel := context.WithCancel(r.ctx)
		r.inbound.Store(in, cancel)
		r.mu.Unlock()
		r.wg.Go(func() {
			defer r.active.Add(-1)
			defer r.inbound.Delete(in)
			defer cancel()
			defer in.Close()
			stop := context.AfterFunc(ctx, func() { _ = in.Close() })
			defer stop()
			r.lastActive.Store(r.now().UnixNano())
			var httpHandler, socksHandler func(net.Conn)
			if slices.Contains(state.config.Protocols, "http") {
				httpHandler = func(c net.Conn) {
					httpDial := func(ctx context.Context, network, address string) (net.Conn, error) {
						r.mu.Lock()
						allowed := r.state != nil && slices.Contains(r.state.config.Protocols, "http")
						r.mu.Unlock()
						if !allowed {
							return nil, &Failure{Class: "unavailable"}
						}
						return r.dial(ctx, network, address)
					}
					pool := localproxy.NewHTTPPool(httpDial, r.poolAllowed)
					defer pool.Close()
					localproxy.ServeHTTP(ctx, c, httpDial, pool, httpError)
				}
			}
			if slices.Contains(state.config.Protocols, "socks5") {
				socksHandler = func(c net.Conn) { r.serveSOCKS(ctx, c) }
			}
			localproxy.Dispatch(in, httpHandler, socksHandler)
		})
	}
}

func (r *Router) serveSOCKS(ctx context.Context, in net.Conn) {
	_ = in.SetDeadline(r.now().Add(localproxy.HeaderTimeout))
	r.mu.Lock()
	allowUDP := r.state != nil && r.state.config.Routing.UDPAssociate
	r.mu.Unlock()
	req, err := socks.ReadClientRequest(in, in, allowUDP)
	if err != nil {
		return
	}
	_ = in.SetDeadline(time.Time{})
	if req.UDP {
		r.serveUDP(ctx, in, req.Source)
		return
	}
	setup, cancel := context.WithCancel(ctx)
	stopWatch := localproxy.WatchSetupDisconnect(in, cancel)
	out, err := r.dial(setup, "tcp", req.Address)
	stopWatch()
	canceled := setup.Err() != nil
	cancel()
	if canceled {
		if out != nil {
			_ = out.Close()
		}
		return
	}
	if err != nil {
		socks.Reply(in, socksCode(err))
		return
	}
	defer out.Close()
	stop := context.AfterFunc(ctx, func() { _ = out.Close() })
	defer stop()
	socks.Reply(in, 0)
	localproxy.Relay(out, in)
}

func socksCode(err error) byte {
	var f *Failure
	if errors.As(err, &f) && f.Code != 0 {
		return f.Code
	}
	return 1
}
func httpError(w http.ResponseWriter, err error) {
	status := http.StatusBadGateway
	var f *Failure
	if errors.As(err, &f) {
		switch {
		case f.Code == 2 || f.Class == "authorization":
			status = http.StatusForbidden
		case f.Code == 6:
			status = http.StatusGatewayTimeout
		case f.Class == "unavailable" || f.Class == "capacity":
			status = http.StatusServiceUnavailable
		case f.Class == "invalid_destination":
			status = http.StatusBadRequest
		}
	}
	http.Error(w, http.StatusText(status), status)
}

type routedConn struct {
	destination Destination
	net.Conn
	member     Member
	generation string
	health     *memberHealth
	once       sync.Once
}

func (c *routedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.health.received.Add(uint64(n))
	return n, err
}
func (c *routedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.health.sent.Add(uint64(n))
	return n, err
}
func (c *routedConn) CloseWrite() error { return localproxy.CloseWrite(c.Conn) }
func (c *routedConn) Close() error {
	c.once.Do(func() { c.health.active.Add(-1) })
	return c.Conn.Close()
}

func (r *Router) poolAllowed(conn net.Conn) bool {
	r.lastActive.Store(r.now().UnixNano())
	c, ok := conn.(*routedConn)
	if !ok {
		return false
	}
	r.mu.Lock()
	state := r.state
	allowed := state != nil && state.config.Enabled && slices.Contains(state.config.Protocols, "http") && !r.excluded[c.member.ID()] &&
		(r.preferred == (MemberID{}) || r.preferred == c.member.ID()) && state.config.approves(c.member) && state.config.Routing.permits(c.destination, c.member.ID())
	r.mu.Unlock()
	if !allowed {
		return false
	}
	fresh := r.candidate(state, c.member)
	return fresh.Dialer != nil && fresh.Generation == c.generation
}

func (r *Router) dial(ctx context.Context, _ string, address string) (net.Conn, error) {
	r.lastActive.Store(r.now().UnixNano())
	dst, err := destination(address)
	if err != nil {
		return nil, &Failure{Class: "invalid_destination"}
	}
	r.mu.Lock()
	state := r.state
	r.mu.Unlock()
	if state == nil || !state.config.Enabled {
		return nil, &Failure{Class: "unavailable"}
	}
	if _, allow := state.config.Routing.destinationMembers(dst); !allow {
		return nil, &Failure{Class: "local_destination_denied", Code: 2}
	}
	ctx, cancel := context.WithTimeout(ctx, state.config.Failover.TotalTimeout)
	defer cancel()
	if !claim(&r.attempts, state.config.Limits.ConcurrentAttempts) {
		return nil, &Failure{Class: "capacity"}
	}
	defer r.attempts.Add(-1)
	ordered := r.rank(state, dst)
	limit := state.config.Failover.MaxAttempts
	if !*state.config.Failover.Enabled {
		limit = 1
	}
	attempt := 0
	var last error = &Failure{Class: "unavailable"}
	var prepared preparation
	if state.config.Failover.Racing && limit >= 2 && len(ordered) >= 2 && r.canRace(state, ordered[:2]) &&
		claim(&r.attempts, state.config.Limits.ConcurrentAttempts) {
		winner, launched, failures := r.raceService(ctx, state, ordered[:2])
		r.attempts.Add(-1)
		for _, f := range failures {
			last = f
			if !f.Retry {
				return nil, f
			}
		}
		if winner.stream != nil {
			prepared = winner
			defer winner.stream.Close()
			// Each launched speculative attempt consumes one setup slot, even if canceled.
			limit -= launched - 1
			ordered = append([]ranked{winner.candidate}, ordered[launched:]...)
		} else {
			attempt = launched
			ordered = ordered[launched:]
		}
	}
	for _, candidate := range ordered {
		if ctx.Err() != nil || attempt >= limit {
			break
		}
		h, halfOpen := r.admit(state, candidate, false)
		if h == nil {
			continue
		}
		if attempt > 0 {
			r.failovers.Add(1)
		}
		attempt++
		var elapsed time.Duration
		var deadline time.Time
		if prepared.stream != nil && prepared.candidate.ID() == candidate.ID() {
			candidate.Dialer = prepared.stream
			elapsed = prepared.elapsed
			deadline = prepared.deadline
		}
		conn, f := r.try(ctx, state, candidate, h, dst, false, halfOpen, elapsed, deadline)
		if f != nil {
			last = f
			if !f.Retry {
				return nil, last
			}
			continue
		}
		r.mu.Lock()
		current := r.state
		valid := current != nil && current.config.Enabled && current.config.approves(candidate.Member) && current.config.Routing.permits(dst, candidate.ID())
		r.mu.Unlock()
		if !valid {
			_ = conn.Close()
			return nil, &Failure{Class: "unavailable"}
		}
		if attempt > 1 {
			r.recovered.Add(1)
		}
		r.mu.Lock()
		if r.state == state {
			r.lastSelection = candidate.ID()
			switch {
			case attempt > 1:
				r.lastReason = "failover"
			case r.preferred == candidate.ID():
				r.lastReason = "user_preference"
			default:
				r.lastReason = state.config.Egress.Selection
			}
		}
		r.mu.Unlock()
		r.remember(state, dst, candidate.ID())
		h.active.Add(1)
		return &routedConn{Conn: conn, destination: dst, member: candidate.Member, generation: candidate.Generation, health: h}, nil
	}
	if ctx.Err() != nil {
		return nil, &Failure{Class: "timeout", Code: 6}
	}
	return nil, last
}

func hostKey(d Destination) string { return strings.TrimSuffix(strings.ToLower(d.Host), ".") }
