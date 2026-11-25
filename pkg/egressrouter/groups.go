package egressrouter

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nmaguiar/ntwire/pkg/pac"
)

// GroupSet owns a backwards-compatible default listener and optional independent
// groups. Configuration and port allocation are committed as one operation.
type GroupSet struct {
	asn         *asnDatabase
	endpoints   atomic.Pointer[[]string]
	mu          sync.RWMutex
	source      Source
	discover    Discover
	groups      map[string]*Router
	config      Config
	pacListener net.Listener
	pacServer   *http.Server
	closed      bool
}

func NewGroupSet(source Source) *GroupSet { return NewDiscoveredGroupSet(source, nil) }

// NewDiscoveredGroupSet enables candidate discovery for explicit enrollments.
func NewDiscoveredGroupSet(source Source, discover Discover) *GroupSet {
	return &GroupSet{source: source, discover: discover, groups: map[string]*Router{}}
}
func (g *GroupSet) Apply(config Config, save func(Config) error) error {
	cfg, err := config.Normalized()
	if err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return net.ErrClosed
	}
	configs := make(map[string]Config, len(cfg.Groups)+1)
	for n, c := range cfg.Groups {
		configs[n] = c
	}
	root := cfg
	root.Groups = nil
	root.PACListen = ""
	configs["default"] = root
	type prepared struct {
		router   *Router
		listener net.Listener
		cfg      Config
	}
	staged := make(map[string]prepared, len(configs))
	before := g.pacListener
	nextPAC := before
	defer func() {
		for _, p := range staged {
			p.router.discardPrepared(p.listener)
			p.router.apply.Unlock()
		}
		if nextPAC != nil && nextPAC != g.pacListener {
			_ = nextPAC.Close()
		}
	}()
	for name, c := range configs {
		router := g.groups[name]
		if router == nil {
			router = New(g.candidate)
			router.discover = g.discover
		}
		router.apply.Lock()
		ln, err := router.prepare(c)
		if err != nil {
			router.apply.Unlock()
			return err
		}
		staged[name] = prepared{router: router, listener: ln, cfg: c}
	}
	if cfg.PACListen == "" {
		nextPAC = nil
	} else if before == nil || before.Addr().String() != cfg.PACListen {
		nextPAC, err = net.Listen("tcp", cfg.PACListen)
		if err != nil {
			return fmt.Errorf("smart proxy PAC bind %s: %w", cfg.PACListen, err)
		}
	}
	if save != nil {
		if err = save(cfg); err != nil {
			return err
		}
	}
	var endpoints []string
	for _, config := range configs {
		if config.Enabled {
			endpoints = append(endpoints, config.Listen)
		}
	}
	if cfg.PACListen != "" {
		endpoints = append(endpoints, cfg.PACListen)
	}
	g.endpoints.Store(&endpoints)
	used := false
	for _, config := range configs {
		used = used || config.Enabled && config.Routing.usesASN()
	}
	g.asn = useASNDatabase(g.asn, cfg.ASNDatabase, used)
	old := g.groups
	g.groups = make(map[string]*Router, len(staged))
	for name, p := range staged {
		// A change to one group should not reset the preferences or routing
		// history of groups with the same configuration and listener.
		if p.router.state == nil || p.router.asnShared != g.asn && p.cfg.Routing.usesASN() || !reflect.DeepEqual(p.router.state.config, p.cfg) || p.router.listener != p.listener {
			p.router.asnShared = g.asn
			p.router.commit(p.cfg, p.listener)
		}
		g.groups[name] = p.router
	}
	g.config = cfg
	if before != nextPAC {
		if g.pacServer != nil {
			_ = g.pacServer.Close()
		}
		// Serve may not yet have acquired the old listener.
		if before != nil {
			_ = before.Close()
		}
		g.pacListener, g.pacServer = nextPAC, nil
		if nextPAC != nil {
			srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 4096}
			mux := http.NewServeMux()
			mux.HandleFunc("GET /{file}", g.servePAC)
			srv.Handler = mux
			g.pacServer = srv
			go func() { _ = srv.Serve(nextPAC) }()
		}
	}
	for name, r := range old {
		if g.groups[name] == nil {
			r.Close()
		}
	}
	return nil
}

func (g *GroupSet) servePAC(w http.ResponseWriter, r *http.Request) {
	// A fixed numeric Host avoids using the PAC endpoint through DNS rebinding.
	g.mu.RLock()
	listener := g.pacListener
	g.mu.RUnlock()
	if listener == nil || r.Host != listener.Addr().String() {
		http.NotFound(w, r)
		return
	}
	file := r.PathValue("file")
	if !strings.HasSuffix(file, ".pac") {
		http.NotFound(w, r)
		return
	}
	script, err := g.PAC(strings.TrimSuffix(file, ".pac"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", pac.ContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(script))
}

func (g *GroupSet) PAC(group string) (string, error) {
	status, cfg, ok := g.Group(group)
	if !ok || status.Listening == "" {
		return "", errors.New("smart proxy group is not listening")
	}
	return pac.Aggregate(status.Listening, slices.Contains(cfg.Protocols, "http"))
}
func (g *GroupSet) Group(group string) (Status, Config, bool) {
	if group == "" {
		group = "default"
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	router := g.groups[group]
	if router == nil {
		return Status{}, Config{}, false
	}
	cfg := g.config
	if group != "default" {
		cfg = g.config.Groups[group]
	}
	return router.Status(), cfg, true
}

// ListeningGroups returns the names of groups that can accept connections.
func (g *GroupSet) ListeningGroups() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	names := make([]string, 0, len(g.groups))
	for name, router := range g.groups {
		router.mu.Lock()
		listening := router.listener != nil
		router.mu.Unlock()
		if listening {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

func (g *GroupSet) Status() Status {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.groups["default"] == nil {
		return Status{}
	}
	status := g.groups["default"].Status()
	status.ASNDatabase = g.asn.status(time.Now())
	if len(g.groups) > 1 {
		status.Groups = make(map[string]Status, len(g.groups)-1)
	}
	for name, r := range g.groups {
		if name != "default" {
			status.Groups[name] = r.Status()
		}
	}
	if g.pacListener != nil {
		status.PACListen = g.pacListener.Addr().String()
	}
	return status
}
func (g *GroupSet) SetPreference(group string, id MemberID, exclude *bool) error {
	if group == "" {
		group = "default"
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	r := g.groups[group]
	if r == nil {
		return errors.New("unknown smart proxy group")
	}
	return r.SetPreference(id, exclude)
}
func (g *GroupSet) Close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
	if g.asn != nil {
		g.asn.cancel()
	}
	if g.pacServer != nil {
		_ = g.pacServer.Close()
	}
	if g.pacListener != nil {
		_ = g.pacListener.Close()
		g.pacListener = nil
	}
	for _, r := range g.groups {
		r.Close()
	}
	clear(g.groups)
}

func (g *GroupSet) candidate(member Member) Candidate {
	if g.source == nil {
		return Candidate{}
	}
	candidate := g.source(member)
	if endpoints := g.endpoints.Load(); endpoints != nil && candidate.ControlProxy != "" {
		for _, endpoint := range *endpoints {
			if sameEndpoint(endpoint, candidate.ControlProxy) {
				candidate.Dialer = nil
				candidate.Reason = "recursive_control_proxy"
				break
			}
		}
	}
	return candidate
}
