package egressrouter

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type testSelector func(time.Time, Destination, []RankedCandidate) []MemberID

func (s testSelector) Rank(now time.Time, dst Destination, in []RankedCandidate) []MemberID {
	return s(now, dst, in)
}

func TestDestinationRulesApplyBeforeSelector(t *testing.T) {
	cfg := testConfig(t)
	only := cfg.Egress.Members[1].ID()
	cfg.Routing.Rules = []Rule{{Suffixes: []string{"internal.example"}, Ports: []uint16{443}, Members: []MemberID{only}},
		{CIDRs: []string{"2001:db8::/32"}, Ports: []uint16{80}},
	}
	var allowed atomic.Int32
	source := func(m Member) Candidate {
		return Candidate{Generation: "1", Dialer: dialFunc(func(ctx context.Context, dst Destination) (net.Conn, error) {
			if m.ID() != only {
				t.Errorf("unapproved dial for %+v", m)
			}
			allowed.Add(1)
			return nil, &Failure{Class: "policy_denied", Code: 2, Stage: "socks_connect"}
		})}
	}
	router := NewWithSelector(source, testSelector(func(_ time.Time, _ Destination, in []RankedCandidate) []MemberID {
		if len(in) != 1 || in[0].ID() != only {
			t.Errorf("selector received unauthorized members: %+v", in)
		}
		return []MemberID{cfg.Egress.Members[0].ID(), only, only}
	}))
	defer router.Close()
	if err := router.Apply(cfg, nil); err != nil {
		t.Fatal(err)
	}
	_, err := router.dial(t.Context(), "tcp", "sub.internal.example:443")
	if socksCode(err) != 2 || allowed.Load() != 1 {
		t.Fatalf("err %v attempts %d", err, allowed.Load())
	}
	_, err = router.dial(t.Context(), "tcp", "notinternal.example:443")
	if socksCode(err) != 2 || allowed.Load() != 1 {
		t.Fatalf("unmatched request made a dial: %v", err)
	}
	if got := router.Status().Members[1]; got.DestinationFailures != 1 || got.RecentSamples != 1 || got.SuccessRate != 0 {
		t.Fatalf("missing bounded telemetry: %+v", got)
	}
}

func TestDestinationAwareUsesFreshHistory(t *testing.T) {
	cfg := testConfig(t)
	cfg.Egress.Selection = "destination-aware"
	r := New(func(Member) Candidate { return Candidate{Generation: "1", Dialer: dialFunc(nil)} })
	defer r.Close()
	if err := r.Apply(cfg, nil); err != nil {
		t.Fatal(err)
	}
	dst := Destination{"host.invalid", 443}
	now := time.Now()
	state := r.state
	for _, m := range cfg.Egress.Members {
		c := ranked{Member: m, Candidate: Candidate{Generation: "1"}}
		n := time.Duration(100) * time.Millisecond
		if m.ID() == cfg.Egress.Members[1].ID() {
			n = 10 * time.Millisecond
		}
		for range 3 {
			state.observeDestination(now, c, dst, n, nil)
		}
	}
	if got := r.rank(state, dst)[0].ID(); got != cfg.Egress.Members[1].ID() {
		t.Fatal(got)
	}
	if got := r.rank(state, Destination{"other.invalid", 443})[0].ID(); got != cfg.Egress.Members[0].ID() {
		t.Fatal(got)
	}
}

func TestGroupAffinitySurvivesDestinationException(t *testing.T) {
	cfg := testConfig(t)
	a, b := cfg.Egress.Members[0].ID(), cfg.Egress.Members[1].ID()
	cfg.Egress.Selection = "sticky-fastest"
	cfg.Routing.AffinityScope = "group"
	cfg.Routing.Unmatched = "allow"
	cfg.Routing.Rules = []Rule{{Hosts: []string{"exception.example"}, Members: []MemberID{a}}}
	r := New(func(Member) Candidate { return Candidate{Generation: "1", Dialer: dialFunc(nil)} })
	defer r.Close()
	now := time.Now()
	r.now = func() time.Time { return now }
	if err := r.Apply(cfg, nil); err != nil {
		t.Fatal(err)
	}
	state := r.state
	r.remember(state, Destination{"first.example", 443}, b)
	exception := Destination{"exception.example", 443}
	if got := r.rank(state, exception)[0].ID(); got != a {
		t.Fatalf("override selected %v", got)
	}
	r.remember(state, exception, a)
	other := Destination{"second.example", 443}
	if got := r.rank(state, other)[0].ID(); got != b {
		t.Fatalf("override changed the group affinity: %v", got)
	}
	now = now.Add(state.config.Routing.AffinityTTL + time.Second)
	if got := r.rank(state, other)[0].ID(); got != a {
		t.Fatalf("expired affinity still selected %v", got)
	}
}

func TestNamedGroupsAndPACApplyAtomically(t *testing.T) {
	cfg := testConfig(t)
	cfg.Groups = map[string]Config{"office": testConfig(t)}
	cfg.PACListen = testConfig(t).Listen
	g := NewGroupSet(func(Member) Candidate { return Candidate{} })
	defer g.Close()
	if err := g.Apply(cfg, nil); err != nil {
		t.Fatal(err)
	}
	if got := g.Status(); got.Groups["office"].Listening != cfg.Groups["office"].Listen || got.Listening != cfg.Listen {
		t.Fatalf("unexpected status %+v", got)
	}
	res, err := http.Get("http://" + cfg.PACListen + "/office.pac")
	if err != nil {
		t.Fatal(err)
	}
	script, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil || res.StatusCode != 200 || !strings.Contains(string(script), cfg.Groups["office"].Listen) ||
		strings.Contains(string(script), "DIRECT") || strings.Contains(string(script), "dnsResolve") {
		t.Fatalf("unexpected PAC %d %s %v", res.StatusCode, script, err)
	}
	next := cfg
	next.Groups = map[string]Config{"office": testConfig(t)}
	if err = g.Apply(next, func(Config) error { return errors.New("save failed") }); err == nil {
		t.Fatal("persist error lost")
	}
	if got := g.Status().Groups["office"].Listening; got != cfg.Groups["office"].Listen {
		t.Fatalf("listener changed: %s", got)
	}
}

type preparing struct {
	prepare func(context.Context) (PreparedEgress, error)
}

func (p preparing) Prepare(ctx context.Context) (PreparedEgress, error) { return p.prepare(ctx) }
func (p preparing) DialDestination(context.Context, Destination) (net.Conn, error) {
	return nil, errors.New("expected preflight")
}

type preparedTest struct {
	payload atomic.Int32
	closed  atomic.Bool
	code    byte
}

func (p *preparedTest) DialDestination(context.Context, Destination) (net.Conn, error) {
	p.payload.Add(1)
	return nil, &Failure{Class: "policy_denied", Code: p.code}
}
func (p *preparedTest) Close() error { p.closed.Store(true); return nil }

func TestRacingSubmitsDestinationOnlyToWinner(t *testing.T) {
	cfg := testConfig(t)
	cfg.Failover.Racing = true
	cfg.Failover.RaceDelay = time.Millisecond
	loser, winner := &preparedTest{}, &preparedTest{code: 2}
	r := New(func(m Member) Candidate {
		return Candidate{Generation: "1", Preparation: true, Dialer: preparing{prepare: func(ctx context.Context) (PreparedEgress, error) {
			if m.ID() == cfg.Egress.Members[0].ID() {
				<-ctx.Done()
				return loser, nil
			}
			return winner, nil
		}}}
	})
	defer r.Close()
	if err := r.Apply(cfg, nil); err != nil {
		t.Fatal(err)
	}
	_, err := r.dial(t.Context(), "tcp", "private.invalid:443")
	if socksCode(err) != 2 || loser.payload.Load() != 0 || !loser.closed.Load() || winner.payload.Load() != 1 {
		t.Fatalf("unexpected racer behavior: %v", err)
	}
	if got := r.Status(); got.RaceAttempts != 2 || got.RaceBackups != 1 || got.Failovers != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestSOCKSDisconnectCancelsPendingDial(t *testing.T) {
	started, stopped := make(chan struct{}), make(chan struct{})
	r := New(func(Member) Candidate {
		return Candidate{Generation: "1", Dialer: dialFunc(func(ctx context.Context, _ Destination) (net.Conn, error) {
			close(started)
			<-ctx.Done()
			close(stopped)
			return nil, ctx.Err()
		})}
	})
	cfg := testConfig(t)
	cfg.Egress.Members = cfg.Egress.Members[:1]
	defer r.Close()
	if err := r.Apply(cfg, nil); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, _ = conn.Write([]byte{5, 1, 0})
	var reply [2]byte
	if _, err = io.ReadFull(conn, reply[:]); err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("dial never started")
	}
	_ = conn.Close()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("setup survived client disconnect")
	}
}
