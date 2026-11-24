package egressrouter

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

type dialFunc func(context.Context, Destination) (net.Conn, error)

func (d dialFunc) DialDestination(ctx context.Context, dst Destination) (net.Conn, error) {
	return d(ctx, dst)
}

func testConfig(t testing.TB) Config {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return Config{Enabled: true, Listen: ln.Addr().String(), Egress: Membership{Selection: "priority", Members: []Member{
		{ProfileID: "a", Tunnel: "internet", ExpectedServer: "https://a.example", Priority: 100},
		{ProfileID: "b", Tunnel: "internet", ExpectedServer: "https://b.example", Priority: 90},
	}}}
}

func TestSmartProxyFailurePolicy(t *testing.T) {
	for _, tc := range []struct {
		name string
		fail *Failure
		want []string
		code byte
	}{
		{"transport", &Failure{Class: "transport", Retry: true}, []string{"a", "b"}, 0},
		{"denied", &Failure{Class: "policy_denied", Code: 2}, []string{"a"}, 2},
		{"ambiguous", &Failure{Class: "ambiguous"}, []string{"a"}, 1},
		{"post-submit-timeout", &Failure{Class: "timeout", Code: 6}, []string{"a"}, 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			cfg := testConfig(t)
			r := New(func(m Member) Candidate {
				return Candidate{Generation: "1", Dialer: dialFunc(func(_ context.Context, d Destination) (net.Conn, error) {
					calls = append(calls, m.ProfileID)
					if d.Host != "internal.invalid" || d.Port != 443 {
						t.Errorf("unexpected destination %+v", d)
					}
					if m.ProfileID == "a" {
						return nil, tc.fail
					}
					in, out := net.Pipe()
					go func() { defer out.Close(); _, _ = io.Copy(out, out) }()
					return in, nil
				})}
			})
			t.Cleanup(r.Close)
			if err := r.Apply(cfg, nil); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			c, err := r.dial(ctx, "tcp", "internal.invalid:443")
			if tc.code == 0 {
				if err != nil {
					t.Fatal(err)
				}
				c.Close()
			} else if socksCode(err) != tc.code {
				t.Fatalf("unexpected error %v", err)
			}
			if !slices.Equal(calls, tc.want) {
				t.Fatalf("attempts %v want %v", calls, tc.want)
			}
			for _, member := range r.Status().Members {
				var want uint64
				if tc.code == 0 && member.ProfileID == "b" {
					want = 1
				}
				if member.Routed != want {
					t.Errorf("%s routed %d connections, want %d", member.ProfileID, member.Routed, want)
				}
			}
		})
	}
}

func TestSmartProxyHTTPPoolNeverReplays(t *testing.T) {
	var requests, dials atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/drop" {
			conn, _, err := http.NewResponseController(w).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()
	cfg := testConfig(t)
	router := New(func(m Member) Candidate {
		return Candidate{Generation: "1", Dialer: dialFunc(func(ctx context.Context, dst Destination) (net.Conn, error) {
			dials.Add(1)
			if dst.Host != "host.invalid" {
				t.Errorf("unexpected destination %s", dst.Host)
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp", origin.Listener.Addr().String())
		})}
	})
	defer router.Close()
	if err := router.Apply(cfg, nil); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	for _, tc := range []struct {
		path   string
		status int
	}{{"/one", 200}, {"/two", 200}, {"/drop", 502}} {
		_, _ = fmt.Fprintf(conn, "GET http://host.invalid%s HTTP/1.1\r\nHost: host.invalid\r\nIdempotency-Key: test\r\n\r\n", tc.path)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Fatalf("%s got %s", tc.path, resp.Status)
		}
	}
	if requests.Load() != 3 || dials.Load() != 1 {
		t.Fatalf("requests=%d dials=%d", requests.Load(), dials.Load())
	}
}

func TestNumericDestinationsShareRuleAffinityAndHistory(t *testing.T) {
	cfg := testConfig(t)
	cfg.Egress.Selection = "sticky-fastest"
	want := cfg.Egress.Members[1].ID()
	cfg.Routing = Routing{Rules: []Rule{{CIDRs: []string{"192.0.2.0/24"}, Members: []MemberID{want}}}}
	r := New(func(m Member) Candidate {
		return Candidate{Generation: "1", NumericDomain: true, Dialer: dialFunc(func(_ context.Context, dst Destination) (net.Conn, error) {
			if m.ID() != want {
				t.Errorf("%+v reached forbidden member %v", dst, m.ID())
			}
			a, b := net.Pipe()
			_ = b.Close()
			return a, nil
		})}
	})
	defer r.Close()
	if err := r.Apply(cfg, nil); err != nil {
		t.Fatal(err)
	}
	for _, dst := range []Destination{
		{Host: "192.0.2.7", Port: 443, AddressType: 1},
		{Host: "192.0.2.7", Port: 443, AddressType: 3},
		{Host: "::ffff:c000:207", Port: 443, AddressType: 3},
		{Host: "::ffff:192.0.2.7", Port: 443, AddressType: 4},
		{Host: "192.0.2.7", Port: 443},
	} {
		conn, err := r.dialDestination(t.Context(), dst)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := observationKey{member: want, host: "192.0.2.7", port: 443}
	if len(r.state.affinity) != 1 || r.state.affinity[key.host].id != want ||
		len(r.state.destinations) != 1 || r.state.destinations[key].samples != 5 {
		t.Fatalf("separate routing state: %+v %+v", r.state.affinity, r.state.destinations)
	}
}

func TestSmartProxyHTTPPoolNumericAliasesDependOnCapability(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer origin.Close()
	for _, native := range []bool{false, true} {
		t.Run(fmt.Sprintf("native=%t", native), func(t *testing.T) {
			var dials atomic.Int32
			cfg := testConfig(t)
			router := New(func(Member) Candidate {
				return Candidate{Generation: "1", NumericDomain: native, Dialer: dialFunc(func(ctx context.Context, _ Destination) (net.Conn, error) {
					dials.Add(1)
					return (&net.Dialer{}).DialContext(ctx, "tcp", origin.Listener.Addr().String())
				})}
			})
			defer router.Close()
			if err := router.Apply(cfg, nil); err != nil {
				t.Fatal(err)
			}
			conn, err := net.Dial("tcp", cfg.Listen)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			br := bufio.NewReader(conn)
			for _, host := range []string{"192.0.2.7", "[::ffff:192.0.2.7]", "[0:0:0:0:0:FFFF:c000:207]"} {
				_, _ = fmt.Fprintf(conn, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)
				resp, err := http.ReadResponse(br, nil)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("%s got %s", host, resp.Status)
				}
			}
			want := int32(2)
			if native {
				want = 1
			}
			if got := dials.Load(); got != want {
				t.Fatalf("dialed %d times, want %d", got, want)
			}
		})
	}
}

func TestSmartProxyReloadKeepsListenerOnError(t *testing.T) {
	cfg := testConfig(t)
	r := New(func(Member) Candidate { return Candidate{} })
	defer r.Close()
	if err := r.Apply(cfg, nil); err != nil {
		t.Fatal(err)
	}
	conflict, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conflict.Close()
	next := cfg
	next.Listen = conflict.Addr().String()
	if err = r.Apply(next, nil); err == nil {
		t.Fatal("port conflict was accepted")
	}
	next.Listen = testConfig(t).Listen
	if err = r.Apply(next, func(Config) error { return errors.New("cannot save") }); err == nil {
		t.Fatal("failed save was accepted")
	}
	if got := r.Status().Listening; got != cfg.Listen {
		t.Fatalf("listener changed to %s", got)
	}
}

func TestSmartProxyStickyAndCircuit(t *testing.T) {
	cfg := testConfig(t)
	cfg.Egress.Selection = "sticky-fastest"
	cfg.Health.FailureThreshold = 1
	now := time.Now()
	r := New(func(Member) Candidate {
		return Candidate{Generation: "1", Dialer: dialFunc(func(context.Context, Destination) (net.Conn, error) {
			return nil, &Failure{Class: "transport", Retry: true}
		})}
	})
	r.now = func() time.Time { return now }
	defer r.Close()
	if err := r.Apply(cfg, nil); err != nil {
		t.Fatal(err)
	}
	state := r.state
	a, b := cfg.Egress.Members[0].ID(), cfg.Egress.Members[1].ID()
	state.health[a] = &memberHealth{generation: "1", measurements: measurements{samples: 3, revision: 3, latency: float64(100 * time.Millisecond), lastSuccess: now}}
	state.health[b] = &memberHealth{generation: "1", measurements: measurements{samples: 3, revision: 3, latency: float64(60 * time.Millisecond), lastSuccess: now}}
	dst := Destination{Host: "test.invalid", Port: 443}
	r.remember(state, dst, a)
	for i, want := range []MemberID{a, a, a, a, b} {
		if i == 3 || i == 4 {
			state.health[b].revision++
		}
		if got := r.rank(state, dst)[0].ID(); got != want {
			t.Fatalf("comparison %d selected %v", i, got)
		}
	}
	c := r.rank(state, dst)[0]
	h, halfOpen := r.admit(state, c, false)
	if h == nil {
		t.Fatal("healthy member not admitted")
	}
	_, _ = r.try(t.Context(), state, c, h, dst, false, halfOpen, 0, time.Time{})
	if got := r.rank(state, dst)[0].ID(); got != a {
		t.Fatalf("open circuit selected %v", got)
	}
	now = now.Add(state.config.Health.RecoveryInterval)
	if h, halfOpen = r.admit(state, c, false); h == nil || !halfOpen {
		t.Fatal("half open probe not admitted")
	}
	if h, _ = r.admit(state, c, false); h != nil {
		t.Fatal("multiple half-open probes admitted")
	}
}

func BenchmarkSmartProxyRank(b *testing.B) {
	members := make([]Member, 32)
	for i := range members {
		members[i] = Member{ProfileID: fmt.Sprint("profile", i), Tunnel: "internet", ExpectedServer: "https://test.example", Priority: i}
	}
	cfg, _ := (Config{Egress: Membership{Selection: "sticky-fastest", Members: members}}).Normalized()
	r := New(func(Member) Candidate { return Candidate{Generation: "1", Dialer: dialFunc(nil)} })
	r.state = &routeState{config: cfg, health: map[MemberID]*memberHealth{}, affinity: map[string]affinity{}}
	b.ReportAllocs()
	for b.Loop() {
		_ = r.rank(r.state, Destination{Host: "test.example", Port: 443})
	}
}

func TestSmartProxyHTTPUpgradeStaysPinned(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		_ = rw.Flush()
		_, _ = io.Copy(c, rw)
	}))
	defer origin.Close()
	cfg := testConfig(t)
	r := New(func(Member) Candidate {
		return Candidate{Generation: "1", Dialer: dialFunc(func(ctx context.Context, _ Destination) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", origin.Listener.Addr().String())
		})}
	})
	defer r.Close()
	if err := r.Apply(cfg, nil); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	_, _ = io.WriteString(conn, "GET http://origin.invalid/ HTTP/1.1\r\nHost: origin.invalid\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 101 {
		t.Fatal(resp.Status)
	}
	exclude := true
	if err = r.SetPreference(cfg.Egress.Members[0].ID(), &exclude); err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(conn, "socket")
	got := make([]byte, 6)
	if _, err = io.ReadFull(br, got); err != nil || string(got) != "socket" {
		t.Fatalf("upgraded stream %q: %v", got, err)
	}
}
