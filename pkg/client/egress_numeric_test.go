package client

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/internal/egressattach"
	"github.com/nmaguiar/ntwire/pkg/egressrouter"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/server"
	"github.com/nmaguiar/ntwire/pkg/socks"
)

func dialNumericProxy(ctx context.Context, proxy, target string, atyp byte) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, err
	}
	if atyp != 0 {
		dst, e := socks.ParseDestination(target)
		if e == nil {
			dst.AddressType = atyp
			e = socks.ConnectDestination(ctx, conn, dst)
		}
		err = e
	} else {
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}
		if _, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err == nil {
			var response *http.Response
			response, err = http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
			if err == nil && response.StatusCode != http.StatusOK {
				err = fmt.Errorf("CONNECT returned %s", response.Status)
			}
		}
		_ = conn.SetDeadline(time.Time{})
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func startNumericProxy(t testing.TB, members []egressrouter.Member, source egressrouter.Source) *egressrouter.Router {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := ln.Addr().String()
	_ = ln.Close()
	router := egressrouter.New(source)
	t.Cleanup(router.Close)
	if err = router.Apply(egressrouter.Config{Enabled: true, Listen: address,
		Egress:   egressrouter.Membership{Selection: "priority", Members: members},
		Failover: egressrouter.Failover{AttemptTimeout: 20 * time.Second, TotalTimeout: 25 * time.Second},
	}, nil); err != nil {
		t.Fatal(err)
	}
	return router
}

func TestSmartProxyNumericDestinationsThroughPublishers(t *testing.T) {
	a, b := newReconnectFixture(t), newReconnectFixture(t)
	startEgressServer(a, "direct-udp", false, true)
	startEgressServer(b, "direct-udp", false, false)
	// Keep the old server view consistent across background renewals until
	// the test enables the upgrade. The data plane uses real WireGuard.
	var upgraded atomic.Bool
	a.http = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler := a.current.Load().Handler()
		if upgraded.Load() || (r.URL.Path != "/v1/auth" && r.URL.Path != "/v1/renew") {
			handler.ServeHTTP(w, r)
			return
		}
		reply := httptest.NewRecorder()
		handler.ServeHTTP(reply, r)
		for k, values := range reply.Header() {
			w.Header()[k] = values
		}
		if reply.Code != http.StatusOK {
			w.WriteHeader(reply.Code)
			_, _ = reply.Body.WriteTo(w)
			return
		}
		var auth protocol.AuthResponse
		if err := json.NewDecoder(reply.Body).Decode(&auth); err != nil {
			http.Error(w, "invalid fixture response", http.StatusInternalServerError)
			return
		}
		for i := range auth.Tunnels {
			auth.Tunnels[i].EgressNumericDomain = false
		}
		_ = json.NewEncoder(w).Encode(auth)
	}))
	t.Cleanup(a.http.Close)
	older, current := a.connect(), b.connect()
	members := []egressrouter.Member{
		{ProfileID: "legacy", Tunnel: "internet", ExpectedServer: a.http.URL, Priority: 100},
		{ProfileID: "current", Tunnel: "internet", ExpectedServer: b.http.URL, Priority: 90},
		{ProfileID: "legacy", Tunnel: "secondary", ExpectedServer: a.http.URL, Priority: 80},
		{ProfileID: "current", Tunnel: "literal-denied", ExpectedServer: b.http.URL, Priority: 70},
		{ProfileID: "current", Tunnel: "private-only", ExpectedServer: b.http.URL, Priority: 60},
	}
	root := filepath.Join(t.TempDir(), "egress")
	for id, owner := range map[string]*Connection{"legacy": older, "current": current} {
		path, _ := egressattach.ProfilePath(root, id)
		publisher, err := egressattach.Start(path, owner.EgressCandidate, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(publisher.Close)
	}
	registry := egressattach.NewRegistry(root)
	refresh := func(grants []egressrouter.Member, caps []bool) {
		t.Helper()
		readiness, cancel := context.WithTimeout(t.Context(), 25*time.Second)
		defer cancel()
		for {
			registry.Refresh(readiness, grants)
			ready := true
			for i, member := range grants {
				candidate := registry.Candidate(member)
				if candidate.Dialer != nil && candidate.NumericDomain == caps[i] {
					continue
				}
				if readiness.Err() != nil {
					t.Fatalf("unexpected snapshot for %v: %+v", member.ID(), candidate)
				}
				ready = false
			}
			if ready {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	refresh(members[:3], []bool{false, true, false})
	router := startNumericProxy(t, members, registry.Candidate)
	proxy := router.Status().Listening
	check := func(target string, atyp, wantCode byte) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 26*time.Second)
		defer cancel()
		conn, err := dialNumericProxy(ctx, proxy, target, atyp)
		if wantCode != 0 {
			if conn != nil {
				_ = conn.Close()
			}
			if atyp == 0 && wantCode == 2 && err != nil && strings.Contains(err.Error(), "403 Forbidden") {
				return
			}
			var reply *socks.ConnectError
			if !errors.As(err, &reply) {
				t.Fatalf("type %d error = %v, want SOCKS reply %d", atyp, err, wantCode)
			}
			if reply.Code != wantCode {
				t.Fatalf("type %d reply %d (cause %v), want %d; router: %+v", atyp, reply.Code, reply.Err, wantCode, router.Status())
			}
			return
		}
		if err != nil {
			t.Fatalf("type %d setup failed: %v; router: %+v", atyp, err, router.Status())
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		_, err = io.WriteString(conn, "echo")
		var echo [4]byte
		if err != nil {
			t.Fatal(err)
		}
		if _, err = io.ReadFull(conn, echo[:]); err != nil || string(echo[:]) != "echo" {
			t.Fatalf("echo %q: %v", echo, err)
		}
	}
	check(a.tcpTarget, 3, 8)
	if status := router.Status(); status.Failovers != 0 || status.Members[0].Attempts != 0 || status.Members[1].Attempts != 0 {
		t.Fatalf("compatibility failure affected routing or health: %+v", status)
	}
	check(a.tcpTarget, 1, 0)
	check(a.tcpTarget, 0, 0)
	if err := router.SetPreference(members[2].ID(), nil); err != nil {
		t.Fatal(err)
	}
	check(a.tcpTarget, 1, 0)
	check(a.tcpTarget, 3, 8)
	if err := router.SetPreference(members[1].ID(), nil); err != nil {
		t.Fatal(err)
	}
	check(b.tcpTarget, 3, 0)
	host, port, _ := net.SplitHostPort(b.tcpTarget)
	check(net.JoinHostPort("::ffff:"+host, port), 3, 0)
	check(b.tcpTarget, 0, 0)
	// Load two additional policies on new listeners. Reconnect to acquire
	// their grants while the already-open egress listeners stay bound.
	srv := b.current.Load()
	cfg := srv.Config
	literalDenied, privateOnly := cfg.Tunnels[0], cfg.Tunnels[0]
	literalDenied.Name, literalDenied.VirtualPort = members[3].Tunnel, 10081
	literalDenied.Socks = &server.SocksConfig{AllowLocalEgress: true, ReverseFilters: true, DomainFilters: []string{".0.1"}}
	privateOnly.Name, privateOnly.VirtualPort = members[4].Tunnel, 10082
	privateOnly.Socks = &server.SocksConfig{OnlyLocal: true}
	cfg.Tunnels = []server.TunnelConfig{cfg.Tunnels[0], literalDenied, privateOnly}
	srv.Reload(cfg)
	if err := current.reconnect(); err != nil {
		t.Fatal(err)
	}
	refresh(members, []bool{false, true, false, true, true})
	if err := router.SetPreference(members[3].ID(), nil); err != nil {
		t.Fatal(err)
	}
	check(b.tcpTarget, 1, 0)
	check(b.tcpTarget, 3, 2)
	if err := router.SetPreference(members[4].ID(), nil); err != nil {
		t.Fatal(err)
	}
	check(b.tcpTarget, 0, 2)
	check(b.tcpTarget, 1, 2)
	check(b.tcpTarget, 3, 2)
	if router.Status().Failovers != 0 {
		t.Fatal("server policy denial triggered failover")
	}
	upgraded.Store(true)
	if err := older.renew(); err != nil {
		// A scheduled renewal may already have replaced the same token.
		if err := older.reconnect(); err != nil {
			t.Fatal(err)
		}
	}
	refresh(members, []bool{true, true, false, true, true})
	if err := router.SetPreference(members[0].ID(), nil); err != nil {
		t.Fatal(err)
	}
	check(a.tcpTarget, 3, 0)
}

func TestSmartProxyChromiumNumericURLs(t *testing.T) {
	browser := os.Getenv("NTWIRE_TEST_CHROMIUM")
	if browser == "" {
		t.Skip("set NTWIRE_TEST_CHROMIUM to a Chromium executable")
	}
	f := newReconnectFixture(t)
	startEgressServer(f, "direct-udp", false, false)
	c := f.connect()
	member := egressrouter.Member{ProfileID: "chromium", Tunnel: "internet", ExpectedServer: f.http.URL}
	router := startNumericProxy(t, []egressrouter.Member{member}, c.EgressCandidate)
	const marker = "ntwire-local-browser-origin"
	for _, host := range []string{"127.0.0.1", "::1", "localhost"} {
		t.Run(host, func(t *testing.T) {
			bind := host
			if host == "localhost" {
				bind = "127.0.0.1"
			}
			ln, err := net.Listen("tcp", net.JoinHostPort(bind, "0"))
			if err != nil {
				t.Fatal(err)
			}
			_, port, _ := net.SplitHostPort(ln.Addr().String())
			origin := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "<p>"+marker+"</p>")
			})}
			go func() { _ = origin.Serve(ln) }()
			t.Cleanup(func() { _ = origin.Close() })
			if host == "localhost" {
				v6, err := net.Listen("tcp", net.JoinHostPort("::1", port))
				if err != nil {
					t.Fatal(err)
				}
				go func() { _ = origin.Serve(v6) }()
			}
			address := router.Status().Listening
			if err := router.Apply(egressrouter.Config{Enabled: true, Listen: address,
				Egress:  egressrouter.Membership{Members: []egressrouter.Member{member}},
				Routing: egressrouter.Routing{Rules: []egressrouter.Rule{{Ports: []uint16{uint16(ln.Addr().(*net.TCPAddr).Port)}}}},
			}, nil); err != nil {
				t.Fatal(err)
			}
			before := router.Status().Members[0].Routed
			proxyHost, _, _ := net.SplitHostPort(address)
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, browser, "--headless", "--disable-background-networking", "--disable-sync", "--no-first-run",
				"--no-default-browser-check", "--user-data-dir="+t.TempDir(), "--proxy-server=socks5://"+address,
				"--proxy-bypass-list=<-loopback>", "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE "+proxyHost,
				"--dump-dom", "http://"+net.JoinHostPort(host, port)+"/")
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			loaded := make(chan bool, 1)
			go func() {
				scanner := bufio.NewScanner(stdout)
				for scanner.Scan() {
					if strings.Contains(scanner.Text(), marker) {
						loaded <- true
						return
					}
				}
				loaded <- false
			}()
			var found bool
			select {
			case found = <-loaded:
			case <-ctx.Done():
			}
			// Chrome can keep the headless process alive after dumping the DOM.
			cancel()
			_ = cmd.Wait()
			if !found {
				t.Fatalf("browser did not render the origin for %s", host)
			}
			if router.Status().Members[0].Routed <= before {
				t.Fatalf("browser rendered %s without using the SOCKS5 group", host)
			}
		})
	}
}
