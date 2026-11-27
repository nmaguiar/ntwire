package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/internal/egressattach"
	"github.com/nmaguiar/ntwire/pkg/egressrouter"
	"golang.org/x/net/proxy"
)

func proxyBenchmarkDial(b *testing.B, addr string) func(context.Context, string, string) (net.Conn, error) {
	b.Helper()
	dialer, err := proxy.SOCKS5("tcp", addr, nil, &net.Dialer{})
	if err != nil {
		b.Fatal(err)
	}
	return dialer.(proxy.ContextDialer).DialContext
}

// BenchmarkSmartProxyTransport compares the three carriers and the five
// deployment cases against one controlled local TCP echo destination.
func BenchmarkSmartProxyTransport(b *testing.B) {
	for _, transport := range []string{"direct-udp", "udp-relay", "wss"} {
		b.Run(transport, func(b *testing.B) {
			a, backup := newReconnectFixture(b), newReconnectFixture(b)
			startEgressServer(a, transport, false, false)
			startEgressServer(backup, transport, false, false)
			ca, cb := connectEgress(a, transport), connectEgress(backup, transport)
			if transport == "udp-relay" {
				testUDPRelayBaseline(b, ca, a.tcpTarget)
				testUDPRelayBaseline(b, cb, backup.tcpTarget)
			}
			members := []egressrouter.Member{
				{ProfileID: "a", Tunnel: "internet", ExpectedServer: a.http.URL, Priority: 100},
				{ProfileID: "b", Tunnel: "internet", ExpectedServer: backup.http.URL, Priority: 90},
			}
			b.Run("direct", func(b *testing.B) {
				benchmarkEgressSetup(b, a.tcpTarget, (&net.Dialer{}).DialContext)
			})
			individual := ca.State().Tunnels[0].LocalAddress
			b.Run("individual", func(b *testing.B) {
				benchmarkEgressSetup(b, a.tcpTarget, proxyBenchmarkDial(b, individual))
			})
			root := filepath.Join(b.TempDir(), "egress")
			for id, owner := range map[string]*Connection{"a": ca, "b": cb} {
				path, _ := egressattach.ProfilePath(root, id)
				publisher, err := egressattach.Start(path, owner.EgressCandidate, nil)
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(publisher.Close)
			}
			registry := egressattach.NewRegistry(root)
			registry.Refresh(b.Context(), members)
			local := func(m egressrouter.Member) egressrouter.Candidate {
				if m.ProfileID == "a" {
					return ca.EgressCandidate(m)
				}
				return cb.EgressCandidate(m)
			}
			for _, backend := range []struct {
				name   string
				source egressrouter.Source
			}{{"in-process", local}, {"attached", registry.Candidate}} {
				for _, scenario := range []string{"one", "multiple", "unavailable-primary"} {
					b.Run(backend.name+"/"+scenario, func(b *testing.B) {
						source := func(m egressrouter.Member) egressrouter.Candidate {
							if m.ProfileID == "a" && scenario == "unavailable-primary" {
								return egressrouter.Candidate{Reason: "transport"}
							}
							return backend.source(m)
						}
						egresses := members
						if scenario == "one" {
							egresses = members[:1]
						}
						benchmarkRoutedSetup(b, a.tcpTarget, egresses, source)
					})
				}
			}
		})
	}
}

// BenchmarkSmartProxyDestinationEncoding compares native SOCKS5 and HTTP
// CONNECT over the same governed WireGuard egress and local echo workload.
func BenchmarkSmartProxyDestinationEncoding(b *testing.B) {
	f := newReconnectFixture(b)
	startEgressServer(f, "direct-udp", false, false)
	owner := f.connect()
	member := egressrouter.Member{ProfileID: "local", Tunnel: "internet", ExpectedServer: f.http.URL}
	router := startNumericProxy(b, []egressrouter.Member{member}, owner.EgressCandidate)
	address := router.Status().Listening
	_, port, err := net.SplitHostPort(f.tcpTarget)
	if err != nil {
		b.Fatal(err)
	}
	v6 := net.JoinHostPort("::1", port)
	listener, err := net.Listen("tcp", v6)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	for _, tc := range []struct {
		name, destination string
		atyp              byte
	}{
		{"SOCKS5/IPv4-binary", f.tcpTarget, 1},
		{"SOCKS5/IPv4-domain", f.tcpTarget, 3},
		{"SOCKS5/IPv6-binary", v6, 4},
		{"SOCKS5/IPv6-domain", v6, 3},
		{"SOCKS5/hostname", net.JoinHostPort("localhost", port), 3},
		{"HTTP/IPv4", f.tcpTarget, 0},
		{"HTTP/IPv6", v6, 0},
	} {
		b.Run(tc.name, func(b *testing.B) {
			benchmarkEgressSetup(b, tc.destination, func(ctx context.Context, _ string, dst string) (net.Conn, error) {
				return dialNumericProxy(ctx, address, dst, tc.atyp)
			})
		})
	}
}

func benchmarkRoutedSetup(b *testing.B, origin string, members []egressrouter.Member, source egressrouter.Source) {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	router := egressrouter.New(source)
	defer router.Close()
	if err = router.Apply(egressrouter.Config{Enabled: true, Listen: addr, Egress: egressrouter.Membership{Members: members},
		Failover: egressrouter.Failover{AttemptTimeout: 8 * time.Second}}, nil); err != nil {
		b.Fatal(err)
	}
	benchmarkEgressSetup(b, origin, proxyBenchmarkDial(b, addr))
}

// BenchmarkSmartProxyWarmService compares actual SOCKS transfers through an
// authenticated local attachment and a delayed loopback WireGuard UDP path.
func BenchmarkSmartProxyWarmService(b *testing.B) {
	fixture := newReconnectFixture(b)
	startEgressServerWithFaults(fixture, "direct-udp", false, false, &udpFault{delay: 10 * time.Millisecond})
	owner := fixture.connect()
	testEgressInternalDial(b, owner, fixture.tcpTarget)
	member := egressrouter.Member{ProfileID: "a", Tunnel: "internet", ExpectedServer: fixture.http.URL}
	root := filepath.Join(b.TempDir(), "egress")
	path, err := egressattach.ProfilePath(root, member.ProfileID)
	if err != nil {
		b.Fatal(err)
	}
	attachment, err := egressattach.Start(path, owner.EgressCandidate, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer attachment.Close()
	registry := egressattach.NewRegistry(root)
	members := []egressrouter.Member{member}
	registry.Refresh(b.Context(), members)

	for _, mode := range []string{"destination-aware", "adaptive", "adaptive-warm"} {
		b.Run(mode, func(b *testing.B) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			addr := ln.Addr().String()
			_ = ln.Close()
			router := egressrouter.New(registry.Candidate)
			defer router.Close()
			warm := mode == "adaptive-warm"
			selection := mode
			if warm {
				selection = "adaptive"
			}
			if err := router.Apply(egressrouter.Config{Enabled: true, Listen: addr, Egress: egressrouter.Membership{
				Members: members, Selection: selection,
			}, Failover: egressrouter.Failover{WarmService: warm}}, nil); err != nil {
				b.Fatal(err)
			}
			dial := proxyBenchmarkDial(b, addr)
			for range 2 {
				conn, err := dial(b.Context(), "tcp", fixture.tcpTarget)
				if err != nil {
					b.Fatal(err)
				}
				_ = conn.Close()
			}
			benchmarkEgressSetup(b, fixture.tcpTarget, dial, 300*time.Millisecond)
			hits := router.Status().WarmHits
			b.ReportMetric(float64(hits)/float64(b.N), "warm-hits/op")
			if warm && hits == 0 {
				b.Fatal("no service preparations were reused")
			}
		})
	}
}

// BenchmarkSmartProxyAdaptiveFanout holds the requested number of routed TCP
// connections open and validates echo while all sockets remain live.
func BenchmarkSmartProxyAdaptiveFanout(b *testing.B) {
	for _, count := range []int{100, 500, 1000, egressrouter.MaxConnections, 10000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			groupCount := (count + egressrouter.MaxConnections - 1) / egressrouter.MaxConnections
			type fixtureGroup struct {
				name   string
				limit  int
				target string
				dial   func(context.Context, string, string) (net.Conn, error)
			}
			groups := make([]fixtureGroup, groupCount)
			owners := make(map[egressrouter.MemberID]*Connection, groupCount)
			var config egressrouter.Config
			for i := range groups {
				fixture := newReconnectFixture(b)
				startEgressServer(fixture, "direct-udp", false, false)
				owner := fixture.connect()
				testEgressInternalDial(b, owner, fixture.tcpTarget)
				member := egressrouter.Member{ProfileID: fmt.Sprintf("profile%d", i), Tunnel: "internet", ExpectedServer: fixture.http.URL}
				owners[member.ID()] = owner
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					b.Fatal(err)
				}
				addr := ln.Addr().String()
				_ = ln.Close()
				limit := (count + groupCount - 1 - i) / groupCount
				group := egressrouter.Config{Enabled: true, Listen: addr, Egress: egressrouter.Membership{
					Members: []egressrouter.Member{member}, Selection: "adaptive",
				}, Limits: egressrouter.Limits{Connections: limit, ConcurrentAttempts: 128}}
				name := "default"
				if i == 0 {
					config = group
					config.Groups = make(map[string]egressrouter.Config, groupCount-1)
				} else {
					name = fmt.Sprintf("group%d", i)
					config.Groups[name] = group
				}
				groups[i] = fixtureGroup{name: name, limit: limit, target: fixture.tcpTarget, dial: proxyBenchmarkDial(b, addr)}
			}
			routers := egressrouter.NewGroupSet(func(member egressrouter.Member) egressrouter.Candidate {
				return owners[member.ID()].EgressCandidate(member)
			})
			defer routers.Close()
			if err := routers.Apply(config, nil); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				func() {
					ctx, cancel := context.WithTimeout(b.Context(), 30*time.Second)
					defer cancel()
					conns := make([]net.Conn, count)
					defer func() {
						for _, conn := range conns {
							if conn != nil {
								_ = conn.Close()
							}
						}
					}()
					var setupErr error
					var recordFailure sync.Once
					var wg sync.WaitGroup
					for worker := range 32 {
						wg.Go(func() {
							for i := worker; i < count; i += 32 {
								group := groups[i%groupCount]
								conn, err := group.dial(ctx, "tcp", group.target)
								if err != nil {
									recordFailure.Do(func() {
										setupErr = fmt.Errorf("connection %d/%d in %s: %w", i+1, count, group.name, err)
										cancel()
									})
									return
								}
								conns[i] = conn
							}
						})
					}
					wg.Wait()
					if setupErr != nil {
						b.Fatal(setupErr)
					}
					for _, group := range groups {
						status, _, ok := routers.Group(group.name)
						if !ok || status.Active != int64(group.limit) {
							b.Fatalf("group %s active connections = %d, want %d", group.name, status.Active, group.limit)
						}
					}
					for i, conn := range conns {
						if conn == nil {
							b.Fatalf("connection %d was not opened", i+1)
						}
						_ = conn.SetDeadline(time.Now().Add(time.Second))
						if _, err := conn.Write([]byte{'x'}); err != nil {
							b.Fatal(err)
						}
						var reply [1]byte
						if _, err := io.ReadFull(conn, reply[:]); err != nil || reply[0] != 'x' {
							b.Fatalf("connection %d echo = %q: %v", i+1, reply, err)
						}
					}
				}()
			}
		})
	}
}

func benchmarkEgressSetup(b *testing.B, origin string, dial func(context.Context, string, string) (net.Conn, error), idle ...time.Duration) {
	b.ReportAllocs()
	var setup, ttfb []int64
	var payload [1024]byte
	var reply [1024]byte
	for b.Loop() {
		if len(idle) != 0 {
			b.StopTimer()
			time.Sleep(idle[0])
			b.StartTimer()
		}
		ctx, cancel := context.WithTimeout(b.Context(), 10*time.Second)
		start := time.Now()
		conn, err := dial(ctx, "tcp", origin)
		established := time.Since(start)
		cancel()
		if err != nil {
			b.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = conn.Write(payload[:]); err != nil {
			conn.Close()
			b.Fatal(err)
		}
		if _, err = io.ReadFull(conn, reply[:1]); err != nil {
			conn.Close()
			b.Fatal(err)
		}
		firstByte := time.Since(start)
		if _, err = io.ReadFull(conn, reply[1:]); err != nil {
			conn.Close()
			b.Fatal(err)
		}
		_ = conn.Close()
		// Keep a bounded sample so long benchmark runs do not retain every dial.
		if len(setup) < 4096 {
			setup = append(setup, established.Nanoseconds())
			ttfb = append(ttfb, firstByte.Nanoseconds())
		}
	}
	b.SetBytes(int64(len(payload) * 2))
	for _, sample := range []struct {
		name string
		data []int64
	}{{"setup", setup}, {"ttfb", ttfb}} {
		sort.Slice(sample.data, func(i, j int) bool { return sample.data[i] < sample.data[j] })
		for _, p := range []struct {
			name    string
			percent int
		}{{"p50", 50}, {"p95", 95}, {"p99", 99}} {
			b.ReportMetric(float64(sample.data[(len(sample.data)-1)*p.percent/100])/1e6, sample.name+"-"+p.name+"-ms")
		}
	}
}
