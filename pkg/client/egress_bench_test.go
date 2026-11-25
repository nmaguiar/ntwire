package client

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"sort"
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

func benchmarkEgressSetup(b *testing.B, origin string, dial func(context.Context, string, string) (net.Conn, error)) {
	b.ReportAllocs()
	var setup, ttfb []int64
	var payload [1024]byte
	var reply [1024]byte
	for b.Loop() {
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
