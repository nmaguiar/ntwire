package egressrouter

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/asn"
	"github.com/nmaguiar/ntwire/pkg/socks"
)

func sampleASN(t testing.TB) *asnData {
	t.Helper()
	var body bytes.Buffer
	gz := gzip.NewWriter(&body)
	_, _ = io.WriteString(gz, `[{"a":13335,"s":16843008,"e":16843263},{"a":15169,"s":134744064,"e":134744319}]`)
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	index, err := asn.Decode(&body, true)
	if err != nil {
		t.Fatal(err)
	}
	return &asnData{index: index, updated: time.Now()}
}

func TestSplitRoutingDecisions(t *testing.T) {
	id := MemberID{ProfileID: "a", Tunnel: "internet"}
	config, err := (Config{Egress: Membership{Members: []Member{{ProfileID: id.ProfileID, Tunnel: id.Tunnel, ExpectedServer: "fixture.example"}}}, Routing: Routing{
		Unmatched: "direct", Rules: []Rule{
			{Suffixes: []string{"internal.invalid"}, Members: []MemberID{id}},
			{ASNs: []uint32{13335, 15169}, Ports: []uint16{443}, Action: Deny},
			{CIDRs: []string{"192.168.1.0/24"}, Action: Direct},
		},
	}}).Normalized()
	if err != nil {
		t.Fatal(err)
	}
	db := &asnDatabase{config: ASNDatabaseConfig{MaxAge: time.Hour}}
	now := time.Now()
	data := sampleASN(t)
	db.data.Store(data)
	state := &routeState{config: config, asn: db}
	tests := []struct {
		name, target string
		data         *asnData
		now          time.Time
		action       Action
		reason       string
	}{
		{"hostname chooses named member", "db.internal.invalid:443", nil, now, Proxy, ""},
		{"first ASN", "1.1.1.1:443", data, now, Deny, ""},
		{"second ASN", "8.8.8.8:443", data, now, Deny, ""},
		{"mapped ASN", "[::ffff:1.1.1.1]:443", data, now, Deny, ""},
		{"port skips ASN", "1.1.1.1:80", nil, now, Direct, ""},
		{"unmapped fails closed", "2.2.2.2:443", data, now, Indeterminate, "asn_unmapped"},
		{"unsupported fails closed", "[2606:4700::1]:443", data, now, Indeterminate, "asn_unsupported_family"},
		{"unavailable fails closed", "1.1.1.1:443", nil, now, Indeterminate, "asn_unavailable"},
		{"stale fails closed", "1.1.1.1:443", data, now.Add(2 * time.Hour), Indeterminate, "asn_stale"},
		{"hostname unresolved", "public.invalid:443", data, now, Indeterminate, "asn_hostname_unresolved"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db.data.Store(tt.data)
			dst, err := destination(tt.target)
			if err != nil {
				t.Fatal(err)
			}
			got := state.decide(dst, dst.IP(), tt.now)
			if got.Action != tt.action || got.reason != tt.reason || got.Action == Proxy && !got.permits(id) {
				t.Fatalf("decision = %+v", got)
			}
			if dst.IP().IsValid() {
				dst.AddressType = 3
				if alternate := state.decide(dst, dst.IP(), tt.now); alternate.Action != got.Action || alternate.reason != got.reason {
					t.Fatalf("domain encoding gave %+v", alternate)
				}
			}
		})
	}
}

func TestSplitRuleConfigurationRejectsConflicts(t *testing.T) {
	for _, rule := range []Rule{
		{Action: "fallback"},
		{Action: Direct, Deny: true},
		{Action: Direct, Members: []MemberID{{ProfileID: "a"}}},
		{Action: Deny, Members: []MemberID{{ProfileID: "a"}}},
		{ASNs: []uint32{0}},
	} {
		if _, err := (Config{Routing: Routing{Rules: []Rule{rule}}}).Normalized(); err == nil {
			t.Errorf("accepted %+v", rule)
		}
	}
}

func TestSplitDirectSafety(t *testing.T) {
	local := []net.Addr{&net.IPNet{IP: net.ParseIP("192.168.1.1"), Mask: net.CIDRMask(24, 32)}}
	routing, err := normalizeRules(Routing{Unmatched: "direct", Rules: []Rule{{Action: Direct, CIDRs: []string{"192.168.1.0/24", "fd00::/8"}}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ip string
		ok bool
	}{
		{"1.1.1.1", true}, {"2606:4700::1", true}, {"192.168.1.5", true}, {"fd00::1", true},
		{"192.168.2.5", false}, {"192.168.1.1", false}, {"192.168.1.255", false}, {"fd00:ec2::254", false},
		{"::ffff:127.0.0.1", false}, {"169.254.169.254", false}, {"64:ff9b::7f00:1", false}, {"2002:7f00:1::", false},
		{"0.0.0.0", false}, {"224.0.0.1", false}, {"100.100.100.200", false},
	} {
		ip := netip.MustParseAddr(tc.ip).Unmap()
		dst, _ := destination(netip.AddrPortFrom(ip, 443).String())
		if got := directIPAllowed(ip, routing.decide(dst, ip, unavailableASN), local); got != tc.ok {
			t.Errorf("%s: got %t want %t", tc.ip, got, tc.ok)
		}
	}
}

const testPublic = "1.1.1.1"

func splitProxyConnect(ctx context.Context, addr, target string, httpProxy bool) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	if !httpProxy {
		dst, _ := destination(target)
		dst.AddressType = 3
		err = socks.ConnectDestination(ctx, conn, dst)
		if err != nil {
			_ = conn.Close()
		}
		return conn, err
	}
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if err == nil {
		var response *http.Response
		response, err = http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
		if err == nil && response.StatusCode != http.StatusOK {
			err = fmt.Errorf("status %d", response.StatusCode)
		}
	}
	if err != nil {
		_ = conn.Close()
	}
	return conn, err
}

func TestSplitDirectOnlyProxy(t *testing.T) {
	cfg := testConfig(t)
	cfg.Egress.Members = nil
	cfg.Routing.Unmatched = "direct"
	r := New(nil)
	t.Cleanup(r.Close)
	var dials, lookups atomic.Int64
	r.network.resolve = func(context.Context, string, string) ([]netip.Addr, error) {
		lookups.Add(1)
		return nil, errors.New("unexpected DNS")
	}
	r.network.dial = func(_ context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" || addr != testPublic+":443" {
			return nil, fmt.Errorf("unexpected dial %s %s", network, addr)
		}
		dials.Add(1)
		in, out := net.Pipe()
		go func() { defer out.Close(); _, _ = io.Copy(out, out) }()
		return in, nil
	}
	if err := r.Apply(cfg, nil); err != nil {
		t.Fatal(err)
	}
	for _, httpProxy := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		conn, err := splitProxyConnect(ctx, cfg.Listen, testPublic+":443", httpProxy)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, err = conn.Write([]byte("echo"))
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		var reply [4]byte
		_, err = io.ReadFull(conn, reply[:])
		_ = conn.Close()
		cancel()
		if err != nil || string(reply[:]) != "echo" {
			t.Fatalf("echo %q %v", reply, err)
		}
	}
	s := r.Status()
	if !s.NumericDomainReady || s.Direct.Successes != 2 || dials.Load() != 2 || lookups.Load() != 0 || len(s.Members) != 0 {
		t.Fatalf("status=%+v direct=%+v dials=%d lookups=%d", s, s.Direct, dials.Load(), lookups.Load())
	}
	c, err := r.dial(t.Context(), "tcp", testPublic+":443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	dst, _ := destination(testPublic + ":443")
	if !r.poolAllowed(c, dst) {
		t.Fatal("current numeric direct lease rejected")
	}
	cfg.Routing.Unmatched = "deny"
	if err := r.Apply(cfg, nil); err != nil {
		t.Fatal(err)
	}
	if r.poolAllowed(c, dst) {
		t.Fatal("old direct connection reused after reload")
	}
	if _, err := r.dial(t.Context(), "tcp", testPublic+":443"); socksCode(err) != 2 {
		t.Fatalf("after reload: %v", err)
	}
}

func TestSplitDirectNoFallbackOrUnapprovedDNS(t *testing.T) {
	cfg := testConfig(t)
	cfg.Routing = Routing{Unmatched: "direct", Rules: []Rule{{Suffixes: []string{"internal.invalid"}, Members: []MemberID{cfg.Egress.Members[0].ID()}}}}
	r := New(func(Member) Candidate {
		return Candidate{Generation: "1", Dialer: dialFunc(func(context.Context, Destination) (net.Conn, error) {
			return nil, &Failure{Class: "policy_denied", Code: 2}
		})}
	})
	defer r.Close()
	r.network.resolve = func(context.Context, string, string) ([]netip.Addr, error) {
		t.Error("corporate name crossed to local DNS")
		return nil, errors.New("unexpected lookup")
	}
	r.network.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Error("proxy denial reached the native network")
		return nil, errors.New("unexpected dial")
	}
	if err := r.Apply(cfg, nil); err != nil {
		t.Fatal(err)
	}
	_, err := r.dial(t.Context(), "tcp", "app.internal.invalid:443")
	if socksCode(err) != 2 {
		t.Fatalf("got %v", err)
	}
}

func TestSplitDirectDNSRejectsDifferentPolicyBeforeDial(t *testing.T) {
	cfg := testConfig(t)
	cfg.Routing = Routing{Unmatched: "direct", Rules: []Rule{{CIDRs: []string{"8.8.8.0/24"}, Action: Deny}}}
	r := New(nil)
	defer r.Close()
	r.network.resolve = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr(testPublic), netip.MustParseAddr("8.8.8.8")}, nil
	}
	r.network.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Error("mixed answers reached native network")
		return nil, errors.New("unexpected dial")
	}
	if err := r.Apply(cfg, nil); err != nil {
		t.Fatal(err)
	}
	_, err := r.dial(t.Context(), "tcp", "public.invalid:443")
	if socksCode(err) != 2 {
		t.Fatalf("got %v", err)
	}
}

type splitOffer struct {
	addresses []netip.Addr
	connected netip.Addr
}

func (p *splitOffer) Addresses() []netip.Addr { return p.addresses }
func (p *splitOffer) Close() error            { return nil }
func (p *splitOffer) ConnectAddress(_ context.Context, ip netip.Addr) (net.Conn, error) {
	p.connected = ip
	in, out := net.Pipe()
	_ = out.Close()
	return in, nil
}

type splitBinder struct {
	dialFunc
	offer func(Destination) (DestinationOffer, error)
}

func (b splitBinder) OfferDestination(_ context.Context, dst Destination) (DestinationOffer, error) {
	return b.offer(dst)
}

func TestSplitRemoteHostBinding(t *testing.T) {
	for _, tc := range []struct {
		name                string
		capable, eligible   bool
		answers             []string
		wantOffer, wantDial bool
	}{
		{"authorized", true, true, []string{testPublic}, true, true},
		{"unsupported", false, true, nil, false, false},
		{"resolver would disclose restricted hostname", true, false, nil, false, false},
		{"conflicting addresses", true, true, []string{testPublic, "8.8.8.8"}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t)
			id := cfg.Egress.Members[0].ID()
			target := id
			if !tc.eligible {
				target = cfg.Egress.Members[1].ID()
			}
			cfg.Routing = Routing{Unmatched: "direct", ASN: &ASNPolicy{HostnameResolution: "remote", ResolverMember: &id, Suffixes: []string{"public.invalid"}},
				Rules: []Rule{{ASNs: []uint32{13335}, Members: []MemberID{target}}}}
			offer := &splitOffer{}
			for _, raw := range tc.answers {
				offer.addresses = append(offer.addresses, netip.MustParseAddr(raw))
			}
			calls := 0
			r := New(func(m Member) Candidate {
				return Candidate{Generation: "1", DestinationBinding: tc.capable, Dialer: splitBinder{offer: func(dst Destination) (DestinationOffer, error) {
					calls++
					if m.ID() != id || !strings.EqualFold(dst.Host, "name.public.invalid") {
						t.Errorf("disclosure to %v for %+v", m.ID(), dst)
					}
					return offer, nil
				}}}
			})
			defer r.Close()
			r.network.resolve = func(context.Context, string, string) ([]netip.Addr, error) {
				t.Error("remote classification used local DNS")
				return nil, errors.New("lookup")
			}
			normalized, err := cfg.Normalized()
			if err != nil {
				t.Fatal(err)
			}
			r.asnShared = &asnDatabase{config: ASNDatabaseConfig{MaxAge: time.Hour}}
			r.asnShared.data.Store(sampleASN(t))
			r.commit(normalized, nil)
			conn, err := r.dial(t.Context(), "tcp", "name.public.invalid:443")
			if conn != nil {
				_ = conn.Close()
			}
			if (err == nil) != tc.wantDial || offer.connected.IsValid() != tc.wantDial || (calls == 1) != tc.wantOffer {
				t.Fatalf("err=%v calls=%d selected=%v", err, calls, offer.connected)
			}
		})
	}
}

func BenchmarkSplitRuleDecision(b *testing.B) {
	dst, _ := destination(testPublic + ":443")
	data := sampleASN(b)
	lookup := func(ip netip.Addr) (uint32, string) { number, _ := data.index.Lookup(ip); return number, "" }
	for _, tc := range []struct {
		name string
		rule Rule
	}{
		{"without_asn", Rule{CIDRs: []string{"1.1.1.0/24"}, Ports: []uint16{443}, Action: Direct}},
		{"with_asn", Rule{CIDRs: []string{"1.1.1.0/24"}, Ports: []uint16{443}, ASNs: []uint32{13335}, Action: Direct}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			routing, _ := normalizeRules(Routing{Rules: []Rule{tc.rule}}, nil)
			b.ReportAllocs()
			for b.Loop() {
				_ = routing.decide(dst, dst.IP(), lookup)
			}
		})
	}
	b.Run("lookup", func(b *testing.B) {
		ip := dst.IP()
		b.ReportAllocs()
		for b.Loop() {
			_, _ = data.index.Lookup(ip)
		}
	})
}

type splitUDPEgress struct{ calls *atomic.Int64 }

func (e splitUDPEgress) DialDestination(context.Context, Destination) (net.Conn, error) {
	return nil, errors.New("unexpected TCP")
}
func (e splitUDPEgress) AssociateUDP(context.Context) (net.Conn, error) {
	e.calls.Add(1)
	in, out := net.Pipe()
	go func() { defer out.Close(); _, _ = io.Copy(out, out) }()
	return in, nil
}

func TestSplitMixedUDP(t *testing.T) {
	origin, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	go func() {
		var b [256]byte
		for {
			n, addr, err := origin.ReadFrom(b[:])
			if err != nil {
				return
			}
			_, _ = origin.WriteTo(b[:n], addr)
		}
	}()
	cfg := testConfig(t)
	cfg.Routing = Routing{UDPAssociate: true, Rules: []Rule{
		{CIDRs: []string{"1.1.1.0/24"}, Action: Direct},
		{CIDRs: []string{"8.8.8.0/24"}, Members: []MemberID{cfg.Egress.Members[0].ID()}},
	}}
	var native, proxy atomic.Int64
	r := New(func(Member) Candidate {
		return Candidate{UDP: true, Generation: "1", Dialer: splitUDPEgress{calls: &proxy}}
	})
	defer r.Close()
	r.network.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network != "udp" || addr != "1.1.1.1:443" {
			return nil, fmt.Errorf("unexpected dial %s %s", network, addr)
		}
		native.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, origin.LocalAddr().String())
	}
	if err := r.Apply(cfg, nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	control, err := (&net.Dialer{}).DialContext(ctx, "tcp", cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	relay, err := socks.Associate(ctx, control)
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(relay))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	exchange := func(conn *net.UDPConn, ip string, allowed bool) {
		t.Helper()
		frame := socks.DatagramFrame(netip.MustParseAddrPort(ip+":443"), []byte("echo"))
		if _, err := conn.Write(frame); err != nil {
			t.Fatal(err)
		}
		var reply [256]byte
		timeout := time.Second
		if !allowed {
			timeout = 40 * time.Millisecond
		}
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		n, err := conn.Read(reply[:])
		if !allowed {
			if err == nil {
				t.Fatalf("destination %s returned an unexpected reply", ip)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		dst, offset, err := socks.DatagramDestination(reply[:n])
		if err != nil || dst.Host != ip || string(reply[offset:n]) != "echo" {
			t.Fatalf("reply %v, %q, %v", dst, reply[:n], err)
		}
	}
	exchange(udp, "1.1.1.1", true)
	if proxy.Load() != 0 {
		t.Fatal("direct datagram opened a tunnel")
	}
	wrong, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(relay))
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	exchange(wrong, "8.8.8.8", false)
	if proxy.Load() != 0 {
		t.Fatal("wrong UDP source opened a tunnel")
	}
	exchange(udp, "8.8.8.8", true)
	exchange(udp, "9.9.9.9", false)
	exchange(udp, "1.1.1.1", true)
	if native.Load() != 1 || proxy.Load() != 1 {
		t.Fatalf("native %d, proxy %d", native.Load(), proxy.Load())
	}
	for {
		status := r.Status()
		if status.Direct.UDPActive == 1 && status.Direct.UDPSent == 8 && status.Direct.UDPReceived == 8 && status.Denied == 1 {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("UDP status %+v, denied %d", status.Direct, status.Denied)
		}
		time.Sleep(time.Millisecond)
	}
}

func BenchmarkSplitProxySetup(b *testing.B) {
	for _, tc := range []struct {
		name          string
		http, proxied bool
	}{
		{"direct_socks", false, false}, {"direct_http_connect", true, false}, {"proxied_socks", false, true},
	} {
		b.Run(tc.name, func(b *testing.B) {
			cfg := testConfig(b)
			echo := func() (net.Conn, error) {
				in, out := net.Pipe()
				go func() { defer out.Close(); _, _ = io.Copy(out, out) }()
				return in, nil
			}
			r := New(func(Member) Candidate {
				return Candidate{NumericDomain: true, Generation: "1", Dialer: dialFunc(func(context.Context, Destination) (net.Conn, error) { return echo() })}
			})
			defer r.Close()
			if !tc.proxied {
				cfg.Routing.Unmatched = "direct"
				cfg.Egress.Members = nil
			}
			r.network.local = func() ([]net.Addr, error) { return nil, nil }
			r.network.dial = func(context.Context, string, string) (net.Conn, error) { return echo() }
			if err := r.Apply(cfg, nil); err != nil {
				b.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(b.Context(), time.Minute)
			defer cancel()
			b.ReportAllocs()
			for b.Loop() {
				conn, err := splitProxyConnect(ctx, cfg.Listen, testPublic+":443", tc.http)
				if err != nil {
					b.Fatal(err)
				}
				_ = conn.Close()
			}
		})
	}
}

func BenchmarkSplitProxyTraffic(b *testing.B) {
	const payloadSize = 256 << 10
	for _, tc := range []struct {
		name   string
		mixed  bool
		direct bool
	}{
		{"direct", false, true}, {"proxied", false, false}, {"mixed_parallel", true, false},
	} {
		b.Run(tc.name, func(b *testing.B) {
			cfg := testConfig(b)
			cfg.Limits = Limits{Connections: 4096, ConcurrentAttempts: 1024}
			cfg.Routing.Unmatched = "allow"
			cfg.Routing.Rules = []Rule{{CIDRs: []string{"1.1.1.0/24"}, Action: Direct}}
			// Both routes use the same local echo fixture so the measurement
			// isolates the router and stream relay from transport differences.
			echo := func() (net.Conn, error) {
				in, out := net.Pipe()
				go func() { defer out.Close(); _, _ = io.Copy(out, out) }()
				return in, nil
			}
			r := New(func(Member) Candidate {
				return Candidate{NumericDomain: true, Generation: "1", Dialer: dialFunc(func(context.Context, Destination) (net.Conn, error) { return echo() })}
			})
			defer r.Close()
			r.network.local = func() ([]net.Addr, error) { return nil, nil }
			r.network.dial = func(context.Context, string, string) (net.Conn, error) { return echo() }
			if err := r.Apply(cfg, nil); err != nil {
				b.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(b.Context(), time.Minute)
			defer cancel()
			var sequence atomic.Uint64
			work := func(target string, payload []byte) error {
				conn, err := splitProxyConnect(ctx, cfg.Listen, target, false)
				if err != nil {
					return err
				}
				defer conn.Close()
				written := make(chan error, 1)
				go func() { _, err := conn.Write(payload); written <- err }()
				_, readErr := io.CopyN(io.Discard, conn, payloadSize)
				if readErr != nil {
					_ = conn.Close()
				}
				return errors.Join(readErr, <-written)
			}
			b.SetBytes(2 * payloadSize)
			b.ReportAllocs()
			if tc.mixed {
				b.ResetTimer()
				b.RunParallel(func(pb *testing.PB) {
					payload := make([]byte, payloadSize)
					for pb.Next() {
						target := "8.8.8.8:443"
						if sequence.Add(1)%2 == 0 {
							target = "1.1.1.1:443"
						}
						if err := work(target, payload); err != nil {
							b.Error(err)
							return
						}
					}
				})
				return
			}
			payload := make([]byte, payloadSize)
			target := "8.8.8.8:443"
			if tc.direct {
				target = "1.1.1.1:443"
			}
			for b.Loop() {
				if err := work(target, payload); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestSplitRefreshKeepsEstablishedTCP(t *testing.T) {
	cfg := testConfig(t)
	cfg.Egress.Members = nil
	cfg.Routing.Rules = []Rule{{ASNs: []uint32{13335}, Action: Direct}}
	cfg, err := cfg.Normalized()
	if err != nil {
		t.Fatal(err)
	}
	r := New(nil)
	defer r.Close()
	r.asnShared = &asnDatabase{config: ASNDatabaseConfig{MaxAge: time.Hour}}
	r.asnShared.data.Store(sampleASN(t))
	r.network.dial = func(context.Context, string, string) (net.Conn, error) {
		in, out := net.Pipe()
		go func() { defer out.Close(); _, _ = io.Copy(out, out) }()
		return in, nil
	}
	listener, err := r.prepare(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.commit(cfg, listener)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	target := testPublic + ":443"
	conn, err := splitProxyConnect(ctx, cfg.Listen, target, false)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	r.asnShared.data.Store(nil)
	if newer, err := splitProxyConnect(ctx, cfg.Listen, target, false); err == nil {
		_ = newer.Close()
		t.Fatal("new request skipped an unavailable ASN rule")
	}
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, err = io.WriteString(conn, "old")
	if err != nil {
		t.Fatal(err)
	}
	var reply [3]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil || string(reply[:]) != "old" {
		t.Fatalf("established echo %q, %v", reply, err)
	}
}
