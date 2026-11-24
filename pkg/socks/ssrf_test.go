package socks

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
)

type recordedSocksConn struct {
	fuzzConn
	reply bytes.Buffer
}

func (c *recordedSocksConn) Write(b []byte) (int, error) { return c.reply.Write(b) }

type numericTestASN struct{}

func (numericTestASN) Lookup(ip netip.Addr) (uint32, bool) {
	return 64512, ip.Is4() && ip == netip.MustParseAddr("203.0.113.7")
}

func TestSOCKS5NumericDestinationPolicies(t *testing.T) {
	for _, tc := range []struct {
		name, ip string
		filter   FilterConfig
		binary   bool
		domain   bool
	}{
		{"CIDR allows", "203.0.113.7", FilterConfig{CIDRs: []string{"203.0.113.0/24"}}, true, true},
		{"CIDR denies", "203.0.113.7", FilterConfig{CIDRs: []string{"198.51.100.0/24"}}, false, false},
		{"IPv6 CIDR", "2001:db8::7", FilterConfig{CIDRs: []string{"2001:db8::/32"}}, true, true},
		{"mapped IPv4 CIDR", "::ffff:203.0.113.7", FilterConfig{CIDRs: []string{"203.0.113.0/24"}}, true, true},
		{"inverted CIDR", "::ffff:203.0.113.7", FilterConfig{CIDRs: []string{"203.0.113.0/24"}, Invert: true}, false, false},
		{"hostname required", "203.0.113.7", FilterConfig{DomainSuffixes: []string{".test"}}, false, false},
		{"literal suffix cannot grant", "203.0.113.7", FilterConfig{DomainSuffixes: []string{".113.7"}}, false, false},
		{"conversion cannot evade inverted suffix", "2001:db8::7", FilterConfig{DomainSuffixes: []string{"::7"}, Invert: true}, true, false},
		{"inverted hostname suffix", "203.0.113.7", FilterConfig{DomainSuffixes: []string{".test"}, Invert: true}, true, true},
		{"ASN allows mapped", "::ffff:203.0.113.7", FilterConfig{ASNs: []uint32{64512}}, true, true},
		{"ASN denies", "203.0.113.7", FilterConfig{ASNs: []uint32{64513}}, false, false},
		{"inverted ASN", "203.0.113.7", FilterConfig{ASNs: []uint32{64512}, Invert: true}, false, false},
		{"private allow", "10.1.2.3", FilterConfig{OnlyLocal: true}, true, true},
		{"private deny", "10.1.2.3", FilterConfig{CIDRs: []string{"10.0.0.0/8"}, Invert: true}, false, false},
		{"mapped loopback floor", "::ffff:127.0.0.1", FilterConfig{AllowAll: true}, false, false},
		{"IPv6 loopback floor", "::1", FilterConfig{Invert: true}, false, false},
		{"metadata floor", "169.254.169.254", FilterConfig{AllowAll: true}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var dns atomic.Int32
			var target string
			s, err := New(Config{Filter: tc.filter, ASNLookup: numericTestASN{},
				Logger: slog.New(slog.DiscardHandler),
				Resolver: &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
					dns.Add(1)
					return nil, errors.New("DNS not expected")
				}},
				Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
					target = addr
					return nil, errors.New("test does not dial")
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			ip := netip.MustParseAddr(tc.ip)
			kind := byte(socks5AtypIPv6)
			if ip.Is4() {
				kind = socks5AtypIPv4
			}
			for _, test := range []struct {
				kind byte
				want bool
			}{{kind, tc.binary}, {socks5AtypDomain, tc.domain}} {
				target = ""
				input := clientRequestBytes(test.kind, tc.ip, 443)
				c := &recordedSocksConn{fuzzConn: fuzzConn{bytes.NewReader(input)}}
				s.ServeConn(t.Context(), c)
				wantCode := byte(socks5RepNotAllowed)
				if test.want {
					wantCode = socks5RepGeneralFailure // the fake dialer refused it
				}
				reply := c.reply.Bytes()
				if len(reply) != 12 || reply[3] != wantCode || (target != "") != test.want {
					t.Errorf("type %d, reply %x target %q, want code %d", test.kind, reply, target, wantCode)
				}
				if test.want && target != netip.AddrPortFrom(ip.Unmap(), 443).String() {
					t.Errorf("dialed %q instead of the authorized address", target)
				}
			}
			if dns.Load() != 0 {
				t.Fatal("numeric request caused DNS traffic")
			}
		})
	}
}

// localDestinations are the addresses no requester-chosen SOCKS destination may
// reach by default: they are trusted for the server's own network position, not
// the requester's. 169.254.169.254 is the cloud instance metadata endpoint.
var localDestinations = []string{
	"127.0.0.1",
	"127.1.2.3",
	"::1",
	"::ffff:127.0.0.1",
	"169.254.169.254",
	"fe80::1",
	"0.0.0.0",
	"::",
	"ff02::1",
}

// TestFilterDeniesLocalDestinations is the regression test for the missing SSRF
// floor: allow_all (and any filter set written with only external destinations
// in mind) previously let an authenticated session use the server as a request
// forgery primitive against its own loopback and metadata endpoint.
func TestFilterDeniesLocalDestinations(t *testing.T) {
	configs := map[string]FilterConfig{
		"allow_all":          {AllowAll: true},
		"broad cidr":         {CIDRs: []string{"0.0.0.0/0", "::/0"}},
		"inverted deny list": {CIDRs: []string{"198.51.100.0/24"}, Invert: true},
		"only_local":         {OnlyLocal: true},
	}
	for name, cfg := range configs {
		f, err := NewFilter(cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, dest := range localDestinations {
			ip := netip.MustParseAddr(dest)
			if f.Allowed("", ip) {
				t.Errorf("%s: destination %s should be denied by default", name, dest)
			}
		}
	}
}

// TestFilterAllowLocalEgressOptsBackIn covers the deliberate override, for the
// legitimate "proxy to a service on the server host" case.
func TestFilterAllowLocalEgressOptsBackIn(t *testing.T) {
	f, err := NewFilter(FilterConfig{AllowAll: true, AllowLocalEgress: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, dest := range []string{"127.0.0.1", "::1", "169.254.169.254"} {
		if !f.Allowed("", netip.MustParseAddr(dest)) {
			t.Errorf("allow_local_egress should permit %s", dest)
		}
	}
}

// TestFilterStillAllowsOrdinaryDestinations guards against the floor being
// over-broad: it must not touch ordinary public or private destinations.
func TestFilterStillAllowsOrdinaryDestinations(t *testing.T) {
	f, err := NewFilter(FilterConfig{AllowAll: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, dest := range []string{"93.184.216.34", "10.1.2.3", "192.168.1.10", "2606:4700::1111"} {
		if !f.Allowed("", netip.MustParseAddr(dest)) {
			t.Errorf("%s should still be allowed", dest)
		}
	}
	local, err := NewFilter(FilterConfig{OnlyLocal: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !local.Allowed("", netip.MustParseAddr("10.1.2.3")) {
		t.Error("only_local should still allow RFC1918 destinations")
	}
}
