package socks

import (
	"net/netip"
	"testing"
)

type stubASN map[string]uint32

func (s stubASN) Lookup(ip netip.Addr) (uint32, bool) {
	asn, ok := s[ip.String()]
	return asn, ok
}

func addr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

func TestFilterAllowed(t *testing.T) {
	tests := []struct {
		name     string
		cfg      FilterConfig
		asns     stubASN
		hostname string
		ip       netip.Addr
		want     bool
	}{
		{
			name: "no filters, deny by default",
			cfg:  FilterConfig{},
			ip:   addr("8.8.8.8"),
			want: false,
		},
		{
			name: "no filters, allow_all opts in",
			cfg:  FilterConfig{AllowAll: true},
			ip:   addr("8.8.8.8"),
			want: true,
		},
		{
			name: "cidr allow match",
			cfg:  FilterConfig{CIDRs: []string{"10.0.0.0/8"}},
			ip:   addr("10.1.2.3"),
			want: true,
		},
		{
			name: "cidr allow miss",
			cfg:  FilterConfig{CIDRs: []string{"10.0.0.0/8"}},
			ip:   addr("192.168.1.1"),
			want: false,
		},
		{
			name: "cidr ipv6 match",
			cfg:  FilterConfig{CIDRs: []string{"fc00::/7"}},
			ip:   addr("fd00::1"),
			want: true,
		},
		{
			name: "v4-in-v6 mapped address normalizes to a plain v4 match",
			cfg:  FilterConfig{CIDRs: []string{"10.0.0.0/8"}},
			ip:   addr("::ffff:10.1.2.3"),
			want: true,
		},
		{
			name:     "domain suffix match, no cidr filters",
			cfg:      FilterConfig{DomainSuffixes: []string{".svc.cluster.local"}},
			hostname: "api.default.svc.cluster.local",
			ip:       addr("10.1.2.3"),
			want:     true,
		},
		{
			name:     "domain suffix miss, no cidr filters",
			cfg:      FilterConfig{DomainSuffixes: []string{".svc.cluster.local"}},
			hostname: "example.com",
			ip:       addr("10.1.2.3"),
			want:     false,
		},
		{
			name: "asn match",
			cfg:  FilterConfig{ASNs: []uint32{15169}},
			asns: stubASN{"8.8.8.8": 15169},
			ip:   addr("8.8.8.8"),
			want: true,
		},
		{
			name: "asn miss",
			cfg:  FilterConfig{ASNs: []uint32{15169}},
			asns: stubASN{"1.2.3.4": 64512},
			ip:   addr("1.2.3.4"),
			want: false,
		},
		{
			name:     "cidr miss vetoes domain check even if hostname matches",
			cfg:      FilterConfig{CIDRs: []string{"10.0.0.0/8"}, DomainSuffixes: []string{".example.com"}},
			hostname: "foo.example.com",
			ip:       addr("192.168.1.1"), // outside the CIDR
			want:     false,
		},
		{
			name:     "cidr hit still requires domain match to decide",
			cfg:      FilterConfig{CIDRs: []string{"10.0.0.0/8"}, DomainSuffixes: []string{".example.com"}},
			hostname: "foo.other.com", // does not match domain filter
			ip:       addr("10.1.2.3"),
			want:     false,
		},
		{
			name:     "cidr hit and domain match both required",
			cfg:      FilterConfig{CIDRs: []string{"10.0.0.0/8"}, DomainSuffixes: []string{".example.com"}},
			hostname: "foo.example.com",
			ip:       addr("10.1.2.3"),
			want:     true,
		},
		{
			name:     "asn-only plus domain filters: asn is ignored, domain decides (ported quirk)",
			cfg:      FilterConfig{ASNs: []uint32{15169}, DomainSuffixes: []string{".example.com"}},
			asns:     stubASN{"1.2.3.4": 99999}, // does not match ASN filter
			hostname: "foo.example.com",         // but domain matches
			ip:       addr("1.2.3.4"),
			want:     true, // no CIDR filters configured, so the veto never triggers
		},
		{
			name: "reverse_filters inverts an allow into a deny",
			cfg:  FilterConfig{CIDRs: []string{"10.0.0.0/8"}, Invert: true},
			ip:   addr("10.1.2.3"),
			want: false,
		},
		{
			name: "reverse_filters inverts a miss into an allow",
			cfg:  FilterConfig{CIDRs: []string{"10.0.0.0/8"}, Invert: true},
			ip:   addr("8.8.8.8"),
			want: true,
		},
		{
			name: "reverse_filters alone (no other filters) allows everything",
			cfg:  FilterConfig{Invert: true},
			ip:   addr("8.8.8.8"),
			want: true,
		},
		{
			name: "only_local allows private ipv4",
			cfg:  FilterConfig{OnlyLocal: true},
			ip:   addr("192.168.1.5"),
			want: true,
		},
		{
			name: "only_local denies public ipv4",
			cfg:  FilterConfig{OnlyLocal: true},
			ip:   addr("8.8.8.8"),
			want: false,
		},
		{
			name: "only_local ignores configured cidr/domain/asn/invert",
			cfg: FilterConfig{
				OnlyLocal:      true,
				CIDRs:          []string{"8.8.8.0/24"},
				DomainSuffixes: []string{".example.com"},
				Invert:         true,
			},
			hostname: "foo.example.com",
			ip:       addr("10.0.0.1"),
			want:     true, // matches the hardcoded private ranges, ignoring everything else
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var lookup ASNLookup
			if tt.asns != nil {
				lookup = tt.asns
			}
			f, err := NewFilter(tt.cfg, lookup)
			if err != nil {
				t.Fatalf("NewFilter: %v", err)
			}
			if got := f.Allowed(tt.hostname, tt.ip); got != tt.want {
				t.Errorf("Allowed(%q, %v) = %v, want %v", tt.hostname, tt.ip, got, tt.want)
			}
		})
	}
}

func TestNewFilterInvalidCIDR(t *testing.T) {
	if _, err := NewFilter(FilterConfig{CIDRs: []string{"not-a-cidr"}}, nil); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}
