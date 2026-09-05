package socks

import (
	"net/netip"
	"testing"
)

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
