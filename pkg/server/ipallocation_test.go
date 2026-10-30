package server

import (
	"log/slog"
	"net/netip"
	"testing"
	"time"
)

func TestAllocateIPPrefixBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, cidr, next string
		want             []string
	}{
		{"ipv4", "100.64.0.0/16", "", []string{"100.64.0.2", "100.64.0.3"}},
		{"subnet", "10.20.30.0/24", "", []string{"10.20.30.2", "10.20.30.3"}},
		{"wrap", "10.20.30.0/24", "10.20.30.254", []string{"10.20.30.254", "10.20.30.2"}},
		{"out_of_prefix", "100.64.0.0/16", "100.65.0.0", []string{"100.64.0.2", "100.64.0.3"}},
		{"ipv6_subnet", "fd00::1200/120", "", []string{"fd00::1202", "fd00::1203"}},
		{"ipv6_wrap", "fd00::1200/120", "fd00::12ff", []string{"fd00::12ff", "fd00::1202"}},
		{"ipv6_large", "fd00::/64", "fd00::ffff", []string{"fd00::ffff", "fd00::1:0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{}
			cfg.Network.TunnelCIDR = tc.cidr
			s := New(cfg, slog.New(slog.DiscardHandler))
			s.data = &dataPlane{serverIP: netip.MustParsePrefix(tc.cidr).Addr().Next()}
			if tc.next != "" {
				s.data.nextIP = netip.MustParseAddr(tc.next)
			}
			for _, want := range tc.want {
				got, err := s.allocateIP()
				if err != nil || got != want {
					t.Fatalf("allocateIP = %q, %v; want %q", got, err, want)
				}
				s.sessions.Create(CreateParams{TunnelIP: got, TTL: time.Hour})
			}
		})
	}
}

func TestAllocateIPExhaustionAndReuse(t *testing.T) {
	cfg := Config{}
	cfg.Network.TunnelCIDR = "10.20.30.0/30"
	s := New(cfg, slog.New(slog.DiscardHandler))
	s.data = &dataPlane{serverIP: netip.MustParseAddr("10.20.30.1")}
	ip, err := s.allocateIP()
	if err != nil || ip != "10.20.30.2" {
		t.Fatalf("first allocation = %q, %v", ip, err)
	}
	session := s.sessions.Create(CreateParams{TunnelIP: ip, TTL: time.Hour})
	if got, err := s.allocateIP(); err == nil {
		t.Fatalf("exhausted pool allocated %s", got)
	}
	s.sessions.Delete(session.Token)
	if got, err := s.allocateIP(); err != nil || got != ip {
		t.Fatalf("released address not reusable: %s, %v", got, err)
	}
	cfg.NativeWireGuard.Peers = []NativeWireGuardPeer{{TunnelIP: ip}}
	s.Config = cfg
	if got, err := s.allocateIP(); err == nil {
		t.Fatalf("reserved native address allocated: %s", got)
	}
}
