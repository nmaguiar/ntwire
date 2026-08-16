package server

import (
	"reflect"
	"testing"
)

func TestSecurityCapabilitiesReportsOnlyExplicitOptIns(t *testing.T) {
	cfg := Config{
		Authorizer: AuthorizerConfig{WebhookURL: "https://auth.example.test/allow"},
		Relay:      RelayConfig{Enabled: true, AdvertiseDirect: true},
		Tunnels: []TunnelConfig{
			{Name: "restricted", Target: "socks", Socks: &SocksConfig{}},
			{Name: "egress", Target: "socks", Socks: &SocksConfig{AllowAll: true, AllowBind: true}},
		},
	}
	want := []string{"authorization_hook", "direct_udp_relay_bypass", "relay_mediated_udp", "socks_bind", "socks_unrestricted"}
	if got := securityCapabilities(cfg); !reflect.DeepEqual(got, want) {
		t.Fatalf("securityCapabilities() = %v, want %v", got, want)
	}
}

func TestSecurityCapabilitiesOmitsDefaultsAndInvalidDirectOptIn(t *testing.T) {
	if got := securityCapabilities(Config{Relay: RelayConfig{AdvertiseDirect: true}}); len(got) != 0 {
		t.Fatalf("securityCapabilities() = %v, want no capability for an invalid relay-less direct opt-in", got)
	}
}
