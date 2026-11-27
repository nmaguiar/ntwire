package client

import (
	"testing"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

func TestParseTunnelMTU(t *testing.T) {
	tests := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"", 0, false},
		{" 1380 ", 1380, false},
		{"1280", 1280, false},
		{"1420", 1420, false},
		{"1279", 0, true},
		{"1421", 0, true},
		{"abc", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseTunnelMTU(tt.in)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("ParseTunnelMTU(%q) = %d, %v; want %d, err=%v", tt.in, got, err, tt.want, tt.wantErr)
		}
	}
}

func TestMultipathOptionsFor_DefaultsOff(t *testing.T) {
	if mo := multipathOptionsFor(Options{}); mo.MTUAware || mo.TunnelMTU != 0 {
		t.Fatalf("default multipath options = %+v, want opt-ins off", mo)
	}
	mo := multipathOptionsFor(Options{MTUAware: true, TunnelMTU: 1380})
	if !mo.MTUAware || mo.TunnelMTU != 1380 {
		t.Fatalf("multipath options = %+v, want MTU-aware 1380", mo)
	}
}

func TestHTTPClient_RejectsTunnelMTUOutOfRange(t *testing.T) {
	if _, err := httpClient("https://example.test", Options{TunnelMTU: 9000}); err == nil {
		t.Fatal("httpClient accepted TunnelMTU 9000")
	}
}

func TestTransportCapabilitiesFor_PromoteOnlyWhenOptedIn(t *testing.T) {
	for _, c := range transportCapabilitiesFor(Options{}) {
		if c == protocol.CapabilityPathPromoteV1 {
			t.Fatal("default options offered path-promote-v1")
		}
	}
	found := false
	for _, c := range transportCapabilitiesFor(Options{Promote: true}) {
		found = found || c == protocol.CapabilityPathPromoteV1
	}
	if !found {
		t.Fatal("Promote did not offer path-promote-v1")
	}
	// A server requiring promotion is satisfiable only by an opted-in client.
	r := protocol.AuthResponse{RequiredTransportCapabilities: []string{protocol.CapabilityPathPromoteV1}}
	if validateAuthResponseCapabilities(r, Options{}) == nil || validateAuthResponseCapabilities(r, Options{Promote: true}) != nil {
		t.Fatal("required path-promote-v1 validation does not follow Options.Promote")
	}
}

func TestTransportCapabilitiesFor_AdaptiveCarrierKeepsOperatorRestrictions(t *testing.T) {
	for _, options := range []Options{{}, {AdaptiveCarrier: true, UseWebSocket: true}, {AdaptiveCarrier: true, Insecure: true},
		{AdaptiveCarrier: true, Promote: true}, {AdaptiveCarrier: true, UDPAlt: true}, {AdaptiveCarrier: true, MTUAware: true},
		{AdaptiveCarrier: true, Transport: "direct-udp"}} {
		if hasTransportCapability(transportCapabilitiesFor(options), protocol.CapabilityAdaptiveCarrierV1) {
			t.Fatalf("adaptive offer bypassed explicit options: %+v", options)
		}
	}
	if !hasTransportCapability(transportCapabilitiesFor(Options{AdaptiveCarrier: true, Transport: "auto"}), protocol.CapabilityAdaptiveCarrierV1) {
		t.Fatal("explicit adaptive carrier opt-in was ignored")
	}
}

func TestAdaptiveUDP_ExplicitProxyAndAddressRestrictions(t *testing.T) {
	base := "https://localhost:8443"
	for _, options := range []Options{
		{AdaptiveCarrier: true, NoDirectUpgrade: true},
		{AdaptiveCarrier: true, HTTPSProxy: "http://127.0.0.1:3321", NoSystemProxy: true},
	} {
		caps := transportCapabilitiesFor(options)
		if adaptiveUDPAllowed(base, options) || hasTransportCapability(caps, protocol.CapabilityAdaptiveUDPV1) ||
			hasTransportCapability(caps, protocol.CapabilityLaneCarriersV1) || hasTransportCapability(caps, protocol.CapabilityRelayPerformanceV1) {
			t.Fatal("adaptive UDP accepted an explicit route restriction")
		}
	}
	if !adaptiveUDPAllowed(base, Options{NoSystemProxy: true}) {
		t.Fatal("direct UDP eligibility unexpectedly rejected an explicit direct route")
	}
	for _, endpoint := range []string{"example.test:443", "0.0.0.0:443", "[::]:443", "224.0.0.1:443", "127.0.0.1:0", "[fe80::1%eth0]:443"} {
		if _, ok := adaptiveUDPAddress(endpoint); ok {
			t.Fatalf("adaptive UDP accepted an invalid endpoint %q", endpoint)
		}
	}
}

func TestAdaptiveRelayPerformance_RequiresOptInAndFeedback(t *testing.T) {
	info := protocol.AdaptiveSession{ParentID: "AQAAAAAAAAAAAAAAAAAAAA", LaneID: "AgAAAAAAAAAAAAAAAAAAAA", AuthGeneration: 1,
		RelayCatalog: true, RelayUDP: true, RelaySelect: true, PathSelect: true, Performance: true, RelayPerformance: true}
	response := protocol.AuthResponse{Adaptive: &info, TransportCapabilities: info.Capabilities(), Token: "fixture-token", TTLSeconds: 60}
	options := Options{AdaptiveCarrier: true}
	if err := validateAuthResponseCapabilities(response, options); err != nil {
		t.Fatalf("valid relay performance negotiation: %v", err)
	}
	options.NoDirectUpgrade = true
	if err := validateAuthResponseCapabilities(response, options); err == nil {
		t.Fatal("accepted relay performance despite an explicit transport restriction")
	}
	options.NoDirectUpgrade = false
	info.Performance = false
	response.TransportCapabilities = info.Capabilities()
	if err := validateAuthResponseCapabilities(response, options); err == nil {
		t.Fatal("accepted relay performance without forwarding feedback")
	}
	info.RelayPerformance = false
	response.TransportCapabilities = info.Capabilities()
	if err := validateAuthResponseCapabilities(response, options); err != nil {
		t.Fatalf("old relay selection became incompatible: %v", err)
	}
}

func TestAdaptiveRelayCatalogNegotiation(t *testing.T) {
	caps := []string{protocol.CapabilityAdaptiveCarrierV1, protocol.CapabilityAdaptiveRelayCatalogV1}
	info := protocol.AdaptiveSession{ParentID: "AQAAAAAAAAAAAAAAAAAAAA", LaneID: "AgAAAAAAAAAAAAAAAAAAAA", AuthGeneration: 1, RelayCatalog: true}
	reply := protocol.AuthResponse{Adaptive: &info, TransportCapabilities: caps, Token: "fixture", TTLSeconds: 60}
	optedIn := Options{AdaptiveCarrier: true}
	if err := validateAuthResponseCapabilities(reply, optedIn); err != nil {
		t.Fatal(err)
	}
	restricted := optedIn
	restricted.HTTPSProxy = "http://127.0.0.1:8080"
	if err := validateAuthResponseCapabilities(reply, restricted); err == nil {
		t.Fatal("accepted unsolicited relay catalog")
	}
	info.RelayCatalog = false
	if err := validateAuthResponseCapabilities(reply, optedIn); err == nil {
		t.Fatal("accepted inconsistent relay catalog metadata")
	}
	reply.TransportCapabilities = caps[:1]
	if err := validateAuthResponseCapabilities(reply, optedIn); err != nil {
		t.Fatalf("server without relay catalog should remain compatible: %v", err)
	}
}
