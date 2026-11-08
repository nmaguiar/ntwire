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
