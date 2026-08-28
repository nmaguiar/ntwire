package protocol

import (
	"encoding/json"
	"testing"
)

func TestCapabilityCompatibilityMatrix(t *testing.T) {
	tests := []struct {
		name      string
		offer     []string
		supported []string
		required  []string
		want      []string
		wantErr   bool
	}{
		{"old peer omits capabilities", nil, []string{CapabilityMultipathV3}, nil, nil, false},
		{"new peer's unknown optional capability is ignored", []string{CapabilityMultipathV3, "future-transport"}, []string{CapabilityMultipathV3}, nil, []string{CapabilityMultipathV3}, false},
		{"v3 peers negotiate complete transport", []string{CapabilityMultipathV3, CapabilityPathMTUV1}, []string{CapabilityMultipathV3, CapabilityPathMTUV1}, []string{CapabilityMultipathV3}, []string{CapabilityMultipathV3, CapabilityPathMTUV1}, false},
		{"retired tiers do not negotiate with v3", []string{CapabilityMultipathV1, CapabilityMultipathV2}, []string{CapabilityMultipathV3}, nil, nil, false},
		{"required unsupported transport fails early", []string{CapabilityMultipathV3}, []string{CapabilityMultipathV3}, []string{CapabilityPathMTUV1}, []string{CapabilityMultipathV3}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateRequiredCapabilities(tt.supported, tt.required); (err != nil) != tt.wantErr {
				t.Fatalf("ValidateRequiredCapabilities() error = %v, want error = %t", err, tt.wantErr)
			}
			got := IntersectCapabilities(tt.offer, tt.supported)
			if len(got) != len(tt.want) {
				t.Fatalf("IntersectCapabilities() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("IntersectCapabilities() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestCapabilityFieldsRemainWireCompatible(t *testing.T) {
	// Old peers neither send nor expect these additive fields.
	legacy := []byte(`{"version":1,"transport_capabilities":["future-transport"]}`)
	var auth AuthRequest
	if err := json.Unmarshal(legacy, &auth); err != nil {
		t.Fatal(err)
	}
	if len(auth.RequiredTransportCapabilities) != 0 {
		t.Fatalf("legacy request unexpectedly has required capabilities: %v", auth.RequiredTransportCapabilities)
	}

	b, err := json.Marshal(RelayRegisterRequest{Version: Version, Name: "home"})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"version":1,"public_key":"","name":"home","timestamp":"","nonce":"","signature":""}` {
		t.Fatalf("new optional fields changed legacy relay JSON: %s", b)
	}

	var info InfoResponse
	if err := json.Unmarshal([]byte(`{"version":1,"capabilities":["tcp"],"required_capabilities":["future-client"]}`), &info); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRequiredCapabilities(clientTestCapabilities(), info.RequiredCapabilities); err == nil {
		t.Fatal("required unknown capability should not be silently ignored")
	}
}

func clientTestCapabilities() []string { return []string{CapabilityMultipathV3, CapabilityPathMTUV1} }
