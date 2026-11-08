package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestProfileTransportOptIns_DefaultOffAndOmitted checks the opt-in advanced
// transport settings are off for a new profile and are not written to
// gui.yaml until enabled, so existing profiles stay byte-identical.
func TestProfileTransportOptIns_DefaultOffAndOmitted(t *testing.T) {
	p := Profile{Name: "home-lab"}
	o, err := p.ToClientOptions("/tmp/status.json", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if o.UDPAlt {
		t.Fatalf("default profile enabled opt-in transport options: %+v", o)
	}
	b, err := yaml.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "udp_alt") {
		t.Fatalf("default profile YAML contains opt-in keys:\n%s", b)
	}
}

func TestProfileTransportOptIns_RoundTripAndMapping(t *testing.T) {
	in := Profile{Name: "home-lab", UDPAlt: true}
	b, err := yaml.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Profile
	if err := yaml.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if !out.UDPAlt {
		t.Fatalf("round trip lost opt-in settings: %+v\n%s", out, b)
	}
	o, err := out.ToClientOptions("/tmp/status.json", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !o.UDPAlt {
		t.Fatalf("ToClientOptions did not map opt-in settings: %+v", o)
	}
}
