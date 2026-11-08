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
	if o.UDPAlt || o.MTUAware || o.TunnelMTU != 0 {
		t.Fatalf("default profile enabled opt-in transport options: %+v", o)
	}
	b, err := yaml.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "udp_alt") || strings.Contains(string(b), "mtu") {
		t.Fatalf("default profile YAML contains opt-in keys:\n%s", b)
	}
}

func TestProfileTransportOptIns_RoundTripAndMapping(t *testing.T) {
	in := Profile{Name: "home-lab", UDPAlt: true, MTUAware: true, TunnelMTU: "1380"}
	b, err := yaml.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Profile
	if err := yaml.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if !out.UDPAlt || !out.MTUAware || out.TunnelMTU != "1380" {
		t.Fatalf("round trip lost opt-in settings: %+v\n%s", out, b)
	}
	o, err := out.ToClientOptions("/tmp/status.json", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !o.UDPAlt || !o.MTUAware || o.TunnelMTU != 1380 {
		t.Fatalf("ToClientOptions did not map opt-in settings: %+v", o)
	}
}

func TestProfileTunnelMTU_InvalidRejected(t *testing.T) {
	p := Profile{Name: "home-lab", TunnelMTU: "9000"}
	if _, err := p.ToClientOptions("/tmp/status.json", "", ""); err == nil {
		t.Fatal("ToClientOptions accepted tunnel MTU 9000")
	}
}
