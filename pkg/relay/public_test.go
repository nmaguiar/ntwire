package relay

import "testing"

func TestResolveTenant(t *testing.T) {
	cases := []struct {
		name     string
		sni      string
		domain   string
		wantName string
		wantOK   bool
	}{
		{"simple match", "home.relay.example.com", "relay.example.com", "home", true},
		{"nested subdomain rejected", "foo.home.relay.example.com", "relay.example.com", "", false},
		{"empty sni", "", "relay.example.com", "", false},
		{"wrong domain suffix", "home.other.com", "relay.example.com", "", false},
		{"empty label", ".relay.example.com", "relay.example.com", "", false},
		{"exact domain, no label", "relay.example.com", "relay.example.com", "", false},
		{"uppercase not normalized here (already done upstream)", "HOME.relay.example.com", "relay.example.com", "", false},
		{"invalid characters", "home_lab.relay.example.com", "relay.example.com", "", false},
		{"valid hyphenated label", "home-lab.relay.example.com", "relay.example.com", "home-lab", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name, ok := resolveTenant(tc.sni, tc.domain)
			if ok != tc.wantOK || name != tc.wantName {
				t.Fatalf("resolveTenant(%q, %q) = (%q, %v), want (%q, %v)", tc.sni, tc.domain, name, ok, tc.wantName, tc.wantOK)
			}
		})
	}
}

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(3)
	for i := 0; i < 3; i++ {
		if !rl.allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed", i)
		}
	}
	if rl.allow("1.2.3.4") {
		t.Fatal("4th request within the window should be rejected")
	}
	// A distinct source IP has its own independent bucket.
	if !rl.allow("5.6.7.8") {
		t.Fatal("a different source IP should not be affected by another IP's limit")
	}
}
