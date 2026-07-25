package relay

import (
	"os"
	"testing"
)

// writeRelayConfig writes a minimal valid relay config with the given
// domain and registration name substituted in, using a freshly generated
// key so public_key parsing always succeeds independent of what's under
// test.
func writeRelayConfig(t *testing.T, domain, name string) string {
	t.Helper()
	k := generateTestKey(t)
	path := t.TempDir() + "/relay.yaml"
	content := "domain: " + domain + "\n" +
		"registrations:\n" +
		"  - name: " + name + "\n" +
		"    public_key: \"" + k.line + "\"\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLoadConfig_RejectsMalformedRegistrationNames is the regression test
// for LoadConfig accepting registration names that resolveTenant
// (public.go) can never match: a name failing validLabel's
// lowercase-[a-z0-9-]+ check loads successfully, registers successfully,
// and then every client connection for it silently resets with nothing
// logged to explain why.
func TestLoadConfig_RejectsMalformedRegistrationNames(t *testing.T) {
	cases := []struct {
		name    string
		regName string
		wantErr bool
	}{
		{"valid lowercase", "home", false},
		{"valid hyphenated", "home-lab", false},
		{"uppercase rejected", "My-Home", true},
		{"underscore rejected", "home_lab", true},
		{"dotted rejected", "home.lab", true},
		{"empty rejected", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// regName=="" is rejected by LoadConfig's pre-existing
			// "requires name and public_key" check, before validLabel ever
			// runs (validLabel itself only judges character validity; it
			// doesn't special-case emptiness, since resolveTenant checks
			// that separately).
			path := writeRelayConfig(t, "relay.example.com", tc.regName)
			_, err := LoadConfig(path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("LoadConfig with registration name %q: err = %v, wantErr = %v", tc.regName, err, tc.wantErr)
			}
		})
	}
}

// TestLoadConfig_NormalizesAndValidatesDomain is the regression test for
// LoadConfig accepting a domain resolveTenant can never match: it compares
// the ClientHello SNI (already lowercased by peekClientHello) against
// c.Domain with a case-sensitive suffix match, so an un-normalized domain
// silently resets every client connection.
func TestLoadConfig_NormalizesAndValidatesDomain(t *testing.T) {
	cases := []struct {
		name       string
		domain     string
		wantErr    bool
		wantDomain string
	}{
		{"already lowercase", "relay.example.com", false, "relay.example.com"},
		{"mixed case normalized", "Relay.Example.COM", false, "relay.example.com"},
		{"trailing dot trimmed", "relay.example.com.", false, "relay.example.com"},
		{"empty rejected", "", true, ""},
		{"leading dot rejected", ".relay.example.com", true, ""},
		{"double dot rejected", "relay..example.com", true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.domain == "" {
				// domain=="" is already rejected earlier by LoadConfig's
				// "domain is required" check, before normalization runs.
				k := generateTestKey(t)
				path := t.TempDir() + "/relay.yaml"
				content := "registrations:\n  - name: home\n    public_key: \"" + k.line + "\"\n"
				if err := os.WriteFile(path, []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := LoadConfig(path); err == nil {
					t.Fatal("expected an empty domain to be rejected")
				}
				return
			}
			path := writeRelayConfig(t, tc.domain, "home")
			cfg, err := LoadConfig(path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("LoadConfig with domain %q: err = %v, wantErr = %v", tc.domain, err, tc.wantErr)
			}
			if err == nil && cfg.Domain != tc.wantDomain {
				t.Fatalf("normalized domain = %q, want %q", cfg.Domain, tc.wantDomain)
			}
		})
	}
}
