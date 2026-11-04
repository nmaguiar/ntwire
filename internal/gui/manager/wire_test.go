package manager

import (
	"encoding/json"
	"github.com/nmaguiar/ntwire/pkg/client"
	"strings"
	"testing"

	"github.com/nmaguiar/ntwire/internal/gui/config"
)

// TestPromptJSONWireFormat locks in the exact JSON shape the settings
// window's JS reads (internal/gui/webui/static/index.html's renderPrompts/
// trustModal/passphraseModal) -- Prompt.Kind's missing json tag was found
// by reading the struct, not by any test, and nothing previously verified
// the other four keys either. A silently wrong tag here means the wrong
// modal renders (or none does) and a real connect attempt sits until
// promptTimeout kills it, five minutes later, with an error that names
// nothing about why.
func TestPromptJSONWireFormat(t *testing.T) {
	trust := Snapshot{
		Profile: config.Profile{ID: "p1", Name: "home"},
		State:   StateAwaitingTrust,
		Prompt: &Prompt{
			Kind:        PromptTrust,
			Host:        "relay.example.com",
			Fingerprint: "SHA256:abc123",
			Previous:    "SHA256:def456",
		},
	}
	assertJSONKeys(t, trust.Prompt, map[string]any{
		"kind":        "trust",
		"host":        "relay.example.com",
		"fingerprint": "SHA256:abc123",
		"previous":    "SHA256:def456",
	})

	passphrase := Snapshot{
		Profile: config.Profile{ID: "p2", Name: "office"},
		State:   StateAwaitingPassphrase,
		Prompt: &Prompt{
			Kind:    PromptPassphrase,
			KeyPath: "/home/user/.ntwire/id_ed25519",
		},
	}
	assertJSONKeys(t, passphrase.Prompt, map[string]any{
		"kind":     "passphrase",
		"key_path": "/home/user/.ntwire/id_ed25519",
	})
}

func assertJSONKeys(t *testing.T, p *Prompt, want map[string]any) {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("keys = %v, want exactly %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("key %q = %v, want %v", k, got[k], v)
		}
	}
}

// TestSnapshotJSONHasLowercaseStateKey guards the field renderProfileRow
// and renderPrompts both key every render off of.
func TestSnapshotJSONHasLowercaseStateKey(t *testing.T) {
	snap := Snapshot{Profile: config.Profile{ID: "p1"}, State: StateConnected}
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if got["state"] != "connected" {
		t.Errorf(`snapshot JSON["state"] = %v, want "connected"`, got["state"])
	}
}

func TestCertificatePromptMetadataJSON(t *testing.T) {
	prompt := Prompt{Kind: PromptTrust, Host: "example.test", Fingerprint: "SHA256:new", Previous: "SHA256:old",
		Certificate: &client.CertificateDetails{Subject: "<script>alert(1)</script>", Issuer: "CN=Netskope CA", SHA256Fingerprint: "SHA256:new"},
		Assessment:  &client.CertificateAssessment{Status: "possible_interception", Warnings: []string{"Possible enterprise TLS inspection"}},
	}
	data, err := json.Marshal(prompt)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["kind"] != "trust" || decoded["previous"] != "SHA256:old" || decoded["assessment"].(map[string]any)["status"] != "possible_interception" || decoded["certificate"].(map[string]any)["subject"] != prompt.Certificate.Subject {
		t.Fatalf("metadata lost: %s", data)
	}
	if strings.Contains(string(data), "<script>") {
		t.Fatal("JSON did not escape HTML")
	}
}
