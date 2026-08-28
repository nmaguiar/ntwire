package relay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigGuide_EmbedsSampleAndStrictSchema(t *testing.T) {
	guide, err := ConfigGuide()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(guide, "```yaml\n"+SampleConfig()+"```") {
		t.Fatal("guide does not embed SampleConfig verbatim")
	}
	checkedIn, err := os.ReadFile(filepath.Join("..", "..", "docs", "RELAY-CONFIG-GUIDE.md"))
	if err != nil || string(checkedIn) != guide {
		t.Fatalf("checked-in guide differs from renderer: %v", err)
	}
	schema, err := ConfigJSONSchema()
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(schema, &decoded); err != nil {
		t.Fatalf("invalid JSON Schema: %v", err)
	}
	if decoded["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("schema draft = %v", decoded["$schema"])
	}
}

func TestLoadConfig_RejectsUnknownFields(t *testing.T) {
	k := generateTestKey(t)
	for _, text := range []string{
		"domain: relay.example.com\nregistrations:\n  - name: home\n    public_key: \"" + k.line + "\"\nunknown: true\n",
		"domain: relay.example.com\nlisten:\n  unknown: true\nregistrations:\n  - name: home\n    public_key: \"" + k.line + "\"\n",
	} {
		path := filepath.Join(t.TempDir(), "relay.yaml")
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil {
			t.Fatalf("unknown field accepted: %s", text)
		}
	}
}
