package server

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
	checkedIn, err := os.ReadFile(filepath.Join("..", "..", "docs", "SERVER-CONFIG-GUIDE.md"))
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

func TestParseConfig_RejectsUnknownFields(t *testing.T) {
	for _, yaml := range []string{
		"auth:\n  authorized_keys_dir: keys\nunknown: true\n",
		"auth:\n  authorized_keys_dir: keys\nlisten:\n  unknown: true\n",
	} {
		if _, err := ParseConfig([]byte(yaml), t.TempDir()); err == nil {
			t.Fatalf("unknown field accepted: %s", yaml)
		}
	}
}
