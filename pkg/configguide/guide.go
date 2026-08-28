// Package configguide renders strict machine-readable schemas and Markdown
// configuration guides from the YAML-tagged configuration structs.
package configguide

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"
)

// Guide is the declarative metadata shared by the Markdown and schema
// renderers. Sample remains the authoritative YAML syntax source.
type Guide struct {
	Title       string
	Description string
	Sample      string
	QA          []QA
	Rules       []string
	Root        any
	// SchemaOverrides is declarative field metadata keyed by YAML path. It
	// records defaults and validator-friendly constraints that Go types alone
	// cannot express (for example enums and address patterns).
	SchemaOverrides map[string]map[string]any
}

type QA struct{ Question, Answer string }

// JSONSchema returns a Draft 2020-12 schema. YAML duration values are strings
// because that is the form accepted by yaml.v3 for time.Duration fields.
func (g Guide) JSONSchema() ([]byte, error) {
	s := map[string]any{
		"$schema":     "https://json-schema.org/draft/2020-12/schema",
		"title":       g.Title,
		"description": g.Description,
	}
	root := schemaFor(reflect.TypeOf(g.Root)).(map[string]any)
	for path, override := range g.SchemaOverrides {
		applyOverride(root, path, override)
	}
	for k, v := range root {
		s[k] = v
	}
	return json.MarshalIndent(s, "", "  ")
}

func applyOverride(root map[string]any, path string, override map[string]any) {
	parts := strings.Split(path, ".")
	current := root
	for _, part := range parts[:len(parts)-1] {
		properties, ok := current["properties"].(map[string]any)
		if !ok {
			return
		}
		next, ok := properties[part].(map[string]any)
		if !ok {
			return
		}
		current = next
	}
	properties, ok := current["properties"].(map[string]any)
	if !ok {
		return
	}
	field, ok := properties[parts[len(parts)-1]].(map[string]any)
	if !ok {
		return
	}
	for k, v := range override {
		field[k] = v
	}
}

func schemaFor(t reflect.Type) any {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == reflect.TypeOf(time.Duration(0)) {
		return map[string]any{"type": "string", "format": "duration"}
	}
	switch t.Kind() {
	case reflect.Struct:
		properties := map[string]any{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" {
				continue
			}
			name := strings.Split(f.Tag.Get("yaml"), ",")[0]
			if name == "" || name == "-" {
				continue
			}
			properties[name] = schemaFor(f.Type)
		}
		return map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	case reflect.Slice, reflect.Array:
		return map[string]any{"type": "array", "items": schemaFor(t.Elem())}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": schemaFor(t.Elem())}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	default:
		return map[string]any{"type": "string"}
	}
}

func (g Guide) Markdown() (string, error) {
	schema, err := g.JSONSchema()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n%s\n\n", g.Title, g.Description)
	b.WriteString("## LLM configuration checklist\n\n")
	b.WriteString("Collect unanswered required choices before producing YAML. Retain the displayed YAML style and key spelling; never invent keys or secrets. Validate the conditional rules below before returning YAML. JSON Schema validates YAML after conversion to JSON; the binary remains the final semantic validator.\n\n")
	b.WriteString("| Question | Answer |\n| --- | --- |\n")
	for _, q := range g.QA {
		fmt.Fprintf(&b, "| %s | %s |\n", q.Question, q.Answer)
	}
	b.WriteString("\n## Complete YAML reference\n\n```yaml\n")
	b.WriteString(g.Sample)
	b.WriteString("```\n\n## Rules and conditional validation\n\n")
	for _, rule := range g.Rules {
		fmt.Fprintf(&b, "- %s\n", rule)
	}
	b.WriteString("\n## JSON Schema\n\n```json\n")
	b.Write(schema)
	b.WriteString("\n```\n")
	return b.String(), nil
}
