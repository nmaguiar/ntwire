// Package configguide renders strict machine-readable schemas and Markdown
// configuration guides from the YAML-tagged configuration structs.
package configguide

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	Skill       Skill
	// SchemaOverrides is declarative field metadata keyed by YAML path. It
	// records defaults and validator-friendly constraints that Go types alone
	// cannot express (for example enums and address patterns).
	SchemaOverrides map[string]map[string]any
}

type QA struct{ Question, Answer string }

// Skill describes a portable, progressively disclosed Agent Skill generated
// from a configuration guide. SKILL.md stays intentionally small; agents load
// a feature reference only when the user's request needs it.
type Skill struct {
	Name        string
	Description string
	Binary      string
	Workflow    []string
	References  []SkillReference
}

// SkillReference is one on-demand part of a generated Agent Skill.
type SkillReference struct {
	Path    string
	When    string
	Content string
}

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
	if g.Skill.Name != "" {
		fmt.Fprintf(&b, "## Low-context LLM skill\n\nGenerate a portable `%s` folder with:\n\n```sh\n%s -write-config-skill /path/to/%s\n```\n\nThe folder contains a short `SKILL.md`, feature references that an agent loads only when needed, the complete reference, and the strict JSON Schema. Move the whole generated folder to one of these locations:\n\n", g.Skill.Name, g.Skill.Binary, g.Skill.Name)
		fmt.Fprintf(&b, "| Tool | Skill folder |\n| --- | --- |\n| VS Code / GitHub Copilot | `.github/skills/%s/` |\n| Claude Code | `.claude/skills/%s/` |\n| Codex | `~/.codex/skills/%s/` |\n| Google Antigravity (`agy`) | `.agents/skills/%s/` |\n| mini-a | `~/.openaf-mini-a/skills/%s/` |\n\n", g.Skill.Name, g.Skill.Name, g.Skill.Name, g.Skill.Name, g.Skill.Name)
		b.WriteString("Restart or refresh the agent after copying the folder. Regenerate it after upgrading the ntwire binary; it requires neither this repository nor network access.\n\n")
	}
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

// SkillMarkdown renders the small entrypoint placed at the root of a
// generated Agent Skill folder. Agent Skills use this portable frontmatter
// format in VS Code, Claude Code, Codex, Google Antigravity, and mini-a.
func (g Guide) SkillMarkdown() (string, error) {
	if g.Skill.Name == "" || g.Skill.Description == "" || g.Skill.Binary == "" {
		return "", fmt.Errorf("configuration guide skill metadata is incomplete")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "---\nname: %s\ndescription: %q\n---\n\n", g.Skill.Name, g.Skill.Description)
	fmt.Fprintf(&b, "# %s\n\n", g.Title)
	b.WriteString("Generate or review ntwire YAML from the operator's stated requirements. Keep the existing configuration unless the operator asks to replace it. Ask only for choices needed by the requested capability, and never invent keys, credentials, hostnames, CIDRs, public keys, or access grants.\n\n")
	b.WriteString("## Workflow\n\n")
	for i, step := range g.Skill.Workflow {
		fmt.Fprintf(&b, "%d. %s\n", i+1, step)
	}
	b.WriteString("\n## Load only the relevant reference\n\n")
	b.WriteString("Do not load every reference preemptively. Read the matching file only after the user asks for that capability or supplies its fields.\n\n")
	b.WriteString("| When the user needs | Read |\n| --- | --- |\n")
	for _, ref := range g.Skill.References {
		fmt.Fprintf(&b, "| %s | [`%s`](%s) |\n", ref.When, ref.Path, ref.Path)
	}
	b.WriteString("\nIf a requested field is not covered by the selected reference, read [`references/config-reference.md`](references/config-reference.md) or [`references/schema.json`](references/schema.json), never guess its spelling or type.\n")
	return b.String(), nil
}

// WriteSkill atomically creates a self-contained, portable Agent Skill folder.
// It refuses to replace an existing folder so an operator's local edits cannot
// be silently discarded during a binary upgrade.
func (g Guide) WriteSkill(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return fmt.Errorf("configuration skill directory is required")
	}
	if _, err := os.Lstat(dir); err == nil {
		return fmt.Errorf("refusing to overwrite existing configuration skill directory %q", dir)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect configuration skill directory %q: %w", dir, err)
	}

	entrypoint, err := g.SkillMarkdown()
	if err != nil {
		return err
	}
	reference, err := g.Markdown()
	if err != nil {
		return err
	}
	schema, err := g.JSONSchema()
	if err != nil {
		return err
	}

	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0755); err != nil {
		return fmt.Errorf("create configuration skill parent: %w", err)
	}
	tmp, err := os.MkdirTemp(parent, "."+g.Skill.Name+"-")
	if err != nil {
		return fmt.Errorf("create configuration skill: %w", err)
	}
	defer os.RemoveAll(tmp)

	files := map[string]string{
		"SKILL.md":                       entrypoint,
		"references/config-reference.md": reference,
		"references/schema.json":         string(schema) + "\n",
	}
	for _, ref := range g.Skill.References {
		if !validSkillPath(ref.Path) {
			return fmt.Errorf("invalid configuration skill reference path %q", ref.Path)
		}
		if _, exists := files[ref.Path]; exists {
			return fmt.Errorf("duplicate configuration skill reference path %q", ref.Path)
		}
		files[ref.Path] = ref.Content
	}
	for name, content := range files {
		path := filepath.Join(tmp, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return fmt.Errorf("create configuration skill reference directory: %w", err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return fmt.Errorf("write configuration skill %q: %w", name, err)
		}
	}
	if err := os.Rename(tmp, dir); err != nil {
		return fmt.Errorf("publish configuration skill: %w", err)
	}
	return nil
}

func validSkillPath(path string) bool {
	clean := filepath.Clean(filepath.FromSlash(path))
	return path != "" && !filepath.IsAbs(path) && clean != "." && clean != ".." && !strings.HasPrefix(clean, ".."+string(filepath.Separator))
}
