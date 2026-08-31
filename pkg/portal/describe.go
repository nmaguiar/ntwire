package portal

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"strings"
)

// SchemaDescription is the machine-readable descriptor exported by `ntwire-server portal describe`.
type SchemaDescription struct {
	Schema                      string            `yaml:"schema" json:"schema"`
	PortalTitle                 string            `yaml:"portal_title" json:"portal_title"`
	AvailableVariables          map[string]string `yaml:"available_variables" json:"available_variables"`
	Capabilities                []string          `yaml:"capabilities" json:"capabilities"`
	Targets                     []TargetDescribe  `yaml:"targets" json:"targets"`
	Categories                  []string          `yaml:"categories" json:"categories"`
	SupportedTemplateConstructs []string          `yaml:"supported_template_constructs" json:"supported_template_constructs"`
	SupportedActions            []string          `yaml:"supported_actions" json:"supported_actions"`
}

// TargetDescribe summarizes one target's metadata safely without sensitive credentials.
type TargetDescribe struct {
	ID           string   `yaml:"id" json:"id"`
	Name         string   `yaml:"name" json:"name"`
	Description  string   `yaml:"description" json:"description"`
	Category     string   `yaml:"category" json:"category"`
	Icon         string   `yaml:"icon" json:"icon"`
	URL          string   `yaml:"url,omitempty" json:"url,omitempty"`
	IsSocks      bool     `yaml:"is_socks" json:"is_socks"`
	VirtualPort  int      `yaml:"virtual_port" json:"virtual_port"`
	Applications []string `yaml:"applications,omitempty" json:"applications,omitempty"`
}

// Describe builds a safe, machine-readable descriptor of the portal schema and available targets.
func Describe(portalCfg PortalConfig, targets []TargetInfo) SchemaDescription {
	title := portalCfg.Title
	if title == "" {
		title = "ntwire Portal"
	}

	caps := []string{
		"native_client",
		"web_portal",
		"open_socks_browser",
		"copy",
		"local_forward",
		"ssh_launcher",
		"client.capabilities.local_ports",
		"client.capabilities.socks",
		"client.capabilities.open_url",
		"client.capabilities.native_wireguard",
		"client.capabilities.portal_native",
		"client.capabilities.portal_web",
		"client.capabilities.launch_browser_with_socks",
	}

	constructs := []string{
		"{{portal.title}}",
		"{{portal.description}}",
		"{{user.identity}}",
		"{{user.display_name}}",
		"{{variables.<NAME>}} or {{<NAME>}}",
		"{{#if capability.<NAME>}} ... {{/if}}",
		"{{#if capabilities.<NAME>}} ... {{/if}}",
		"{{#if target.<ID>}} ... {{/if}}",
		"{{#if <FIELD>}} ... {{else}} ... {{/if}}",
		"{{#unless <FIELD>}} ... {{/unless}}",
		"{{#each categories}} ... {{/each}}",
		"{{#each targets}} ... {{/each}}",
		"{{#each applications}} ... {{/each}}",
		"{{client.os}}, {{client.view_os}}, {{client.type}}, {{client.browser}}, {{client.mobile}}",
		"{{.Client.OS}}, {{if .Client.Capabilities.LocalPorts}} ... {{end}}",
		"{{if eq .Client.ViewOS \"windows\"}} ... {{end}}",
	}

	actions := []string{
		"ntwire://open/<target_id>",
		"ntwire://browser/<target_id>",
	}

	var targetList []TargetDescribe
	categorySet := make(map[string]bool)

	for _, t := range targets {
		name := t.Name
		desc := t.Description
		cat := "General"
		icon := "server"
		var urlStr string
		var apps []string

		if t.Portal != nil {
			if t.Portal.Name != "" {
				name = t.Portal.Name
			}
			if t.Portal.Description != "" {
				desc = t.Portal.Description
			}
			if t.Portal.Category != "" {
				cat = t.Portal.Category
			}
			if t.Portal.Icon != "" {
				icon = t.Portal.Icon
			}
			urlStr = t.Portal.URL
			apps = t.Portal.Applications
		}

		categorySet[cat] = true
		targetList = append(targetList, TargetDescribe{
			ID:           t.Name,
			Name:         name,
			Description:  desc,
			Category:     cat,
			Icon:         icon,
			URL:          urlStr,
			IsSocks:      t.IsSocks,
			VirtualPort:  t.VirtualPort,
			Applications: apps,
		})
	}

	var categories []string
	for c := range categorySet {
		categories = append(categories, c)
	}

	vars := make(map[string]string)
	for k, v := range portalCfg.Variables {
		vars[k] = v
	}

	return SchemaDescription{
		Schema:                      SchemaVersion,
		PortalTitle:                 title,
		AvailableVariables:          vars,
		Capabilities:                caps,
		Targets:                     targetList,
		Categories:                  categories,
		SupportedTemplateConstructs: constructs,
		SupportedActions:            actions,
	}
}

// GenerateLLMPrompt creates a ready-to-use LLM prompt instructing an AI model how to write portal.md.
func GenerateLLMPrompt(portalCfg PortalConfig, targets []TargetInfo) string {
	desc := Describe(portalCfg, targets)
	descYAML, _ := yaml.Marshal(desc)

	return fmt.Sprintf(`You are an expert technical documentation and systems engineer writing a secure portal template for ntwire.

### Overview
ntwire is a secure WireGuard and proxy overlay network. The ntwire Portal displays authorized resources and applications to connecting users.
The portal is authored in Markdown with a strictly restricted, declarative templating syntax.

### Environment & Target Metadata
Here is the YAML description of the configured portal variables, capabilities, and targets:

%s

### Security Rules & Constraints
1. NEVER invent target IDs, addresses, hostnames, or ports not present in the configuration above.
2. NEVER use raw HTML, <script> tags, or inline JavaScript event handlers (e.g. onload, onclick).
3. NEVER use dangerous URI schemes like javascript:, data:, or file:.
4. Actions MUST strictly follow the format: [Button Label](ntwire://open/<target_id>) where <target_id> is a valid ID from the targets list above.
5. Use capability conditionals so the template works seamlessly in both Native ntwire Client (supports SOCKS browser actions) and WireGuard Web Portal (standard HTTP links/instructions).

### Supported Template Constructs
- Variables: {{portal.title}}, {{user.display_name}}, {{variable_name}}
- Conditionals:
  {{#if capability.open_socks_browser}}
  [Open in Browser](ntwire://open/{{id}})
  {{/if}}
  {{#if capability.web_portal}}
  [Open Web Service]({{url}})
  {{/if}}
- Iteration:
  {{#each categories}}
  ## {{name}}
  {{#each targets}}
  ### {{name}}
  {{description}}
  {{/each}}
  {{/each}}

### Instructions
Generate a clean, professional, and well-structured portal Markdown document (portal.md) utilizing the categories and targets described above. Output ONLY the Markdown content.`, strings.TrimSpace(string(descYAML)))
}
