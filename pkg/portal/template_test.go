package portal

import (
	"strings"
	"testing"
)

func TestRenderTemplate_Variables(t *testing.T) {
	ctx := &PortalContext{
		Portal: PortalInfo{Title: "My Secure Network"},
		User:   PortalUser{DisplayName: "Alice Smith", Identity: "alice@corp.com"},
		Variables: map[string]string{
			"support_email": "help@corp.com",
			"env":           "Production",
		},
	}

	tmpl := "# {{portal.title}}\n\nWelcome {{user.display_name}} ({{user.identity}}).\nSupport: {{support_email}}\nEnv: {{variables.env}}"
	out, err := RenderTemplate(tmpl, ctx)
	if err != nil {
		t.Fatalf("RenderTemplate failed: %v", err)
	}

	if !strings.Contains(out, "# My Secure Network") {
		t.Errorf("expected title in output, got:\n%s", out)
	}
	if !strings.Contains(out, "Welcome Alice Smith (alice@corp.com).") {
		t.Errorf("expected user in output, got:\n%s", out)
	}
	if !strings.Contains(out, "Support: help@corp.com") {
		t.Errorf("expected support_email, got:\n%s", out)
	}
	if !strings.Contains(out, "Env: Production") {
		t.Errorf("expected env, got:\n%s", out)
	}
}

func TestRenderTemplate_Conditionals(t *testing.T) {
	ctx := &PortalContext{
		Capabilities: PortalCapabilities{
			NativeClient:     true,
			OpenSocksBrowser: true,
			WebPortal:        false,
		},
		User: PortalUser{
			DisplayName: "Alice",
		},
	}

	tmpl := `{{#if capability.open_socks_browser}}
Native Browser Enabled
{{else}}
Native Browser Disabled
{{/if}}
{{#if capability.web_portal}}
Web Portal Active
{{/if}}
{{#unless capability.web_portal}}
Not In Web Portal
{{/unless}}`

	out, err := RenderTemplate(tmpl, ctx)
	if err != nil {
		t.Fatalf("RenderTemplate failed: %v", err)
	}

	if !strings.Contains(out, "Native Browser Enabled") {
		t.Errorf("expected 'Native Browser Enabled', got:\n%s", out)
	}
	if strings.Contains(out, "Native Browser Disabled") {
		t.Errorf("did not expect 'Native Browser Disabled', got:\n%s", out)
	}
	if strings.Contains(out, "Web Portal Active") {
		t.Errorf("did not expect 'Web Portal Active', got:\n%s", out)
	}
	if !strings.Contains(out, "Not In Web Portal") {
		t.Errorf("expected 'Not In Web Portal', got:\n%s", out)
	}
}

func TestRenderTemplate_IterationAndCategories(t *testing.T) {
	ctx := &PortalContext{
		Portal: PortalInfo{Title: "Dev Services"},
		Categories: []PortalCategory{
			{
				Name: "Observability",
				Targets: []PortalTarget{
					{ID: "grafana", Name: "Grafana Dashboard", URL: "http://grafana.internal:3000"},
					{ID: "kibana", Name: "Kibana Logs", URL: "http://kibana.internal:5601"},
				},
			},
			{
				Name:    "Empty Category",
				Targets: nil, // Should be omitted!
			},
			{
				Name: "Databases",
				Targets: []PortalTarget{
					{ID: "postgres", Name: "PostgreSQL Production", Port: 5432},
				},
			},
		},
		Capabilities: PortalCapabilities{
			OpenSocksBrowser: true,
		},
	}

	tmpl := `# {{portal.title}}

{{#each categories}}
## {{name}}
{{#each targets}}
### {{name}}
{{#if url}}
Link: [Open {{name}}](ntwire://open/{{id}})
{{/if}}
{{/each}}
{{/each}}`

	out, err := RenderTemplate(tmpl, ctx)
	if err != nil {
		t.Fatalf("RenderTemplate failed: %v", err)
	}

	if !strings.Contains(out, "## Observability") {
		t.Errorf("expected Observability category, got:\n%s", out)
	}
	if !strings.Contains(out, "### Grafana Dashboard") {
		t.Errorf("expected Grafana, got:\n%s", out)
	}
	if !strings.Contains(out, "Link: [Open Grafana Dashboard](ntwire://open/grafana)") {
		t.Errorf("expected Grafana link, got:\n%s", out)
	}
	if !strings.Contains(out, "## Databases") {
		t.Errorf("expected Databases category, got:\n%s", out)
	}
	if !strings.Contains(out, "### PostgreSQL Production") {
		t.Errorf("expected PostgreSQL, got:\n%s", out)
	}
	if strings.Contains(out, "Empty Category") {
		t.Errorf("empty category should not be present in output, got:\n%s", out)
	}
}

func TestRenderTemplate_TargetIDCondition(t *testing.T) {
	ctx := &PortalContext{
		Targets: []PortalTarget{
			{ID: "postgres", Name: "PostgreSQL", Port: 5432},
			{ID: "redis", Name: "Redis", Port: 6379},
		},
	}

	tmpl := `{{#each targets}}
### {{name}}
{{#if target.postgres}}
Connect via DBeaver!
{{/if}}
{{#if target.redis}}
Connect via Redis CLI!
{{/if}}
{{/each}}`

	out, err := RenderTemplate(tmpl, ctx)
	if err != nil {
		t.Fatalf("RenderTemplate failed: %v", err)
	}

	if !strings.Contains(out, "Connect via DBeaver!") {
		t.Errorf("expected DBeaver note for postgres, got:\n%s", out)
	}
	if !strings.Contains(out, "Connect via Redis CLI!") {
		t.Errorf("expected Redis CLI note for redis, got:\n%s", out)
	}
}
