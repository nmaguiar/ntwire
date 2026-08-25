package portal

import (
	"strings"
	"testing"
)

func TestValidateTemplate(t *testing.T) {
	known := &KnownContext{
		TargetIDs: map[string]bool{
			"grafana":  true,
			"postgres": true,
		},
	}

	validTmpl := `# {{portal.title}}
{{#if capability.open_socks_browser}}
[Open Grafana](ntwire://open/grafana)
{{/if}}`

	errs := ValidateTemplate(validTmpl, known)
	if len(errs) > 0 {
		t.Fatalf("expected valid template, got errors: %v", errs)
	}

	// Malicious script test
	scriptTmpl := `# Title
<script>alert(1)</script>`
	errs = ValidateTemplate(scriptTmpl, known)
	if len(errs) == 0 {
		t.Fatalf("expected error for script tag, got none")
	}

	// Unknown target action
	unknownTargetTmpl := `[Open Unknown](ntwire://open/unknown_svc)`
	errs = ValidateTemplate(unknownTargetTmpl, known)
	if len(errs) == 0 {
		t.Fatalf("expected warning/error for unknown target, got none")
	}

	// Unclosed block
	unclosedTmpl := `{{#if capability.web_portal}} Unclosed content`
	errs = ValidateTemplate(unclosedTmpl, known)
	if len(errs) == 0 {
		t.Fatalf("expected error for unclosed block, got none")
	}
}

func TestDescribeAndPrompt(t *testing.T) {
	cfg := PortalConfig{
		Title: "Enterprise Lab",
		Variables: map[string]string{
			"region": "us-east-1",
		},
	}
	targets := []TargetInfo{
		{
			Name:        "grafana",
			Target:      "grafana.internal:3000",
			Description: "Grafana Dashboard",
			Portal: &TargetPortalConfig{
				Name:     "Grafana",
				Category: "Observability",
				URL:      "http://grafana.internal:3000",
			},
		},
	}

	desc := Describe(cfg, targets)
	if desc.PortalTitle != "Enterprise Lab" {
		t.Errorf("expected title Enterprise Lab, got %q", desc.PortalTitle)
	}
	if len(desc.Targets) != 1 || desc.Targets[0].Name != "Grafana" {
		t.Errorf("expected 1 target named Grafana, got: %+v", desc.Targets)
	}

	prompt := GenerateLLMPrompt(cfg, targets)
	if !strings.Contains(prompt, "Enterprise Lab") || !strings.Contains(prompt, "Observability") {
		t.Errorf("expected prompt to contain title and category, got:\n%s", prompt)
	}
}

func TestBuildContext_AuthorizationIsolation(t *testing.T) {
	portalCfg := PortalConfig{Title: "Portal"}
	allTargets := []TargetInfo{
		{Name: "targetA", Description: "Service A"},
		{Name: "targetB", Description: "Service B (Secret)"},
		{Name: "targetC", Description: "Service C"},
	}

	// User 1 authorized for A, B, C
	user1Ctx := BuildContext(portalCfg, PortalUser{Identity: "user1"}, PortalClient{}, allTargets, "native", "100.64.0.1")
	if len(user1Ctx.Targets) != 3 {
		t.Fatalf("expected user1 to have 3 targets, got %d", len(user1Ctx.Targets))
	}

	// User 2 authorized for A, C only
	user2Targets := []TargetInfo{
		{Name: "targetA", Description: "Service A"},
		{Name: "targetC", Description: "Service C"},
	}
	user2Ctx := BuildContext(portalCfg, PortalUser{Identity: "user2"}, PortalClient{}, user2Targets, "native", "100.64.0.1")
	if len(user2Ctx.Targets) != 2 {
		t.Fatalf("expected user2 to have 2 targets, got %d", len(user2Ctx.Targets))
	}

	// Verify User2 context contains no trace of targetB
	for _, target := range user2Ctx.Targets {
		if target.ID == "targetB" || strings.Contains(target.Description, "Secret") {
			t.Errorf("user2 received targetB: %+v", target)
		}
	}
}
