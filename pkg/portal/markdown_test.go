package portal

import (
	"strings"
	"testing"
)

func TestRenderMarkdown_BasicElements(t *testing.T) {
	md := `# Main Title

Welcome to the **secure** portal with *monitoring* tools.

- Target 1
- Target 2

` + "```sh" + `
curl http://localhost:8080
` + "```"

	caps := PortalCapabilities{NativeClient: true, OpenSocksBrowser: true}
	html := RenderMarkdown(md, caps)

	if !strings.Contains(html, "<h1>Main Title</h1>") {
		t.Errorf("expected h1 tag, got:\n%s", html)
	}
	if !strings.Contains(html, "<strong>secure</strong>") {
		t.Errorf("expected strong tag, got:\n%s", html)
	}
	if !strings.Contains(html, "<em>monitoring</em>") {
		t.Errorf("expected em tag, got:\n%s", html)
	}
	if !strings.Contains(html, "<ul class=\"portal-list\">") || !strings.Contains(html, "<li>Target 1</li>") {
		t.Errorf("expected list items, got:\n%s", html)
	}
	if !strings.Contains(html, "<div class=\"code-container\">") || !strings.Contains(html, "curl http://localhost:8080") {
		t.Errorf("expected code container, got:\n%s", html)
	}
}

func TestRenderMarkdown_LinksAndActions(t *testing.T) {
	md := `[External Docs](https://docs.example.com)
[Open Grafana](ntwire://open/grafana)`

	// Native client mode
	nativeCaps := PortalCapabilities{NativeClient: true, OpenSocksBrowser: true}
	nativeHTML := RenderMarkdown(md, nativeCaps)

	if !strings.Contains(nativeHTML, `<a href="https://docs.example.com" target="_blank" rel="noopener noreferrer" class="portal-link">External Docs</a>`) {
		t.Errorf("expected safe external link in native mode, got:\n%s", nativeHTML)
	}
	if !strings.Contains(nativeHTML, `<button type="button" class="ntwire-action-btn" data-action="open" data-target="grafana">Open Grafana</button>`) {
		t.Errorf("expected action button in native mode, got:\n%s", nativeHTML)
	}

	// WireGuard Web mode
	webCaps := PortalCapabilities{WebPortal: true, NativeClient: false}
	webHTML := RenderMarkdown(md, webCaps)

	if !strings.Contains(webHTML, `<a href="https://docs.example.com"`) {
		t.Errorf("expected safe external link in web mode, got:\n%s", webHTML)
	}
	if !strings.Contains(webHTML, `<span class="ntwire-action-text">Open Grafana</span>`) {
		t.Errorf("expected action text fallback in web mode, got:\n%s", webHTML)
	}
}

func TestSecurity_XSSNeutralization(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		forbidden []string
	}{
		{
			name:      "Raw script tag",
			input:     `<script>alert(1)</script>`,
			forbidden: []string{"<script>", "alert(1)"},
		},
		{
			name:      "JavaScript URI in link",
			input:     `[Click Me](javascript:alert('pwned'))`,
			forbidden: []string{"javascript:", "alert"},
		},
		{
			name:      "Data URI in link",
			input:     `[Data Link](data:text/html,<script>alert(1)</script>)`,
			forbidden: []string{"data:text/html"},
		},
		{
			name:      "Inline event handlers",
			input:     `<img src="x" onerror="alert(1)">`,
			forbidden: []string{"onerror", "<img"},
		},
		{
			name:      "File URI in link",
			input:     `[Local File](file:///etc/passwd)`,
			forbidden: []string{"file://"},
		},
	}

	caps := PortalCapabilities{NativeClient: true, OpenSocksBrowser: true}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rendered := RenderMarkdown(tc.input, caps)
			for _, forb := range tc.forbidden {
				if strings.Contains(strings.ToLower(rendered), strings.ToLower(forb)) &&
					!strings.Contains(rendered, "&lt;") { // Ensure it was neutralized/escaped
					t.Errorf("forbidden construct %q found in rendered HTML:\n%s", forb, rendered)
				}
			}
		})
	}
}
