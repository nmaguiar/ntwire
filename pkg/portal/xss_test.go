package portal

import (
	"strings"
	"testing"
)

// nativeCaps enables the action-button path, which is the branch that emits the
// generated <button>/<span> markup the old sanitizer tried to re-recognize.
func nativeCaps() PortalCapabilities {
	return PortalCapabilities{NativeClient: true, OpenSocksBrowser: true, WebPortal: true, Copy: true}
}

// xssPayloads are inputs that must never reach the DOM as live markup. The
// first three are direct bypasses of the previous sanitizer, which copied any
// substring starting "<a ", "<button " or "<span " through verbatim; the rest
// cover the blocklist gaps in ValidateTemplate (onmouseover, onfocus, srcdoc,
// formaction) and obfuscated scheme forms.
var xssPayloads = []struct {
	name string
	md   string
}{
	{"span event handler", `<span onmouseover="alert(1)">hover</span>`},
	{"anchor event handler", `<a href="#" onmouseover="alert(1)">click</a>`},
	{"button event handler", `<button onfocus="alert(1)" autofocus>go</button>`},
	{"uppercase anchor", `<A HREF="#" ONMOUSEOVER="alert(1)">click</A>`},
	{"tab after tag name", "<a\thref=\"#\" onmouseover=\"alert(1)\">click</a>"},
	{"img onerror", `<img src=x onerror="alert(1)">`},
	{"iframe srcdoc", `<iframe srcdoc="<script>alert(1)</script>"></iframe>`},
	{"form formaction", `<button formaction="javascript:alert(1)">x</button>`},
	{"raw script", `<script>alert(1)</script>`},
	{"base tag", `<base href="https://evil.example/">`},
	{"javascript link", `[click](javascript:alert(1))`},
	{"entity-encoded javascript link", `[click](&#106;avascript:alert(1))`},
	{"whitespace in scheme", `[click](java script:alert(1))`},
	{"data html link", `[click](data:text/html,<script>alert(1)</script>)`},
	{"markup inside code span", "`<span onmouseover=alert(1)>`"},
	{"markup inside link label", `[<span onmouseover=alert(1)>x</span>](https://example.com)`},
	{"markup in heading", `# <span onmouseover="alert(1)">h</span>`},
	{"markup in table cell", "| a | <span onmouseover=\"alert(1)\">b</span> |"},
	{"markup in list item", `- <span onmouseover="alert(1)">i</span>`},
	{"markup in blockquote", `> <span onmouseover="alert(1)">q</span>`},
}

// allowedTags are the only tags RenderMarkdown is permitted to generate. Any
// other "<name" sequence in the output came from the input.
var allowedTags = []string{
	"<p>", "</p>", "<h1>", "</h1>", "<h2>", "</h2>", "<h3>", "</h3>", "<h4>", "</h4>",
	"<h5>", "</h5>", "<h6>", "</h6>", "<hr>", "<blockquote>", "</blockquote>",
	"<ul class=\"portal-list\">", "<ol class=\"portal-list\">", "</ul>", "</ol>", "<li>", "</li>",
	"<table class=\"portal-table\">", "</table>", "<thead>", "</thead>", "<tbody>", "</tbody>",
	"<tr>", "</tr>", "<th>", "</th>", "<td>", "</td>",
	"<div class=\"code-container\">", "</div>", "<pre>", "</pre>", "<code>", "</code>",
	"<code class=\"language-", "<button type=\"button\" class=\"copy-button\"",
	"<button type=\"button\" class=\"ntwire-action-btn\"", "</button>",
	"<span class=\"ntwire-action-text\">", "</span>",
	"<a href=\"", "</a>", "<strong>", "</strong>", "<em>", "</em>",
}

// stripGenerated removes every tag RenderMarkdown is allowed to emit. Whatever
// "<" remains was contributed by the input and should have been escaped.
func stripGenerated(out string) string {
	for changed := true; changed; {
		changed = false
		for _, tag := range allowedTags {
			if i := strings.Index(out, tag); i >= 0 {
				out = out[:i] + out[i+len(tag):]
				changed = true
			}
		}
	}
	return out
}

// TestRenderMarkdownEscapesRawHTML is the regression test for the sanitizer
// bypass: escapeRawHTMLPreservingTags passed any "<a ", "<button " or "<span "
// through unescaped, and the in-tunnel portal's CSP allowed inline handlers, so
// the result executed.
func TestRenderMarkdownEscapesRawHTML(t *testing.T) {
	for _, tc := range xssPayloads {
		t.Run(tc.name, func(t *testing.T) {
			out := RenderMarkdown(tc.md, nativeCaps())
			if leftover := stripGenerated(out); strings.Contains(leftover, "<") {
				t.Fatalf("unescaped markup survived rendering.\ninput:  %s\noutput: %s\nleftover: %s", tc.md, out, leftover)
			}
			// A dangerous scheme is only dangerous in a generated href; as
			// escaped body text ("&lt;button formaction=...") it is inert.
			for _, bad := range []string{`href="javascript:`, `href="data:`, `href="vbscript:`, `href="file:`} {
				if strings.Contains(strings.ToLower(out), bad) {
					t.Fatalf("dangerous scheme reached a generated href.\ninput:  %s\noutput: %s", tc.md, out)
				}
			}
		})
	}
}

// TestRenderMarkdownEscapesInterpolatedValues covers the second input path:
// the template engine writes configuration values (a target description, an
// identity) into the Markdown unescaped, and ValidateTemplate never sees them,
// so the renderer is the only thing standing between them and the DOM.
func TestRenderMarkdownEscapesInterpolatedValues(t *testing.T) {
	ctx := &PortalContext{
		Portal:  PortalInfo{Title: `<span onmouseover="alert(1)">t</span>`},
		Targets: []PortalTarget{{ID: "a", Name: "a", Description: `<span onmouseover="alert(1)">d</span>`}},
	}
	md, err := RenderTemplate("# {{portal.title}}\n\n{{#each targets}}{{description}}\n{{/each}}\n", ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(md, "<span") {
		t.Skip("template engine no longer interpolates raw values; renderer test above still applies")
	}
	out := RenderMarkdown(md, nativeCaps())
	if leftover := stripGenerated(out); strings.Contains(leftover, "<") {
		t.Fatalf("interpolated value reached the DOM as markup: %s", out)
	}
}

// TestRenderMarkdownKeepsSupportedConstructs guards against the fix being
// over-broad: the legitimate Markdown subset must still render.
func TestRenderMarkdownKeepsSupportedConstructs(t *testing.T) {
	out := RenderMarkdown("# Title\n\n**bold** and *em* and `code`\n\n[link](https://example.com)\n\n[Open](ntwire://open/reports)\n", nativeCaps())
	for _, want := range []string{
		"<h1>Title</h1>", "<strong>bold</strong>", "<em>em</em>", "<code>code</code>",
		`<a href="https://example.com"`, `class="ntwire-action-btn" data-action="open" data-target="reports"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestValidateTemplateRejectsRawHTML covers the blocklist-to-allowlist change:
// the previous rule named onload/onerror/onclick and <script> only, so the
// handlers below reached the renderer unreported.
func TestValidateTemplateRejectsRawHTML(t *testing.T) {
	for _, tmpl := range []string{
		`<span onmouseover="alert(1)">x</span>`,
		`<button onfocus="alert(1)">x</button>`,
		`<iframe srcdoc="x"></iframe>`,
		`<script>alert(1)</script>`,
		`<A HREF="#">x</A>`,
		`</div>`,
	} {
		errs := ValidateTemplate(tmpl, nil)
		if !hasFatal(errs) {
			t.Fatalf("template %q should be rejected, got %+v", tmpl, errs)
		}
	}
}

// TestValidateTemplateAllowsMarkdown guards against the allowlist being
// over-broad: a bare "<" is arithmetic, not a tag, and the default template
// must stay valid.
func TestValidateTemplateAllowsMarkdown(t *testing.T) {
	for _, tmpl := range []string{
		"# Title\n\nUse a value < 10.\n\n[link](https://example.com)\n",
		DefaultTemplate,
	} {
		if errs := ValidateTemplate(tmpl, nil); hasFatal(errs) {
			t.Fatalf("valid template rejected: %+v", errs)
		}
	}
}

func hasFatal(errs []ValidationError) bool {
	for _, e := range errs {
		if e.Fatal {
			return true
		}
	}
	return false
}

// TestResolveActionDropsUnsafeURL covers the server half of the action-URL
// guard: authorization answers "which target", so an unusable URL must be
// dropped rather than forwarded to a client that will hand it to a browser.
func TestResolveActionDropsUnsafeURL(t *testing.T) {
	targets := []PortalTarget{
		{ID: "evil", Name: "evil", URL: "--load-extension=/tmp/x"},
		{ID: "good", Name: "good", URL: "https://example.com"},
	}
	got, err := ResolveAction("evil", targets)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Authorized {
		t.Fatal("the target itself is still authorized; only its URL is unusable")
	}
	if got.URL != "" {
		t.Fatalf("unsafe URL forwarded to the client: %q", got.URL)
	}

	got, err = ResolveAction("good", targets)
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != "https://example.com" {
		t.Fatalf("a valid URL should pass through, got %q", got.URL)
	}
}
