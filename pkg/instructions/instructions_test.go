package instructions

import (
	"reflect"
	"strings"
	"testing"
)

func data() Data {
	return Data{
		Name: "reports", Description: "Reporting service",
		LocalAddress: "127.0.0.1:58080", LocalHost: "127.0.0.1", LocalPort: 58080,
		VirtualPort: 18080, TargetHint: "reports.internal:8080",
		TunnelIP: "10.90.0.7", ServerTunnelIP: "10.90.0.1", Server: "https://ntwire.example:8443",
	}
}

// The whole point of rendering client-side is that a copyable command carries
// the port this client actually bound, so the substitution has to land inside
// the fenced block that the UI turns into a copy button.
func TestRenderSubstitutesPortInsideCodeFence(t *testing.T) {
	blocks := Render("Run it:\n\n```sh\ncurl http://{{.LocalHost}}:{{.LocalPort}}/reports\n```\n", data())
	if len(blocks) != 2 {
		t.Fatalf("got %d blocks, want 2: %+v", len(blocks), blocks)
	}
	code := blocks[1]
	if code.Type != "code" || code.Lang != "sh" {
		t.Fatalf("second block = %+v, want a sh code block", code)
	}
	if code.Text != "curl http://127.0.0.1:58080/reports" {
		t.Fatalf("code text = %q", code.Text)
	}
}

func TestRenderExposesEveryDataField(t *testing.T) {
	src := "{{.Name}} {{.Description}} {{.LocalAddress}} {{.LocalHost}} {{.LocalPort}} " +
		"{{.VirtualPort}} {{.TargetHint}} {{.TunnelIP}} {{.ServerTunnelIP}} {{.Server}}"
	blocks := Render(src, data())
	if len(blocks) != 1 || blocks[0].Type != "paragraph" {
		t.Fatalf("blocks = %+v", blocks)
	}
	got := blocks[0].Spans[0].Text
	want := "reports Reporting service 127.0.0.1:58080 127.0.0.1 58080 18080 reports.internal:8080 10.90.0.7 10.90.0.1 https://ntwire.example:8443"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

// A broken template is an operator typo in the server config: the instructions
// must still show up rather than vanishing from the card.
func TestRenderFallsBackToRawTextOnTemplateError(t *testing.T) {
	for _, src := range []string{"port {{.LocalPort", "port {{.Nope}}", "port {{ range }}"} {
		blocks := Render(src, data())
		if len(blocks) != 1 || !strings.Contains(blocks[0].Spans[0].Text, "port {{") {
			t.Fatalf("Render(%q) = %+v, want the raw text", src, blocks)
		}
	}
}

func TestRenderEmpty(t *testing.T) {
	if b := Render("   \n\t\n", data()); b != nil {
		t.Fatalf("got %+v, want nil", b)
	}
}

func TestRenderCapsSize(t *testing.T) {
	if b := Render(strings.Repeat("a", maxSize+5000), data()); len(b[0].Spans[0].Text) != maxSize {
		t.Fatalf("input cap: got %d bytes, want %d", len(b[0].Spans[0].Text), maxSize)
	}
	// A template can expand far past its own length, so the cap has to apply
	// to the result as well as the source.
	bomb := `{{define "x"}}` + strings.Repeat("a", 900) + `{{end}}` + strings.Repeat(`{{template "x"}}`, 200)
	if b := Render(bomb, data()); len(b[0].Spans[0].Text) != maxSize {
		t.Fatalf("output cap: got %d bytes, want %d", len(b[0].Spans[0].Text), maxSize)
	}
}

func TestParseHeadingsListsAndCode(t *testing.T) {
	blocks := Parse(strings.Join([]string{
		"# Setup",
		"",
		"Do the following steps",
		"in order.",
		"",
		"- first item",
		"- second item",
		"",
		"1. one",
		"2. two",
		"",
		"    ~~~",
		"    indented fence",
		"    ~~~",
	}, "\n"))
	want := []Block{
		{Type: "heading", Level: 1, Spans: []Span{{Type: "text", Text: "Setup"}}},
		{Type: "paragraph", Spans: []Span{{Type: "text", Text: "Do the following steps in order."}}},
		{Type: "list", Items: [][]Span{{{Type: "text", Text: "first item"}}, {{Type: "text", Text: "second item"}}}},
		{Type: "list", Ordered: true, Items: [][]Span{{{Type: "text", Text: "one"}}, {{Type: "text", Text: "two"}}}},
		{Type: "code", Text: "indented fence"},
	}
	if !reflect.DeepEqual(blocks, want) {
		t.Fatalf("got %+v\nwant %+v", blocks, want)
	}
}

func TestInlineSpans(t *testing.T) {
	cases := []struct {
		in   string
		want []Span
	}{
		{"plain", []Span{{Type: "text", Text: "plain"}}},
		{"use `curl -s`", []Span{{Type: "text", Text: "use "}, {Type: "code", Text: "curl -s"}}},
		{"**bold** and *soft*", []Span{
			{Type: "strong", Text: "bold"}, {Type: "text", Text: " and "}, {Type: "em", Text: "soft"},
		}},
		// A code span wins, so markers inside it stay literal.
		{"`**not bold**`", []Span{{Type: "code", Text: "**not bold**"}}},
		{"see [docs](https://example.com/a)", []Span{
			{Type: "text", Text: "see "}, {Type: "link", Text: "docs", Href: "https://example.com/a"},
		}},
		// Unmatched and escaped markers are literal, not swallowed.
		{"a * b ** c `d", []Span{{Type: "text", Text: "a * b ** c `d"}}},
		{`\*literal\*`, []Span{{Type: "text", Text: "*literal*"}}},
	}
	for _, c := range cases {
		if got := inline(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("inline(%q) = %+v\nwant %+v", c.in, got, c.want)
		}
	}
}

// Links are the one place server-supplied text reaches an href, so anything
// that is not an absolute http(s) URL must degrade to literal text.
func TestUnsafeLinksStayLiteral(t *testing.T) {
	for _, raw := range []string{
		"javascript:alert(1)", "data:text/html,<script>", "file:///etc/passwd",
		"//example.com", "/relative", "https://exa mple.com",
	} {
		got := inline("[click](" + raw + ")")
		if len(got) != 1 || got[0].Type != "text" {
			t.Errorf("link to %q produced %+v, want literal text", raw, got)
		}
		if SafeURL(raw) {
			t.Errorf("SafeURL(%q) = true", raw)
		}
	}
	for _, raw := range []string{"http://a.example", "https://a.example/x?y=1", "  https://a.example  "} {
		if !SafeURL(raw) {
			t.Errorf("SafeURL(%q) = false", raw)
		}
	}
}
