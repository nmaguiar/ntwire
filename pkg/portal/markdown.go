package portal

import (
	"crypto/rand"
	"encoding/base64"
	"html"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// RenderMarkdown converts Markdown text to sanitized, secure HTML.
// It explicitly escapes all raw HTML and only generates safe DOM elements.
// Dangerous URL schemes (javascript:, data:, file:) are neutralized.
func RenderMarkdown(md string, caps PortalCapabilities) string {
	lines := strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n")
	var out strings.Builder

	inCodeBlock := false
	var codeLang string
	var codeLines []string

	inList := false
	listOrdered := false

	inTable := false
	tableHeaderDone := false

	flushList := func() {
		if inList {
			if listOrdered {
				out.WriteString("</ol>\n")
			} else {
				out.WriteString("</ul>\n")
			}
			inList = false
		}
	}

	flushTable := func() {
		if inTable {
			out.WriteString("</tbody>\n</table>\n")
			inTable = false
			tableHeaderDone = false
		}
	}

	flushAll := func() {
		flushList()
		flushTable()
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		// 1. Fenced Code Block handling
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			fence := trimmed[:3]
			if !inCodeBlock {
				flushAll()
				inCodeBlock = true
				codeLang = strings.TrimSpace(strings.TrimPrefix(trimmed, fence))
				codeLines = nil
				continue
			} else {
				inCodeBlock = false
				codeContent := strings.Join(codeLines, "\n")
				escapedCode := html.EscapeString(codeContent)
				out.WriteString("<div class=\"code-container\">")
				if codeLang != "" {
					out.WriteString("<pre><code class=\"language-" + html.EscapeString(codeLang) + "\">" + escapedCode + "</code></pre>")
				} else {
					out.WriteString("<pre><code>" + escapedCode + "</code></pre>")
				}
				out.WriteString("<button type=\"button\" class=\"copy-button\" title=\"Copy to clipboard\" data-copy=\"" + html.EscapeString(codeContent) + "\">Copy</button>")
				out.WriteString("</div>\n")
				continue
			}
		}

		if inCodeBlock {
			codeLines = append(codeLines, line)
			continue
		}

		// Empty line flushes list and non-continued table
		if trimmed == "" {
			flushList()
			if inTable {
				hasMoreTable := false
				for j := i + 1; j < len(lines); j++ {
					t := strings.TrimSpace(lines[j])
					if t == "" {
						continue
					}
					if strings.HasPrefix(t, "|") && strings.HasSuffix(t, "|") {
						hasMoreTable = true
					}
					break
				}
				if !hasMoreTable {
					flushTable()
				}
			}
			continue
		}

		// 2. Headings (# Heading)
		if strings.HasPrefix(trimmed, "#") {
			flushAll()
			level := 0
			for level < len(trimmed) && trimmed[level] == '#' {
				level++
			}
			if level >= 1 && level <= 6 && level < len(trimmed) && (trimmed[level] == ' ' || trimmed[level] == '\t') {
				headingText := strings.TrimSpace(trimmed[level:])
				tag := "h" + strconv.Itoa(level)
				out.WriteString("<" + tag + ">" + renderInlines(headingText, caps) + "</" + tag + ">\n")
				continue
			}
		}

		// 3. Horizontal rule (---, ***, ___)
		if isHorizontalRule(trimmed) {
			flushAll()
			out.WriteString("<hr>\n")
			continue
		}

		// 4. Blockquote (> quote)
		if strings.HasPrefix(trimmed, ">") {
			flushAll()
			quoteText := strings.TrimSpace(strings.TrimPrefix(trimmed, ">"))
			out.WriteString("<blockquote><p>" + renderInlines(quoteText, caps) + "</p></blockquote>\n")
			continue
		}

		// 5. Table row (| a | b |)
		if strings.HasPrefix(trimmed, "|") && strings.HasSuffix(trimmed, "|") {
			flushList()
			cols := parseTableRow(trimmed)
			if isTableDivider(cols) {
				// Divider row
				if inTable && !tableHeaderDone {
					out.WriteString("</thead>\n<tbody>\n")
					tableHeaderDone = true
				}
				continue
			}
			if !inTable {
				inTable = true
				tableHeaderDone = false
				out.WriteString("<table class=\"portal-table\">\n<thead>\n<tr>")
				for _, col := range cols {
					out.WriteString("<th>" + renderInlines(col, caps) + "</th>")
				}
				out.WriteString("</tr>\n")
				continue
			}
			// Normal row
			out.WriteString("<tr>")
			tag := "td"
			if !tableHeaderDone {
				tag = "th"
			}
			for _, col := range cols {
				out.WriteString("<" + tag + ">" + renderInlines(col, caps) + "</" + tag + ">")
			}
			out.WriteString("</tr>\n")
			continue
		}

		// 6. List items (- item, * item, 1. item)
		if itemText, ordered, isItem := parseListItem(trimmed); isItem {
			flushTable()
			if !inList || listOrdered != ordered {
				flushList()
				inList = true
				listOrdered = ordered
				if ordered {
					out.WriteString("<ol class=\"portal-list\">\n")
				} else {
					out.WriteString("<ul class=\"portal-list\">\n")
				}
			}
			out.WriteString("<li>" + renderInlines(itemText, caps) + "</li>\n")
			continue
		}

		// 7. Regular paragraph
		flushAll()
		out.WriteString("<p>" + renderInlines(trimmed, caps) + "</p>\n")
	}

	flushAll()
	if inCodeBlock {
		escapedCode := html.EscapeString(strings.Join(codeLines, "\n"))
		out.WriteString("<pre><code>" + escapedCode + "</code></pre>\n")
	}

	return out.String()
}

func isHorizontalRule(s string) bool {
	if len(s) < 3 {
		return false
	}
	r := s[0]
	if r != '-' && r != '*' && r != '_' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] != r && s[i] != ' ' && s[i] != '\t' {
			return false
		}
	}
	return true
}

func parseTableRow(row string) []string {
	row = strings.Trim(row, "|")
	parts := strings.Split(row, "|")
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = strings.TrimSpace(p)
	}
	return out
}

func isTableDivider(cols []string) bool {
	if len(cols) == 0 {
		return false
	}
	for _, c := range cols {
		c = strings.TrimSpace(c)
		if len(c) == 0 {
			return false
		}
		for i := 0; i < len(c); i++ {
			if c[i] != '-' && c[i] != ':' {
				return false
			}
		}
	}
	return true
}

func parseListItem(s string) (text string, ordered bool, ok bool) {
	if (strings.HasPrefix(s, "- ") || strings.HasPrefix(s, "* ") || strings.HasPrefix(s, "+ ")) && len(s) > 2 {
		return strings.TrimSpace(s[2:]), false, true
	}
	dotIdx := strings.Index(s, ". ")
	if dotIdx > 0 && dotIdx < 10 {
		if _, err := strconv.Atoi(s[:dotIdx]); err == nil {
			return strings.TrimSpace(s[dotIdx+2:]), true, true
		}
	}
	return "", false, false
}

// inlineKind distinguishes the three things that can appear inside a line of
// portal Markdown.
type inlineKind int

const (
	inlineText inlineKind = iota
	inlineCode
	inlineLink
)

type inlineToken struct {
	kind inlineKind
	text string // literal text, code-span content, or link label
	href string // link target; inlineLink only
}

// renderInlines converts the supported inline Markdown subset -- `code`,
// **bold**, *em*, [links](url), and ntwire:// action links -- into HTML.
//
// Every run of caller-supplied text is HTML-escaped as it is emitted, and the
// escaped result is never re-scanned for markup. This ordering is the whole
// point: the previous implementation escaped *after* substituting its own
// generated tags, so it needed a pass that re-recognized that output, and
// because that pass matched on the content string, any input that merely looked
// like a generated tag ("<a ", "<button ", "<span ") was copied through raw.
// Escape-then-emit removes the class of bug rather than the instance -- there is
// no pass in which caller text and generated markup share a string.
//
// Note that portal Markdown carries interpolated configuration values
// (descriptions, identities) that the template engine writes out unescaped, so
// this function -- not template validation -- is what makes those values safe.
func renderInlines(text string, caps PortalCapabilities) string {
	var out strings.Builder
	for _, tok := range scanInline(text) {
		switch tok.kind {
		case inlineCode:
			out.WriteString("<code>" + html.EscapeString(tok.text) + "</code>")
		case inlineLink:
			out.WriteString(renderLink(tok.text, tok.href, caps))
		default:
			out.WriteString(emphasize(html.EscapeString(tok.text)))
		}
	}
	return out.String()
}

// scanInline splits a line into literal, code-span, and link tokens. It
// recognizes the same shapes the previous regexes did (`[^`]+` and
// \[([^\]]+)\]\(([^)]+)\)) without ever substituting into the string it is
// still scanning.
func scanInline(s string) []inlineToken {
	var toks []inlineToken
	var lit strings.Builder
	flush := func() {
		if lit.Len() > 0 {
			toks = append(toks, inlineToken{kind: inlineText, text: lit.String()})
			lit.Reset()
		}
	}
	for i := 0; i < len(s); {
		switch s[i] {
		case '`':
			if n := strings.IndexByte(s[i+1:], '`'); n > 0 {
				flush()
				toks = append(toks, inlineToken{kind: inlineCode, text: s[i+1 : i+1+n]})
				i += n + 2
				continue
			}
		case '[':
			if label, href, n, ok := parseInlineLink(s[i:]); ok {
				flush()
				toks = append(toks, inlineToken{kind: inlineLink, text: label, href: href})
				i += n
				continue
			}
		}
		lit.WriteByte(s[i])
		i++
	}
	flush()
	return toks
}

// parseInlineLink matches "[label](href)" at the start of s, returning the
// number of bytes consumed. Both parts must be non-empty, matching the regex it
// replaces.
func parseInlineLink(s string) (label, href string, n int, ok bool) {
	closeIdx := strings.IndexByte(s, ']')
	if closeIdx < 2 || closeIdx+1 >= len(s) || s[closeIdx+1] != '(' {
		return "", "", 0, false
	}
	hrefEnd := strings.IndexByte(s[closeIdx+2:], ')')
	if hrefEnd < 1 {
		return "", "", 0, false
	}
	return s[1:closeIdx], s[closeIdx+2 : closeIdx+2+hrefEnd], closeIdx + 2 + hrefEnd + 1, true
}

// renderLink emits an action button, an external link, or -- for a scheme that
// is neither -- the bare label. Label and href are escaped at every exit.
func renderLink(label, rawHref string, caps PortalCapabilities) string {
	href := strings.TrimSpace(rawHref)
	escapedLabel := html.EscapeString(label)

	if strings.HasPrefix(href, "ntwire://") {
		if action, targetID, err := ParseActionURI(href); err == nil {
			if caps.NativeClient && caps.OpenSocksBrowser {
				return `<button type="button" class="ntwire-action-btn" data-action="` + html.EscapeString(action) +
					`" data-target="` + html.EscapeString(targetID) + `">` + escapedLabel + `</button>`
			}
			// WireGuard web mode or copy-only mode.
			return `<span class="ntwire-action-text">` + escapedLabel + `</span>`
		}
	}
	if isSafeExternalURL(href) {
		return `<a href="` + html.EscapeString(href) + `" target="_blank" rel="noopener noreferrer" class="portal-link">` + escapedLabel + `</a>`
	}
	// Dangerous or unsupported scheme: neutralize and render the plain label.
	return escapedLabel
}

var (
	boldRegex   = regexp.MustCompile(`\*\*([^*]+)\*\*|__([^_]+)__`)
	italicRegex = regexp.MustCompile(`\*([^*]+)\*|_([^_]+)_`)
)

// emphasize applies **bold** and *italic* to text that has already been
// HTML-escaped. Inserting tags here is safe precisely because the input can no
// longer contain markup of its own, and because no HTML entity contains "*" or
// "_" for the patterns to trip over.
func emphasize(escaped string) string {
	escaped = boldRegex.ReplaceAllStringFunc(escaped, func(m string) string {
		return "<strong>" + strings.Trim(m, "*_") + "</strong>"
	})
	return italicRegex.ReplaceAllStringFunc(escaped, func(m string) string {
		return "<em>" + strings.Trim(m, "*_") + "</em>"
	})
}

func isSafeExternalURL(raw string) bool { return SafeExternalURL(raw) }

// SafeExternalURL reports whether raw is a URL that may be presented to a user
// as a link or handed to a browser. Only absolute http, https and mailto URLs
// qualify; everything else (javascript:, data:, file:, a bare "--flag") is
// server-supplied text that must not reach an href or a process argument.
func SafeExternalURL(raw string) bool {
	s := strings.TrimSpace(raw)
	if strings.ContainsAny(s, " \t\r\n\"'<>") {
		return false
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	return scheme == "http" || scheme == "https" || scheme == "mailto"
}

// DefaultTemplate is the built-in portal template used when no custom template is configured.
const DefaultTemplate = `# {{portal.title}}

Welcome{{#if user.display_name}}, **{{user.display_name}}**{{/if}}.

Select one of the services available to you.

{{#each categories}}
## {{name}}

{{#each targets}}
### {{name}}
{{description}}

{{#if url}}
{{#if capability.open_socks_browser}}
[Open in Browser](ntwire://open/{{id}})
{{/if}}
{{#if capability.web_portal}}
[Open Web Service]({{url}})
{{/if}}
{{/if}}

{{#if connection_instructions}}
{{connection_instructions}}
{{/if}}

{{#if client.capabilities.local_ports}}
Local endpoint: {{local_address}}
{{else}}
Tunnel endpoint: use the server tunnel address and port {{virtual_port}}.
{{/if}}

{{/each}}
{{/each}}
`

// NewScriptNonce returns a fresh CSP nonce for one response. Callers must pass
// the same value to SecurityHeaders and WrapWebPage.
func NewScriptNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(b), nil
}

// SecurityHeaders returns standard HTTP security headers for web portal
// responses, binding script execution to nonce.
//
// script-src was previously 'unsafe-inline', which permits inline event handler
// attributes and therefore made the CSP no defense at all against markup that
// slipped past the renderer. A nonce covers only the page's own <script> block:
// an injected handler attribute cannot carry one.
func SecurityHeaders(nonce string) map[string]string {
	return map[string]string{
		"Content-Security-Policy":   "default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-" + nonce + "'; img-src 'self' data:; connect-src 'self'",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "no-referrer",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Cache-Control":             "no-store, no-cache, must-revalidate",
	}
}

// WrapWebPage wraps rendered portal HTML in a self-contained, themed HTML
// document whose inline script carries nonce, matching SecurityHeaders.
func WrapWebPage(title, bodyHTML string, client ClientContext, nonce string) string {
	escapedTitle := html.EscapeString(title)
	if escapedTitle == "" {
		escapedTitle = "ntwire Portal"
	}
	// No inline onchange handler here: it would need 'unsafe-inline' in
	// script-src, which is exactly what the nonce replaces. The listener is
	// attached from the nonced script at the bottom of the page instead.
	selector := `<form class="platform-selector" method="get"><label for="view_os">Instructions for</label><select id="view_os" name="view_os"><option value="">Auto (` + html.EscapeString(client.DetectedOS) + `)</option>`
	for _, os := range []string{"ios", "ipados", "macos", "windows", "linux", "android"} {
		selected := ""
		if client.Override && client.ViewOS == os {
			selected = " selected"
		}
		selector += `<option value="` + os + `"` + selected + `>` + html.EscapeString(os) + `</option>`
	}
	if client.Type == "wireguard" {
		selector += `<option value="wireguard">Generic WireGuard</option>`
	}
	selector += `</select></form>`
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>` + escapedTitle + `</title>
<style>
:root {
  --bg: #0f172a;
  --surface: #1e293b;
  --surface-border: #334155;
  --text: #f8fafc;
  --text-muted: #94a3b8;
  --accent: #38bdf8;
  --accent-hover: #0ea5e9;
  --btn-bg: #2563eb;
  --btn-hover: #1d4ed8;
  --code-bg: #020617;
}
@media (prefers-color-scheme: light) {
  :root {
    --bg: #f8fafc;
    --surface: #ffffff;
    --surface-border: #e2e8f0;
    --text: #0f172a;
    --text-muted: #64748b;
    --accent: #0284c7;
    --accent-hover: #0369a1;
    --btn-bg: #2563eb;
    --btn-hover: #1d4ed8;
    --code-bg: #f1f5f9;
  }
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  background-color: var(--bg);
  color: var(--text);
  line-height: 1.6;
  padding: 2rem 1rem;
}
.portal-container {
  max-width: 860px;
  margin: 0 auto;
}
.platform-selector { margin: 0 0 1rem; color: var(--text-muted); font-size: .9rem; }
.platform-selector select { margin-left: .5rem; padding: .25rem; }
header {
  margin-bottom: 2rem;
  padding-bottom: 1rem;
  border-bottom: 1px solid var(--surface-border);
}
h1 { font-size: 2rem; margin-bottom: 0.5rem; color: var(--text); font-weight: 700; }
h2 { font-size: 1.4rem; margin-top: 2rem; margin-bottom: 1rem; color: var(--accent); border-bottom: 1px solid var(--surface-border); padding-bottom: 0.3rem; }
h3 { font-size: 1.15rem; margin-top: 1.25rem; margin-bottom: 0.5rem; color: var(--text); }
p { margin-bottom: 1rem; color: var(--text); }
.portal-list, ol.portal-list { margin-left: 1.5rem; margin-bottom: 1rem; }
li { margin-bottom: 0.35rem; }
.portal-link {
  color: var(--accent);
  text-decoration: none;
  font-weight: 500;
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
}
.portal-link:hover { text-decoration: underline; color: var(--accent-hover); }
.ntwire-action-btn {
  display: inline-block;
  background-color: var(--btn-bg);
  color: #ffffff;
  border: none;
  padding: 0.5rem 1rem;
  border-radius: 6px;
  font-size: 0.95rem;
  font-weight: 500;
  cursor: pointer;
  margin: 0.5rem 0;
  transition: background-color 0.15s ease;
}
.ntwire-action-btn:hover { background-color: var(--btn-hover); }
.ntwire-action-text {
  display: inline-block;
  background-color: var(--surface);
  color: var(--text-muted);
  border: 1px solid var(--surface-border);
  padding: 0.4rem 0.8rem;
  border-radius: 6px;
  font-size: 0.9rem;
}
.code-container {
  position: relative;
  margin: 1rem 0;
}
pre {
  background-color: var(--code-bg);
  border: 1px solid var(--surface-border);
  border-radius: 6px;
  padding: 1rem;
  overflow-x: auto;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.9rem;
}
code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.9em;
  background-color: var(--code-bg);
  padding: 0.15rem 0.35rem;
  border-radius: 4px;
  border: 1px solid var(--surface-border);
}
pre code { border: none; padding: 0; }
.copy-button {
  position: absolute;
  top: 0.5rem;
  right: 0.5rem;
  background-color: var(--surface);
  color: var(--text-muted);
  border: 1px solid var(--surface-border);
  border-radius: 4px;
  padding: 0.25rem 0.5rem;
  font-size: 0.8rem;
  cursor: pointer;
}
.copy-button:hover { background-color: var(--surface-border); color: var(--text); }
.portal-table {
  width: 100%;
  border-collapse: collapse;
  margin: 1rem 0;
}
.portal-table th, .portal-table td {
  border: 1px solid var(--surface-border);
  padding: 0.6rem 0.8rem;
  text-align: left;
}
.portal-table th { background-color: var(--surface); color: var(--text); }
blockquote {
  border-left: 4px solid var(--accent);
  padding-left: 1rem;
  margin: 1rem 0;
  color: var(--text-muted);
}
</style>
</head>
<body>
<div class="portal-container">
` + selector + bodyHTML + `
</div>
<script nonce="` + html.EscapeString(nonce) + `">
const viewOS = document.querySelector('#view_os');
if (viewOS) {
  viewOS.addEventListener('change', () => { viewOS.form.submit(); });
}
document.querySelectorAll('.copy-button').forEach(btn => {
  btn.addEventListener('click', () => {
    const text = btn.getAttribute('data-copy');
    if (text) {
      navigator.clipboard.writeText(text).then(() => {
        const prev = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = prev; }, 2000);
      });
    }
  });
});
</script>
</body>
</html>`
}
