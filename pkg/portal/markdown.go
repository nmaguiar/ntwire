package portal

import (
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

var linkRegex = regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`)

// renderInlines parses inline markdown: `code`, **bold**, *em*, and [links](url).
// Raw HTML characters (<, >, &, ") are escaped safely.
func renderInlines(text string, caps PortalCapabilities) string {
	// First extract code spans so we don't parse markdown inside code spans
	var placeholders []string
	codeSpanRegex := regexp.MustCompile("`([^`]+)`")
	text = codeSpanRegex.ReplaceAllStringFunc(text, func(match string) string {
		inner := match[1 : len(match)-1]
		idx := len(placeholders)
		placeholders = append(placeholders, "<code>"+html.EscapeString(inner)+"</code>")
		return "@@NTWIRECODESPAN" + strconv.Itoa(idx) + "@@"
	})

	// Process links
	text = linkRegex.ReplaceAllStringFunc(text, func(match string) string {
		sub := linkRegex.FindStringSubmatch(match)
		if len(sub) < 3 {
			return html.EscapeString(match)
		}
		label := sub[1]
		href := strings.TrimSpace(sub[2])

		// Handle ntwire:// action links
		if strings.HasPrefix(href, "ntwire://") {
			action, targetID, err := ParseActionURI(href)
			if err == nil {
				escapedLabel := html.EscapeString(label)
				if caps.NativeClient && caps.OpenSocksBrowser {
					return `<button type="button" class="ntwire-action-btn" data-action="` + html.EscapeString(action) + `" data-target="` + html.EscapeString(targetID) + `">` + escapedLabel + `</button>`
				}
				// In WireGuard web mode or copy-only mode
				return `<span class="ntwire-action-text">` + escapedLabel + `</span>`
			}
		}

		// Validate external links
		if isSafeExternalURL(href) {
			escapedHref := html.EscapeString(href)
			escapedLabel := html.EscapeString(label)
			return `<a href="` + escapedHref + `" target="_blank" rel="noopener noreferrer" class="portal-link">` + escapedLabel + `</a>`
		}

		// Dangerous or unsupported scheme: neutralize and render plain label
		return html.EscapeString(label)
	})

	// Escape remaining raw HTML
	// Notice we must temporarily protect our generated HTML tags from escaping
	text = escapeRawHTMLPreservingTags(text)

	// Bold: **text** or __text__
	boldRegex := regexp.MustCompile(`\*\*([^*]+)\*\*|__([^_]+)__`)
	text = boldRegex.ReplaceAllStringFunc(text, func(m string) string {
		inner := strings.Trim(m, "*_")
		return "<strong>" + inner + "</strong>"
	})

	// Italic: *text* or _text_
	italicRegex := regexp.MustCompile(`\*([^*]+)\*|_([^_]+)_`)
	text = italicRegex.ReplaceAllStringFunc(text, func(m string) string {
		inner := strings.Trim(m, "*_")
		return "<em>" + inner + "</em>"
	})

	// Restore code spans
	for idx, codeHTML := range placeholders {
		placeholder := "@@NTWIRECODESPAN" + strconv.Itoa(idx) + "@@"
		text = strings.ReplaceAll(text, placeholder, codeHTML)
	}

	return text
}

func escapeRawHTMLPreservingTags(s string) string {
	var sb strings.Builder
	i := 0
	for i < len(s) {
		if strings.HasPrefix(s[i:], "<a ") || strings.HasPrefix(s[i:], "</a>") ||
			strings.HasPrefix(s[i:], "<button ") || strings.HasPrefix(s[i:], "</button>") ||
			strings.HasPrefix(s[i:], "<span ") || strings.HasPrefix(s[i:], "</span>") ||
			strings.HasPrefix(s[i:], "@@NTWIRECODESPAN") {
			// Find end of tag or placeholder
			if strings.HasPrefix(s[i:], "@@NTWIRECODESPAN") {
				end := strings.Index(s[i:], "@@")
				if end >= 0 {
					end2 := strings.Index(s[i+end+2:], "@@")
					if end2 >= 0 {
						fullEnd := end + 2 + end2 + 2
						sb.WriteString(s[i : i+fullEnd])
						i += fullEnd
						continue
					}
				}
			}
			end := strings.Index(s[i:], ">")
			if end >= 0 {
				sb.WriteString(s[i : i+end+1])
				i += end + 1
				continue
			}
		}

		switch s[i] {
		case '<':
			sb.WriteString("&lt;")
		case '>':
			sb.WriteString("&gt;")
		case '&':
			sb.WriteString("&amp;")
		case '"':
			sb.WriteString("&quot;")
		default:
			sb.WriteByte(s[i])
		}
		i++
	}
	return sb.String()
}

func isSafeExternalURL(raw string) bool {
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

{{/each}}
{{/each}}
`

// SecurityHeaders returns standard HTTP security headers for web portal responses.
func SecurityHeaders() map[string]string {
	return map[string]string{
		"Content-Security-Policy":   "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "no-referrer",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Cache-Control":             "no-store, no-cache, must-revalidate",
	}
}

// WrapWebPage wraps rendered portal HTML in a self-contained, themed HTML document.
func WrapWebPage(title, bodyHTML string) string {
	escapedTitle := html.EscapeString(title)
	if escapedTitle == "" {
		escapedTitle = "ntwire Portal"
	}
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
` + bodyHTML + `
</div>
<script>
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
