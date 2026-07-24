package instructions

import (
	"strconv"
	"strings"
)

// Parse converts the supported Markdown subset into blocks: ATX headings,
// paragraphs, fenced code blocks, and bullet or numbered lists, with inline
// code, emphasis and links. Anything outside that subset is kept as literal
// text rather than being interpreted -- instructions are commands to copy, so
// showing an unsupported construct verbatim is safer than guessing at it.
func Parse(text string) []Block {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var blocks []Block
	var para, items []string
	ordered := false

	flush := func() {
		if len(para) > 0 {
			blocks = append(blocks, Block{Type: "paragraph", Spans: inline(strings.Join(para, " "))})
			para = nil
		}
		if len(items) > 0 {
			b := Block{Type: "list", Ordered: ordered}
			for _, it := range items {
				b.Items = append(b.Items, inline(it))
			}
			blocks = append(blocks, b)
			items = nil
		}
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimLeft(line, " \t")

		if fence, lang, ok := fenceOpen(trimmed); ok {
			flush()
			var body []string
			indent := len(line) - len(trimmed)
			for i++; i < len(lines); i++ {
				if fenceCloses(lines[i], fence) {
					break
				}
				body = append(body, stripIndent(lines[i], indent))
			}
			blocks = append(blocks, Block{Type: "code", Lang: lang, Text: strings.Join(body, "\n")})
			continue
		}
		if strings.TrimSpace(trimmed) == "" {
			flush()
			continue
		}
		if level, rest, ok := heading(trimmed); ok {
			flush()
			blocks = append(blocks, Block{Type: "heading", Level: level, Spans: inline(rest)})
			continue
		}
		if rest, num, ok := listItem(trimmed); ok {
			if len(para) > 0 || (len(items) > 0 && num != ordered) {
				flush()
			}
			ordered = num
			items = append(items, rest)
			continue
		}
		if len(items) > 0 {
			// A plain line under a list item continues that item.
			items[len(items)-1] += " " + strings.TrimSpace(trimmed)
			continue
		}
		para = append(para, strings.TrimRight(trimmed, " \t"))
	}
	flush()
	return blocks
}

func fenceOpen(trimmed string) (fence, lang string, ok bool) {
	for _, f := range []string{"```", "~~~"} {
		if strings.HasPrefix(trimmed, f) {
			return f, strings.TrimSpace(strings.Trim(trimmed[len(f):], string(f[0]))), true
		}
	}
	return "", "", false
}

func fenceCloses(line, fence string) bool {
	t := strings.TrimSpace(line)
	return strings.HasPrefix(t, fence) && strings.Trim(t, string(fence[0])) == ""
}

// stripIndent removes up to n leading spaces or tabs, so a fenced block that
// is indented along with its surrounding list keeps its own inner indentation.
func stripIndent(line string, n int) string {
	i := 0
	for i < n && i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	return line[i:]
}

func heading(trimmed string) (int, string, bool) {
	level := 0
	for level < len(trimmed) && trimmed[level] == '#' {
		level++
	}
	if level == 0 || level > 6 || level == len(trimmed) || (trimmed[level] != ' ' && trimmed[level] != '\t') {
		return 0, "", false
	}
	return level, strings.TrimSpace(strings.TrimRight(trimmed[level:], "# \t")), true
}

func listItem(trimmed string) (rest string, ordered, ok bool) {
	if len(trimmed) > 1 && strings.IndexByte("-*+", trimmed[0]) >= 0 && (trimmed[1] == ' ' || trimmed[1] == '\t') {
		return strings.TrimSpace(trimmed[2:]), false, true
	}
	for i := 0; i < len(trimmed) && i < 9; i++ {
		if trimmed[i] >= '0' && trimmed[i] <= '9' {
			continue
		}
		if i > 0 && (trimmed[i] == '.' || trimmed[i] == ')') && i+1 < len(trimmed) && (trimmed[i+1] == ' ' || trimmed[i+1] == '\t') {
			if _, err := strconv.Atoi(trimmed[:i]); err == nil {
				return strings.TrimSpace(trimmed[i+2:]), true, true
			}
		}
		break
	}
	return "", false, false
}

// inline splits a line into spans. Code spans win over every other marker, so
// a backticked `**literal**` stays literal.
func inline(s string) []Span {
	var spans []Span
	var text strings.Builder
	push := func(sp Span) {
		if text.Len() > 0 {
			spans = append(spans, Span{Type: "text", Text: text.String()})
			text.Reset()
		}
		spans = append(spans, sp)
	}
	for i := 0; i < len(s); {
		switch {
		case s[i] == '\\' && i+1 < len(s) && strings.IndexByte("`*_[]\\", s[i+1]) >= 0:
			text.WriteByte(s[i+1])
			i += 2
		case s[i] == '`':
			if body, n, ok := delimited(s[i:], "`", "`"); ok {
				push(Span{Type: "code", Text: body})
				i += n
				continue
			}
			text.WriteByte(s[i])
			i++
		case s[i] == '[':
			if label, href, n, ok := link(s[i:]); ok {
				push(Span{Type: "link", Text: label, Href: href})
				i += n
				continue
			}
			text.WriteByte(s[i])
			i++
		case strings.HasPrefix(s[i:], "**"), strings.HasPrefix(s[i:], "__"):
			d := s[i : i+2]
			if body, n, ok := emphasis(s[i:], d); ok {
				push(Span{Type: "strong", Text: body})
				i += n
				continue
			}
			text.WriteString(d)
			i += 2
		case s[i] == '*', s[i] == '_':
			d := s[i : i+1]
			if body, n, ok := emphasis(s[i:], d); ok {
				push(Span{Type: "em", Text: body})
				i += n
				continue
			}
			text.WriteByte(s[i])
			i++
		default:
			text.WriteByte(s[i])
			i++
		}
	}
	if text.Len() > 0 {
		spans = append(spans, Span{Type: "text", Text: text.String()})
	}
	return spans
}

// emphasis matches d...d at the start of s. A body padded with whitespace does
// not count, which is the cheap stand-in for CommonMark's flanking rules: it
// keeps arithmetic and shell globs in a sentence ("a * b") as literal text.
func emphasis(s, d string) (string, int, bool) {
	body, n, ok := delimited(s, d, d)
	if !ok || strings.TrimSpace(body) == "" || body != strings.Trim(body, " \t") {
		return "", 0, false
	}
	return body, n, true
}

// delimited matches open...close at the start of s, returning the enclosed
// body and how many bytes were consumed. An empty body does not match, so a
// bare "“" or "**" stays literal text.
func delimited(s, open, closing string) (string, int, bool) {
	rest := s[len(open):]
	end := strings.Index(rest, closing)
	if end <= 0 {
		return "", 0, false
	}
	return rest[:end], len(open) + end + len(closing), true
}

// link matches [label](href) at the start of s. Only http(s) targets are
// accepted; anything else falls back to literal text so that server-supplied
// content can never place a javascript: or data: URL in an href.
func link(s string) (label, href string, n int, ok bool) {
	label, used, ok := delimited(s, "[", "]")
	if !ok || used >= len(s) || s[used] != '(' {
		return "", "", 0, false
	}
	href, hrefUsed, ok := delimited(s[used:], "(", ")")
	if !ok || !SafeURL(href) {
		return "", "", 0, false
	}
	return label, strings.TrimSpace(href), used + hrefUsed, true
}
