// Package instructions renders the optional per-tunnel setup instructions a
// server ships to clients (protocol.Tunnel.Instructions) into a structured
// block tree the local status UI can build DOM nodes from.
//
// Rendering happens on the client, not the server, for two reasons: the real
// loopback port is only known there (the server advertises a preference, and
// listenLocal/ReplacePort may pick another), and emitting structured blocks
// instead of HTML keeps the web UI free of innerHTML for server-supplied text.
// The server uses only SafeURL, to reject a bad docs_url at config load.
package instructions

import (
	"bytes"
	"strings"
	"text/template"
)

// maxSize caps both the instruction text that is templated and the result that
// is parsed, so a misconfigured server cannot make the client render an
// unbounded document -- template definitions can expand well past their input.
const maxSize = 64 << 10

// Data is the template context exposed to instruction text. It is deliberately
// a flat value of strings and ints: text/template can reach any exported field
// or method of whatever it is handed, so nothing wider (a Connection, an
// AuthResponse) may be passed in its place.
type Data struct {
	Name           string // tunnel name
	Description    string // tunnel description, as configured on the server
	LocalAddress   string // bound loopback address, e.g. 127.0.0.1:58080
	LocalHost      string // host part of LocalAddress, e.g. 127.0.0.1
	LocalPort      int    // actually bound loopback port
	VirtualPort    int    // port exposed inside the WireGuard tunnel
	TargetHint     string // server-side target, when the server discloses one
	TunnelIP       string // this client's address inside the tunnel
	ServerTunnelIP string // the server's address inside the tunnel
	Server         string // control-plane base URL this client is connected to
}

// Span is a run of inline content within a Block.
type Span struct {
	// Type is one of "text", "code", "strong", "em" or "link".
	Type string `json:"type"`
	Text string `json:"text"`
	// Href is set for "link" spans only, and is always http(s).
	Href string `json:"href,omitempty"`
}

// Block is one top-level piece of rendered instruction content.
type Block struct {
	// Type is one of "heading", "paragraph", "code" or "list".
	Type string `json:"type"`
	// Level is the heading level, 1 through 6, for "heading" blocks.
	Level int `json:"level,omitempty"`
	// Spans is the inline content of "heading" and "paragraph" blocks.
	Spans []Span `json:"spans,omitempty"`
	// Text is the verbatim content of a "code" block: it is what the web UI
	// offers as copy-to-clipboard, so it is never split into spans.
	Text string `json:"text,omitempty"`
	// Lang is the info string of a fenced "code" block, when present.
	Lang string `json:"lang,omitempty"`
	// Items holds the inline content of each entry of a "list" block.
	Items [][]Span `json:"items,omitempty"`
	// Ordered marks a numbered "list" block.
	Ordered bool `json:"ordered,omitempty"`
}

// Render expands text as a Go template with data and parses the result as the
// supported Markdown subset. A template that fails to parse or execute is an
// operator typo in the server's configuration: the raw text is rendered
// instead, so the instructions stay readable rather than disappearing.
func Render(text string, data Data) []Block {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	return Parse(truncate(expand(truncate(text), data)))
}

func truncate(s string) string {
	if len(s) > maxSize {
		return s[:maxSize]
	}
	return s
}

func expand(text string, data Data) string {
	t, err := template.New("instructions").Parse(text)
	if err != nil {
		return text
	}
	var out bytes.Buffer
	if err := t.Execute(&out, data); err != nil {
		return text
	}
	return out.String()
}

// SafeURL reports whether raw is a URL the UI may turn into a link. Only
// absolute http and https URLs qualify: everything else (javascript:, data:,
// file:, scheme-relative) is server-supplied text reaching an href.
func SafeURL(raw string) bool {
	s := strings.TrimSpace(raw)
	if strings.ContainsAny(s, " \t\r\n\"'<>") {
		return false
	}
	l := strings.ToLower(s)
	return strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://")
}
