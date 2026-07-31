package autostart

import (
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"testing"
)

// TestPlistContentsIsWellFormedXML confirms escaping didn't break the
// document -- decoding every token until EOF is enough to catch a
// malformed tag or an unescaped special character, without needing a
// full plist-aware parser (encoding/xml has no first-class support for
// <dict>/<key>/<string> alternation).
func TestPlistContentsIsWellFormedXML(t *testing.T) {
	b := plistContents("/opt/ntwire/ntwire-gui", []string{"--autostart"})
	dec := xml.NewDecoder(strings.NewReader(string(b)))
	for {
		_, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("plist is not well-formed XML: %v\n%s", err, b)
		}
	}
}

func TestPlistContentsIncludesExpectedValues(t *testing.T) {
	b := string(plistContents("/opt/ntwire/ntwire-gui", []string{"--autostart"}))
	for _, want := range []string{
		"<key>Label</key>",
		"<string>" + launchAgentLabel + "</string>",
		"<string>/opt/ntwire/ntwire-gui</string>",
		"<string>--autostart</string>",
		"<key>RunAtLoad</key>",
		"<true/>",
	} {
		if !strings.Contains(b, want) {
			t.Errorf("plist missing %q:\n%s", want, b)
		}
	}
}

func TestPlistContentsEscapesSpecialCharacters(t *testing.T) {
	b := string(plistContents(`/opt/A & B/ntwire-gui`, []string{"--flag=<value>"}))
	if strings.Contains(b, "A & B") {
		t.Errorf("unescaped & in plist:\n%s", b)
	}
	if !strings.Contains(b, "A &amp; B") {
		t.Errorf("expected escaped &amp; in plist:\n%s", b)
	}
	if strings.Contains(b, "<value>") {
		t.Errorf("unescaped angle brackets in plist:\n%s", b)
	}
}
