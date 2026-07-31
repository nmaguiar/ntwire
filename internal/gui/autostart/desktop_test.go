package autostart

import (
	"strings"
	"testing"
)

func TestDesktopContentsIncludesExpectedLines(t *testing.T) {
	got := desktopContents("/opt/ntwire/ntwire-gui", []string{"--autostart"})
	for _, want := range []string{
		"[Desktop Entry]",
		"Type=Application",
		"Exec='/opt/ntwire/ntwire-gui' '--autostart'",
		"X-GNOME-Autostart-enabled=true",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("desktop entry missing %q:\n%s", want, got)
		}
	}
}

func TestQuoteShellArgEscapesSingleQuotes(t *testing.T) {
	got := quoteShellArg(`/opt/it's ntwire/ntwire-gui`)
	want := `'/opt/it'\''s ntwire/ntwire-gui'`
	if got != want {
		t.Errorf("quoteShellArg = %q, want %q", got, want)
	}
}

func TestQuoteShellArgHandlesSpaces(t *testing.T) {
	got := quoteShellArg("/opt/my ntwire/ntwire-gui")
	if got != "'/opt/my ntwire/ntwire-gui'" {
		t.Errorf("quoteShellArg = %q", got)
	}
}
