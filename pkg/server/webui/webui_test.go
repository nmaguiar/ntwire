package webui

import (
	"io/fs"
	"strings"
	"testing"
)

func TestOperatorDashboardUsesClientBrandLanguage(t *testing.T) {
	page, err := fs.ReadFile(mustFiles(t), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"brand-lockup", "brand-mark", "brand-nt", "logo-cyan", "logo-indigo", "server operator console", "class=\"tabs\"", "ntwire.server.targetsExpanded", "card.open=expanded.has", "function copy(v)", "reconnect-banner"} {
		if !strings.Contains(string(page), want) {
			t.Errorf("operator dashboard missing %q", want)
		}
	}
}
func mustFiles(t *testing.T) fs.FS {
	t.Helper()
	files, err := Files()
	if err != nil {
		t.Fatal(err)
	}
	return files
}
