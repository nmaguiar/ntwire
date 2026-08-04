package webui

import (
	"io/fs"
	"strings"
	"testing"
)

func TestStatusPageShowsLatencyTransportHistory(t *testing.T) {
	page, err := fs.ReadFile(mustFiles(t), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"transportColors",
		"UDP direct",
		"UDP via relay",
		"WSS through relay",
		"WSS fallback",
		"connectionType:s.connection_type||'unknown'",
		"transportBand",
		"connection transport history",
	} {
		if !strings.Contains(string(page), want) {
			t.Errorf("status page is missing %q", want)
		}
	}
}

func mustFiles(t *testing.T) fs.FS {
	t.Helper()
	f, err := Files()
	if err != nil {
		t.Fatal(err)
	}
	return f
}
