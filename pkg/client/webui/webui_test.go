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

func TestStatusPageAttachesTargetGrid(t *testing.T) {
	page, err := fs.ReadFile(mustFiles(t), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(page), "list.append(item(t,recordTraffic(t))));app.append(list)") {
		t.Error("status page creates target cards but does not attach their grid to the app container")
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
