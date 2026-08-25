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
		"connectionType:hs.connection_type||'unknown'",
		"transportBand",
		"connection transport and downtime history",
		"chart-down-band",
		"Connection down",
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
	if !strings.Contains(string(page), "list.append(item(t,trafficSeries(statusHistory.samples,t.name))));app.append(list)") {
		t.Error("status page creates target cards but does not attach their grid to the app container")
	}
}

func TestStatusPageKeepsViewTabsBeforeTargetAccordion(t *testing.T) {
	page, err := fs.ReadFile(mustFiles(t), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	text := string(page)
	tabs := strings.Index(text, `id="tabs"`)
	targets := strings.Index(text, `id="app"`)
	if tabs < 0 || targets < 0 || tabs > targets {
		t.Error("status page must render the Tunnels and Portal tab bar before the target accordion")
	}
	for _, want := range []string{
		`aria-controls="app"`,
		`aria-controls="portal-app"`,
		`.tabs{position:sticky;top:0;`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("status page is missing persistent dashboard view control %q", want)
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
