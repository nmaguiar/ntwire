package webui

import (
	"io/fs"
	"strings"
	"testing"
)

func TestProfileDashboardLinkStartsAtPortal(t *testing.T) {
	files, err := Files()
	if err != nil {
		t.Fatal(err)
	}
	page, err := fs.ReadFile(files, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(page), "dashboardLink.href = snap.dashboard_url + '#portal';") {
		t.Error("GUI profile card must open the client dashboard's Portal view")
	}
}
