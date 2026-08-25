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

func TestGUISettingsMessageResetAndDismissControls(t *testing.T) {
	files, err := Files()
	if err != nil {
		t.Fatal(err)
	}
	page, err := fs.ReadFile(files, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	text := string(page)
	for _, want := range []string{
		"function clearMessage()",
		"function setMessage(",
		"msg-close",
		"aria-label",
		"Dismiss message",
		"#message.ok{color:var(--accent)}",
		"#message.err{color:var(--danger)}",
		"#message.info{color:var(--brand)}",
		"Escape",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("GUI settings page is missing message reset/dismiss feature %q", want)
		}
	}
}
