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

func TestGUISettingsIncludesAdaptiveBrandMark(t *testing.T) {
	files, err := Files()
	if err != nil {
		t.Fatal(err)
	}
	page, err := fs.ReadFile(files, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	text := string(page)
	for _, want := range []string{"brand-lockup", "brand-mark", "brand-nt", "logo-cyan", "logo-indigo"} {
		if !strings.Contains(text, want) {
			t.Errorf("GUI settings page is missing brand treatment %q", want)
		}
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

func TestProfileFailureHasClearErrorControl(t *testing.T) {
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
		"snap.state === 'failed' && snap.error",
		"✖️ Clear error",
		"/clear-error",
		"Dismiss this completed connection error",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("GUI settings page is missing clear-error control %q", want)
		}
	}
}

func TestPassphrasePromptKeyboardControls(t *testing.T) {
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
		"input.addEventListener('keydown'",
		"event.key === 'Enter'",
		"connect.click()",
		"event.key === 'Escape'",
		"cancel.click()",
		"queueMicrotask(() => input.focus())",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("GUI passphrase prompt is missing keyboard behavior %q", want)
		}
	}
}
