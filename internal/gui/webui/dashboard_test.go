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

func TestSmartProxyDashboardMatchesSettingsBrand(t *testing.T) {
	files, err := Files()
	if err != nil {
		t.Fatal(err)
	}
	settings, err := fs.ReadFile(files, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	dashboard, err := fs.ReadFile(files, "smart-proxy-dashboard.html")
	if err != nil {
		t.Fatal(err)
	}
	const logoStart = `<svg class="brand-mark"`
	_, logoTail, found := strings.Cut(string(settings), logoStart)
	logo, _, closed := strings.Cut(logoTail, "</svg>")
	if !found || !closed || !strings.Contains(string(dashboard), logoStart+logo+"</svg>") {
		t.Error("The Smart Proxy dashboard must use the Settings logo")
	}
	const title = "ntwire Smart Proxy live dashboard"
	if !strings.Contains(string(dashboard), "<title>"+title+"</title>") ||
		!strings.Contains(string(dashboard), `<h1><span class="brand-nt">nt</span>wire Smart Proxy live dashboard</h1>`) {
		t.Errorf("The Smart Proxy dashboard heading and tab must read %q", title)
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

func TestSimpleSetupUsesURLFirstOIDCThenFileChooserFallback(t *testing.T) {
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
		"id=\"setup-panel\"", "id=\"setup-form\"", "setupMode",
		"/api/identities/import", "type = 'file'",
		"no SSH private key available.*does not support SSO",
		"location.replace(snap.dashboard_url + '#portal')",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("simple setup is missing %q", want)
		}
	}
}

func TestProxySettingsAreVisibleAndCredentialsAreWriteOnly(t *testing.T) {
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
		"Use system/environment proxy", "Custom proxy", "Direct connection",
		"generatedFields.replaceChildren(proxySettingsControl(profile))",
		"[\"HTTPSProxy\", \"NoSystemProxy\"].includes(f.field)",
		"type=\"password\" autocomplete=\"new-password\"",
		"Inherited environment (read-only)", "Restart ntwire-gui",
		"snap.proxy_reconnect_required", "Proxy settings saved. Reconnect this profile to apply the changes.",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing proxy UI requirement %q", want)
		}
	}
}

func TestSettingsPlaceSmartProxyAfterProfileManagement(t *testing.T) {
	files, err := Files()
	if err != nil {
		t.Fatal(err)
	}
	page, err := fs.ReadFile(files, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(page)
	if !strings.Contains(html, `<details id="profiles-disclosure" open>`) ||
		!strings.Contains(html, `aria-hidden="true">🌐</span> Browser settings (advanced)</summary>`) {
		t.Fatal("Settings must start with Profiles expanded and mark the Browser settings icon as decorative")
	}
	for _, disclosure := range []string{"updates-disclosure", "browser-cleanup-disclosure"} {
		if !strings.Contains(html, `<details id="`+disclosure+`">`) {
			t.Errorf("missing collapsed disclosure %s", disclosure)
		}
	}
	previous := -1
	for _, marker := range []string{`id="profiles"`, `id="form-panel"`, `id="smart-proxy-panel"`, `id="updates-panel"`} {
		at := strings.Index(html, marker)
		if at <= previous {
			t.Fatalf("missing or out-of-order Settings panel %s", marker)
		}
		previous = at
	}
	panel := html[strings.Index(html, `id="smart-proxy-panel"`):previous]
	if !strings.Contains(panel, `<details id="smart-proxy-disclosure">`) || strings.Count(panel, "<details") != 1 {
		t.Fatal("Smart Proxy must start collapsed and have no nested disclosures")
	}
	for _, want := range []string{"Enable Smart Proxy", "Activate this group", "Export saved settings", "Import settings",
		"Save changes", "Discard changes", "Open isolated browser", "Open live dashboard"} {
		if !strings.Contains(panel, want) {
			t.Errorf("Smart Proxy is missing %q", want)
		}
	}
	if !strings.Contains(panel, `id="smart-proxy-open-live" target="_blank" rel="noopener noreferrer"`) ||
		!strings.Contains(html, `q('/smart-proxy-dashboard.html?group='`) {
		t.Fatal("Settings must link to the authenticated dashboard in a new tab")
	}
	for i, name := range []string{"setup", "tunnels", "destinations", "health-settings", "limits"} {
		id := "smart-proxy-" + name
		tab := `id="` + id + `-tab" role="tab" aria-controls="` + id + `" aria-selected="`
		tabPanel := `id="` + id + `" role="tabpanel" aria-labelledby="` + id + `-tab" tabindex="0"`
		if i == 0 {
			tab += `true">`
			tabPanel += ">"
		} else {
			tab += `false" tabindex="-1">`
			tabPanel += " hidden>"
		}
		if !strings.Contains(panel, tab) || !strings.Contains(panel, tabPanel) {
			t.Errorf("Missing tab or incorrect initial state for %s", name)
		}
	}
	if !strings.Contains(html, "import(q('/smart-proxy.js'))") {
		t.Fatal("Settings must load the Smart Proxy module with the loopback API token")
	}
	if _, err := fs.ReadFile(files, "smart-proxy.js"); err != nil {
		t.Fatal(err)
	}
}

func TestSmartProxyDashboardChartsAndAuthentication(t *testing.T) {
	files, err := Files()
	if err != nil {
		t.Fatal(err)
	}
	page, err := fs.ReadFile(files, "smart-proxy-dashboard.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Traffic sent and received", "Tunnel latency", "Connection activity",
		"Tunnel usage", "Clear preference", "import(url('/smart-proxy-dashboard.js'))"} {
		if !strings.Contains(string(page), want) {
			t.Errorf("Live dashboard is missing %q", want)
		}
	}
	module, err := fs.ReadFile(files, "smart-proxy-dashboard.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(module), "settingsModule.search = new URL(import.meta.url).search") {
		t.Fatal("The dashboard dependency must inherit the loopback token")
	}
}
