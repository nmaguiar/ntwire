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
		"WSS",
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
	if !strings.Contains(string(page), "list.append(item(t,trafficSeries(statusHistory.samples,t.name))));tunnelList.append(list)") {
		t.Error("status page creates target cards but does not attach their grid to the app container")
	}
}

func TestStatusPageCollapsesAndSafelyRendersTransportPaths(t *testing.T) {
	page, err := fs.ReadFile(mustFiles(t), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	text := string(page)
	for _, want := range []string{
		"const transportExpandedKey='ntwire.transportExpanded'",
		"card.open=transportExpanded",
		"card.className='stats-toggle'",
		"head.className='stats-toggle-head'",
		"body.className='stats-toggle-body'",
		"function pathText(v){return v===null||v===undefined||v===''?'n/a':String(v)}",
		"const tr=document.createElement('tr'),hasStatus=typeof p.healthy==='boolean'",
		"const rtt=pathNumber(p.rtt)?Math.round(p.rtt/1000000)+' ms':'n/a'",
		"const loss=pathNumber(p.loss)?(p.loss*100).toFixed(1)+'%':'n/a'",
		"const delivery=pathNumber(p.delivery_ratio)&&p.delivery_ratio>=0?Math.round(p.delivery_ratio*100)+'%':'n/a'",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("status page is missing transport rendering behavior %q", want)
		}
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
		`aria-controls="settings-app"`,
		`id="tab-settings"`,
		`.tabs{position:sticky;top:0;`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("status page is missing persistent dashboard view control %q", want)
		}
	}
}

func TestStatusPageUsesFragmentsAndEmbedsProtectedSettings(t *testing.T) {
	page, err := fs.ReadFile(mustFiles(t), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	text := string(page)
	for _, want := range []string{
		"function viewFromHash()",
		"addEventListener('hashchange',selectHash)",
		"location.hash!=='#'+view",
		"setSettingsURL(s.settings_url)",
		"nextFrame.src=settingsURL",
		"nextFrame.title='Local connection settings'",
		"function renderSettingsView(){if(!settingsURL){switchTab('tunnels');return}const frame=settingsApp.querySelector('iframe.settings-frame');if(frame&&frame.getAttribute('src')===settingsURL)return",
		"let activeTab='tunnels',settingsURL='',settingsURLKnown=false,portalEnabled=false,portalLoaded=false,portalLoading=false;",
		"async function renderPortalView(){if(portalLoaded||portalLoading)return;portalLoading=true;",
		"portalApp.append(card);portalLoaded=true",
		"finally{portalLoading=false}",
		"switchTab('tunnels');setMessage('Portal is not configured or unavailable for this session.','err')",
		`id="tab-portal" type="button" class="tab-btn" role="tab" aria-controls="portal-app" aria-selected="false" hidden`,
		"function setPortalEnabled(enabled){portalEnabled=enabled===true;tabPortal.hidden=!portalEnabled",
		"setPortalEnabled(s.portal_enabled)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("status page is missing fragment/settings behavior %q", want)
		}
	}
}

func TestStatusPageMessageResetAndDismissControls(t *testing.T) {
	page, err := fs.ReadFile(mustFiles(t), "index.html")
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
			t.Errorf("status page is missing message reset/dismiss feature %q", want)
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
