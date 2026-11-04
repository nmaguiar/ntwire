package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/nmaguiar/ntwire/internal/gui/config"
)

func TestProxyAPI(t *testing.T) {
	s := newTestServer(t)
	resp := s.do(t, "POST", "/api/proxy", map[string]any{"Server": "https://server.example"})
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(data), `"environment"`) {
		t.Fatalf("diagnostics: %d %s", resp.StatusCode, data)
	}
	req, _ := http.NewRequest("POST", "http://"+s.Addr()+"/api/proxy", strings.NewReader(`{}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatal("unauthorized diagnostics accepted")
	}

	const raw = "socks5h://alice:private-password@proxy:1080"
	resp = s.do(t, "POST", "/api/profiles", map[string]any{"Name": "proxy", "Server": "https://server.example", "HTTPSProxy": raw})
	data, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 201 || strings.Contains(string(data), "private-password") {
		t.Fatal("create failed or leaked password")
	}
	var p config.Profile
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	for _, update := range []map[string]any{
		{"HTTPSProxy": "", "KeepProxyURL": true},
		{"HTTPSProxy": p.HTTPSProxy}, // backwards-compatible masked round-trip
	} {
		update["Name"] = "proxy"
		update["Server"] = p.Server
		resp = s.do(t, "PUT", "/api/profiles/"+p.ID, update)
		data, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		snap, _ := s.mgr.Snapshot(p.ID)
		if resp.StatusCode != 200 || snap.Profile.HTTPSProxy != raw || strings.Contains(string(data), "private-password") {
			t.Fatal("saved credentials were changed or leaked")
		}
	}
	resp = s.do(t, "POST", "/api/proxy", map[string]any{"ID": p.ID, "Server": p.Server, "KeepProxyURL": true})
	data, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(data), "Custom profile setting") || strings.Contains(string(data), "private-password") {
		t.Fatal("preview leaked credentials or lost custom proxy")
	}
	resp = s.get(t, "/api/profiles")
	data, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(data), "private-password") {
		t.Fatal("list leaked credentials")
	}
	snap, _ := s.mgr.Snapshot(p.ID)
	encoded, _ := json.Marshal(snap)
	if strings.Contains(string(encoded), "private-password") {
		t.Fatal("SSE snapshot leaks credentials")
	}
	for _, bad := range []string{"ftp://proxy", "http://user:private-password%zz@proxy", "http://proxy:99999", "http://alice:********@other"} {
		resp = s.do(t, "PUT", "/api/profiles/"+p.ID, map[string]any{"HTTPSProxy": bad})
		data, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 400 || strings.Contains(string(data), "private-password") {
			t.Fatal("invalid proxy accepted or error leaked credentials")
		}
	}
	// A complete new URL without userinfo explicitly clears saved credentials.
	resp = s.do(t, "PUT", "/api/profiles/"+p.ID, map[string]any{"HTTPSProxy": "http://proxy:8080"})
	resp.Body.Close()
	snap, _ = s.mgr.Snapshot(p.ID)
	if snap.Profile.HTTPSProxy != "http://proxy:8080" {
		t.Fatal("credential clear failed")
	}
}
