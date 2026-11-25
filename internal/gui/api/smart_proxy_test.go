package api

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/internal/gui/manager"
	"github.com/nmaguiar/ntwire/pkg/egressrouter"
)

func TestSmartProxyHistoryAPI_BackfillsSamplesAndSupportsCursor(t *testing.T) {
	s := newTestServer(t)
	t.Cleanup(s.mgr.Close)

	const path = "/api/smart-proxy/history"
	anonymous, err := http.Get("http://" + s.Addr() + path)
	if err != nil {
		t.Fatal(err)
	}
	anonymous.Body.Close()
	if anonymous.StatusCode != http.StatusNotFound {
		t.Fatalf("anonymous history returned %d", anonymous.StatusCode)
	}
	invalid := s.get(t, path+"?after=-1")
	invalid.Body.Close()
	if invalid.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid cursor returned %d", invalid.StatusCode)
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	probe.Close()
	if err := s.mgr.SetSmartProxy(egressrouter.Config{
		Groups: map[string]egressrouter.Config{"office": {Enabled: true, Listen: addr}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.mgr.SetSmartProxyEnabled(true); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if recent := s.mgr.SmartProxyHistory("office", 0); len(recent) > 0 && recent[len(recent)-1].Listening {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	openedAt := time.Now().UnixMilli()
	officePath := path + "?group=office"
	samples := decode[[]manager.SmartProxyHistorySample](t, s.get(t, officePath))
	if len(samples) == 0 || !samples[len(samples)-1].Listening || samples[len(samples)-1].Time > openedAt {
		t.Fatalf("expected samples collected before opening the dashboard, got %+v", samples)
	}
	last := samples[len(samples)-1].Time
	delta := decode[[]manager.SmartProxyHistorySample](t, s.get(t, officePath+"&after="+strconv.FormatInt(last, 10)))
	for _, sample := range delta {
		if sample.Time <= last {
			t.Fatalf("cursor returned old sample %+v", sample)
		}
	}
	if missed := decode[[]manager.SmartProxyHistorySample](t, s.get(t, path+"?group=unknown")); len(missed) != 0 {
		t.Fatalf("unknown group returned samples: %+v", missed)
	}
}

func TestSmartProxyAPIAppliesConfiguration(t *testing.T) {
	s := newTestServer(t)
	t.Cleanup(s.mgr.Close)
	path := "/api/smart-proxy"
	anonymous, err := http.Get("http://" + s.Addr() + path)
	if err != nil {
		t.Fatal(err)
	}
	anonymous.Body.Close()
	if anonymous.StatusCode != http.StatusNotFound {
		t.Fatalf("anonymous status %d", anonymous.StatusCode)
	}
	if cfg := decode[egressrouter.Config](t, s.get(t, path)); cfg.Enabled {
		t.Fatal("router enabled by default")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	cfg := egressrouter.Config{Enabled: true, Listen: addr}
	resp := s.do(t, http.MethodPut, path, cfg)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enable status %d", resp.StatusCode)
	}
	resp.Body.Close()
	if status := decode[manager.SmartProxyStatus](t, s.get(t, path+"/status")); status.MasterEnabled || !status.Enabled || status.Listening != "" {
		t.Fatalf("saving a group opened the master gate: %+v", status)
	}
	resp = s.do(t, http.MethodPut, path+"/master", map[string]bool{"enabled": true})
	if status := decode[manager.SmartProxyStatus](t, resp); !status.MasterEnabled || status.Listening != addr {
		t.Fatalf("master activation did not start the listener: %+v", status)
	}
	if status := decode[egressrouter.Status](t, s.get(t, path+"/status")); status.Listening != addr {
		t.Fatalf("status %+v", status)
	}
	cfg.Listen = "0.0.0.0:1080"
	resp = s.do(t, http.MethodPut, path, cfg)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid bind status %d", resp.StatusCode)
	}
	resp.Body.Close()
	if status := decode[egressrouter.Status](t, s.get(t, path+"/status")); status.Listening != addr {
		t.Fatal("invalid edit changed listener")
	}
	export := s.get(t, path+"/export")
	if !strings.Contains(export.Header.Get("Content-Disposition"), "ntwire-smart-proxy.json") {
		t.Fatal("export is not an attachment")
	}
	file := decode[map[string]json.RawMessage](t, export)
	if string(file["version"]) != "1" || len(file["smart_proxy"]) == 0 || len(file["master_enabled"]) > 0 {
		t.Fatalf("unexpected exported fields: %v", file)
	}
	validated := s.do(t, http.MethodPost, path+"/validate", egressrouter.Config{Listen: addr})
	if validated.StatusCode != http.StatusOK {
		t.Fatalf("validate status %d", validated.StatusCode)
	}
	validated.Body.Close()
	if status := decode[egressrouter.Status](t, s.get(t, path+"/status")); status.Listening != addr {
		t.Fatal("validation changed listener")
	}
	resp = s.do(t, http.MethodPut, path+"/master", map[string]bool{"enabled": false})
	if status := decode[manager.SmartProxyStatus](t, resp); status.MasterEnabled || !status.Enabled || status.Listening != "" {
		t.Fatalf("master disable lost saved activation or kept listener: %+v", status)
	}
	resp = s.do(t, http.MethodPut, path+"/master", map[string]bool{"enabled": true})
	if status := decode[manager.SmartProxyStatus](t, resp); !status.MasterEnabled || status.Listening != addr {
		t.Fatalf("master did not restore the selected group: %+v", status)
	}
	cfg.Enabled, cfg.Listen = false, addr
	resp = s.do(t, http.MethodPut, path, cfg)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("disable status %d", resp.StatusCode)
	}
	resp.Body.Close()
	if status := decode[egressrouter.Status](t, s.get(t, path+"/status")); status.Listening != "" {
		t.Fatal("disable kept listener")
	}
}

func TestSmartProxyAPISavesAutomaticUnmatchedPolicy(t *testing.T) {
	s := newTestServer(t)
	t.Cleanup(s.mgr.Close)
	const path = "/api/smart-proxy"
	cfg := egressrouter.Config{Routing: egressrouter.Routing{
		Unmatched: "deny",
		Rules:     []egressrouter.Rule{{Hosts: []string{"internal.example"}}},
	}}
	// Start with a saved explicit block, then choose "Block when rules exist".
	for _, policy := range []string{"deny", ""} {
		cfg.Routing.Unmatched = policy
		saved := decode[egressrouter.Config](t, s.do(t, http.MethodPut, path, cfg))
		loaded := decode[egressrouter.Config](t, s.get(t, path))
		for _, result := range []egressrouter.Config{saved, loaded} {
			if result.Routing.Unmatched != policy || len(result.Routing.Rules) != 1 {
				t.Fatalf("saving %q changed routing: %+v", policy, result.Routing)
			}
		}
	}
}
