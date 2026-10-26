package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/nmaguiar/ntwire/internal/gui/config"
	"github.com/nmaguiar/ntwire/internal/gui/manager"
	"github.com/nmaguiar/ntwire/internal/gui/updates"
)

func TestUpdateEndpointsAuthenticationAndPreferences(t *testing.T) {
	dir := t.TempDir()
	for _, key := range []string{"HOME", "USERPROFILE", "LOCALAPPDATA", "XDG_CACHE_HOME"} {
		t.Setenv(key, dir)
	}
	cfgPath := filepath.Join(dir, "gui.yaml")
	m, e := manager.New(fakeConnector{}, cfgPath, filepath.Join(dir, "missing"))
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	c := updates.New("dev", cfgPath, func() updates.Preferences {
		p := m.Settings()
		return updates.Preferences{Disabled: p.UpdateChecksDisabled, Automatic: p.AutomaticUpdates}
	})
	defer c.Close()
	// Exercise exactly the protected mux without opening a listener.
	s := &Server{mgr: m, token: "secret", mux: http.NewServeMux(), updates: c}
	s.updateRoutes()
	for _, methodPath := range [][2]string{{"GET", "/api/updates"}, {"POST", "/api/updates/check"}, {"POST", "/api/updates/download"}, {"PUT", "/api/updates/preferences"}, {"POST", "/api/updates/install"}} {
		req := httptest.NewRequest(methodPath[0], methodPath[1], nil)
		w := httptest.NewRecorder()
		s.mux.ServeHTTP(w, req)
		if w.Code != 404 {
			t.Fatalf("unauthenticated %s: %d", methodPath[1], w.Code)
		}
	}
	req := httptest.NewRequest("PUT", "/api/updates/preferences?token=secret", bytes.NewBufferString(`{"disabled":true,"automatic":true}`))
	req.Header.Set("Origin", "http://foreign.invalid")
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatal("accepted foreign origin")
	}
	req = httptest.NewRequest("PUT", "/api/updates/preferences?token=secret", bytes.NewBufferString(`{"disabled":true,"automatic":true}`))
	w = httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("preferences: %d %s", w.Code, w.Body)
	}
	cfg, e := config.Load(cfgPath)
	if e != nil || !cfg.Settings.UpdateChecksDisabled || !cfg.Settings.AutomaticUpdates {
		t.Fatal("preferences not persisted", cfg, e)
	}
	req = httptest.NewRequest("POST", "/api/updates/install?token=secret", bytes.NewBufferString(`{"elevate":true}`))
	w = httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)
	if w.Code != 409 {
		t.Fatal("headless installation accepted")
	}
	// A status read never changes preferences or creates a download.
	req = httptest.NewRequest("GET", "/api/updates?token=secret", nil).WithContext(context.Background())
	w = httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if _, e = os.Stat(cfgPath); e != nil {
		t.Fatal(e)
	}
}
