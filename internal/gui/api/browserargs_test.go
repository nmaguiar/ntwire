package api

import (
	"github.com/nmaguiar/ntwire/internal/gui/config"
	"net/http"
	"reflect"
	"testing"
)

func TestBrowserArgumentsAPI(t *testing.T) {
	s := newTestServer(t)
	want := []string{"--custom=a b", "--custom=a b"}
	resp := s.do(t, http.MethodPut, "/api/settings", config.Settings{BrowserArgs: want})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("global save %d", resp.StatusCode)
	}
	resp.Body.Close()
	got := decode[config.Settings](t, s.get(t, "/api/settings"))
	if !reflect.DeepEqual(got.BrowserArgs, want) {
		t.Fatalf("globals %q", got.BrowserArgs)
	}
	resp = s.do(t, http.MethodPut, "/api/settings", config.Settings{BrowserArgs: []string{"--proxy-server=x"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid global save %d", resp.StatusCode)
	}
	resp.Body.Close()
	got = decode[config.Settings](t, s.get(t, "/api/settings"))
	if !reflect.DeepEqual(got.BrowserArgs, want) {
		t.Fatal("invalid save changed globals")
	}
	p := decode[config.Profile](t, s.do(t, http.MethodPost, "/api/profiles", config.Profile{Name: "test", Server: "https://example.com", BrowserArgs: want, BrowserArgsMode: "append"}))
	if p.BrowserArgsMode != "append" || !reflect.DeepEqual(p.BrowserArgs, want) {
		t.Fatalf("profile round trip %+v", p)
	}
	p.BrowserArgsMode = "replace"
	p.BrowserArgs = []string{}
	resp = s.do(t, http.MethodPut, "/api/profiles/"+p.ID, p)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("empty replace save %d", resp.StatusCode)
	}
	resp.Body.Close()
	p.BrowserArgsMode = "bad"
	resp = s.do(t, http.MethodPut, "/api/profiles/"+p.ID, p)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid mode save %d", resp.StatusCode)
	}
	resp.Body.Close()
}
