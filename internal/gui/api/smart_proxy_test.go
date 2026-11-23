package api

import (
	"net"
	"net/http"
	"testing"

	"github.com/nmaguiar/ntwire/pkg/egressrouter"
)

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
