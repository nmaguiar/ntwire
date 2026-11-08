package server

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/client"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

func primaryOf(paths []wstransport.PathStatus) string {
	for _, p := range paths {
		if p.Primary {
			return p.Name
		}
	}
	return ""
}

// TestPromotion_EndToEnd covers path-promote-v1: only when both the server
// (transport.promotion) and the client (Options.Promote) opt in does a
// healthy WSS-bootstrapped session move both directions to direct UDP.
func TestPromotion_EndToEnd(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		serverOn, clientOn    bool
		wantPromoted, wantCap bool
	}{
		{"both opted in", true, true, true, true},
		{"server off", false, true, false, false},
		{"client off", true, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, keyPath, _ := newTestServer(t, nil)
			port := freeUDPPort(t)
			s.Config.Network.TunnelCIDR = "100.66.0.0/16"
			s.Config.Listen.WireGuard = "127.0.0.1:" + fmt.Sprint(port)
			s.Config.Network.AdvertisedEndpoint = "127.0.0.1:" + fmt.Sprint(port)
			s.Config.Transport.Promotion = tc.serverOn
			if err := s.StartDataPlane(); err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			httpSrv := httptest.NewTLSServer(s.Handler())
			defer httpSrv.Close()
			conn, err := client.ConnectWithOptions(httpSrv.URL, keyPath, protocol.ClientInfo{OS: "darwin"}, client.Options{
				Insecure: true, NoWebUI: true, StatusFile: filepath.Join(t.TempDir(), "status.json"),
				Promote: tc.clientOn, Multipath: &client.MultipathOptions{PromotionQualifyingProbes: 2},
			})
			if err != nil {
				t.Fatalf("ConnectWithOptions() = %v", err)
			}
			defer conn.Close()
			if got := protocol.HasCapability(conn.Response.TransportCapabilities, protocol.CapabilityPathPromoteV1); got != tc.wantCap {
				t.Fatalf("negotiated path-promote-v1 = %v, want %v", got, tc.wantCap)
			}
			wait := 8 * time.Second
			if !tc.wantPromoted {
				wait = 5 * time.Second
			}
			deadline := time.Now().Add(wait)
			var clientPrimary, serverPrimary string
			for time.Now().Before(deadline) {
				clientPrimary = primaryOf(conn.Status().Paths)
				serverPrimary = primaryOf(s.data.multipath.PeerPaths(conn.Stack.PublicKey()))
				if tc.wantPromoted && clientPrimary == "direct-udp" && serverPrimary == "direct-udp" {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if tc.wantPromoted {
				if clientPrimary != "direct-udp" || serverPrimary != "direct-udp" {
					t.Fatalf("primaries client=%q server=%q, want both direct-udp; client paths %+v; server paths %+v", clientPrimary, serverPrimary, conn.Status().Paths, s.data.multipath.PeerPaths(conn.Stack.PublicKey()))
				}
				promoted := false
				for _, e := range conn.TransportDetails().Events {
					promoted = promoted || (e.Reason == wstransport.SwitchPromoted && e.To == "direct-udp")
				}
				if !promoted {
					t.Fatalf("no promoted switch event: %+v", conn.TransportDetails().Events)
				}
				return
			}
			if clientPrimary != "wss" || serverPrimary != "wss" {
				t.Fatalf("primaries client=%q server=%q, want both to stay on wss", clientPrimary, serverPrimary)
			}
		})
	}
}

func TestPromoteTransport_RejectsWithoutOptIn(t *testing.T) {
	s, _, _ := newTestServer(t, nil)
	h := s.Handler()
	body := []byte(`{"path":"direct-udp"}`)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/transport/primary", bytes.NewReader(body)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", rec.Code)
	}

	sess := s.sessions.Create(CreateParams{Method: "ssh", Identity: "alice", Multipath: true, TTL: time.Minute})
	req := httptest.NewRequest(http.MethodPost, "/v1/transport/primary", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+sess.Token)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status without transport.promotion = %d, want 404", rec.Code)
	}

	s.Config.Transport.Promotion = true
	req = httptest.NewRequest(http.MethodPost, "/v1/transport/primary", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+sess.Token)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status for a session that did not negotiate path-promote-v1 = %d, want 404", rec.Code)
	}
}

func TestPromoteTransport_ValidatesAndRateLimits(t *testing.T) {
	s, _, _ := newTestServer(t, nil)
	s.Config.Transport.Promotion = true
	h := s.Handler()
	sess := s.sessions.Create(CreateParams{Method: "ssh", Identity: "alice", Multipath: true, Promote: true, TTL: time.Minute})
	post := func(body string) int {
		req := httptest.NewRequest(http.MethodPost, "/v1/transport/primary", bytes.NewReader([]byte(body)))
		req.Header.Set("Authorization", "Bearer "+sess.Token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := post(`{"path":"carrier-pigeon"}`); code != http.StatusBadRequest {
		t.Fatalf("invalid path status = %d, want 400", code)
	}
	if code := post(`{"path":"auto"}`); code != http.StatusBadRequest {
		t.Fatalf("auto path status = %d, want 400", code)
	}
	if code := post(`{"path":"direct-udp"}`); code != http.StatusConflict {
		t.Fatalf("no data plane status = %d, want 409", code)
	}
	if code := post(`{"path":"direct-udp"}`); code != http.StatusTooManyRequests {
		t.Fatalf("second attempt status = %d, want 429", code)
	}
}
