package server

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
)

func TestAdaptiveCarrier_AttachIdempotenceExpiryAndRevocation(t *testing.T) {
	cfg := Config{}
	cfg.Transport.Adaptive = true
	cfg.Network.TunnelCIDR = "100.73.0.0/24"
	cfg.Listen.WireGuard = "127.0.0.1:0"
	s := New(cfg, nil)
	if err := s.StartUserspaceDataPlane(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	key, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	anchor := newAdaptiveSession()
	ctx, err := s.adaptive.add(anchor, key.Public, "100.73.0.2")
	if err != nil {
		t.Fatal(err)
	}
	v := s.sessions.Create(CreateParams{TTL: time.Minute, TunnelIP: "100.73.0.2", WireGuardPublicKey: key.Public, Adaptive: anchor, FlowLifetime: ctx})
	attach := func(id string, secured bool, status int) string {
		t.Helper()
		body := `{"request_id":"` + id + `","auth_generation":1,"expected_path_epoch":0,"candidate_id":"wss"}`
		r := httptest.NewRequest(http.MethodPost, "/v1/transport/lanes/"+anchor.LaneID+"/attach", strings.NewReader(body))
		if secured {
			r.TLS = &tls.ConnectionState{}
		}
		r.Header.Set("Authorization", "Bearer "+v.Token)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("attach status %d, want %d", w.Code, status)
		}
		if status != http.StatusOK {
			return ""
		}
		var reply protocol.CarrierAttachResponse
		if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil || reply.Ticket == "" || reply.ExpiresInMS <= 0 {
			t.Fatal("invalid attach response")
		}
		return reply.Ticket
	}
	const a = "AAAAAAAAAAAAAAAAAAAAAA"
	const b = "AQAAAAAAAAAAAAAAAAAAAA"
	attach(a, false, http.StatusUnauthorized)
	first := attach(a, true, http.StatusOK)
	if got := attach(a, true, http.StatusOK); first != got {
		t.Fatal("idempotent request created another ticket")
	}
	attach(b, true, http.StatusTooManyRequests)
	lane := s.adaptive.lanes[anchor.LaneID]
	s.operationMu.Lock()
	lane.attach.expires = time.Now().Add(-time.Second)
	lane.attach.issued = lane.attach.expires
	s.operationMu.Unlock()
	second := attach(b, true, http.StatusOK)
	if first == second {
		t.Fatal("expired ticket was reused")
	}
	attach(a, true, http.StatusTooManyRequests) // Another ticket is pending.
	s.operationMu.Lock()
	lane.attach.expires = time.Now().Add(-time.Second)
	lane.attach.issued = lane.attach.expires
	s.operationMu.Unlock()
	attach(a, true, http.StatusConflict)
	s.operationMu.Lock()
	s.sessions.Delete(v.Token)
	s.dropSession(v)
	s.operationMu.Unlock()
	attach(b, true, http.StatusUnauthorized)
	if ctx.Err() == nil {
		t.Fatal("revocation did not cancel forwarder lifetime")
	}
	if _, _, ok := s.adaptive.bind.LaneState(lane.endpoint); ok {
		t.Fatal("revoked lane still registered")
	}
}

func TestAdaptiveCarrier_OptionalEnrollmentAtCapacity(t *testing.T) {
	cfg := Config{}
	cfg.Transport.Adaptive = true
	cfg.Auth.SessionTTL = time.Minute
	cfg.Network.TunnelCIDR = "100.73.8.0/24"
	cfg.Listen.WireGuard = "127.0.0.1:0"
	s := New(cfg, nil)
	if err := s.StartUserspaceDataPlane(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	// Simulate occupied capacity without creating a second network stack
	// or generating load for each slot.
	s.operationMu.Lock()
	s.adaptive.retiredMu.Lock()
	s.adaptive.retired = make(map[string]string)
	for i := range adaptiveLaneLimit {
		s.adaptive.retired[fmt.Sprint(i)] = fmt.Sprint(i)
	}
	s.adaptive.retiredMu.Unlock()
	s.operationMu.Unlock()

	for _, tc := range []struct {
		name     string
		required []string
		status   int
	}{
		{name: "optional", status: http.StatusOK},
		{name: "required", required: []string{protocol.CapabilityAdaptiveCarrierV1}, status: http.StatusTooManyRequests},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := wgnet.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, "https://localhost/v1/auth", nil)
			w := httptest.NewRecorder()
			s.operationMu.Lock()
			s.establishSession(w, r, sessionRequest{
				Method: "ssh", Identity: tc.name, WireGuardPublicKey: key.Public,
				TransportCapabilities:         []string{protocol.CapabilityAdaptiveCarrierV1, protocol.CapabilityMultipathV3},
				RequiredTransportCapabilities: tc.required,
			}, nil)
			s.operationMu.Unlock()
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
			if tc.required == nil {
				var response protocol.AuthResponse
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response.Adaptive != nil || response.WebSocket == "" {
					t.Fatalf("expected authorized legacy WireGuard at capacity, got %+v, %v", response, err)
				}
			}
		})
	}
}
