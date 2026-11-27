package server

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
)

type failedLaneRemoval struct{ serverStack }

func (failedLaneRemoval) RemovePeer(string) error { return errors.New("fixture peer removal failure") }

func TestAdaptiveMultiLane_ReplayGrantFencingAndCleanup(t *testing.T) {
	cfg := Config{}
	cfg.Transport.Adaptive, cfg.Transport.AdaptiveMaxLanes = true, 3
	cfg.Network.TunnelCIDR = "100.76.0.0/24"
	cfg.Listen.WireGuard = "127.0.0.1:0"
	s := New(cfg, nil)
	if err := s.StartUserspaceDataPlane(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	generate := func() string {
		t.Helper()
		key, err := wgnet.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		return key.Public
	}
	anchor := newAdaptiveSession()
	anchor.MaxLanes = 3
	key := generate()
	s.operationMu.Lock()
	lifetime, err := s.adaptive.add(anchor, key, "100.76.0.2")
	if err != nil {
		s.operationMu.Unlock()
		t.Fatal(err)
	}
	parent := s.sessions.Create(CreateParams{TTL: time.Minute, TunnelIP: "100.76.0.2",
		WireGuardPublicKey: key, Adaptive: anchor, FlowLifetime: lifetime,
		Tunnels: []protocol.Tunnel{{Name: "kept"}, {Name: "revoked"}}})
	s.operationMu.Unlock()

	control := func(method, path, bearer string, request protocol.LaneRequest, tlsEnabled bool, status int) []byte {
		t.Helper()
		body, _ := json.Marshal(request)
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		if tlsEnabled {
			r.TLS = &tls.ConnectionState{}
		}
		r.Header.Set("Authorization", "Bearer "+bearer)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("%s %s got %d, want %d: %s", method, path, w.Code, status, w.Body)
		}
		return w.Body.Bytes()
	}
	create := func(req protocol.LaneRequest) protocol.LaneDescriptor {
		t.Helper()
		response := control(http.MethodPost, "/v1/session/lanes", parent.Token, req, true, http.StatusOK)
		var lane protocol.LaneDescriptor
		if err := json.Unmarshal(response, &lane); err != nil || !lane.Adaptive.Child || lane.State != "creating" {
			t.Fatalf("invalid child descriptor %+v: %v", lane, err)
		}
		return lane
	}
	request := protocol.LaneRequest{RequestID: "AAAAAAAAAAAAAAAAAAAAAA", Generation: 1, WireGuardPublicKey: generate()}
	control(http.MethodPost, "/v1/session/lanes", parent.Token, request, false, http.StatusUnauthorized)
	child := create(request)
	if replay := create(request); replay.Adaptive.LaneID != child.Adaptive.LaneID || replay.TunnelIP != child.TunnelIP {
		t.Fatal("lost create reply allocated another child")
	}
	conflict := request
	conflict.WireGuardPublicKey = generate()
	control(http.MethodPost, "/v1/session/lanes", parent.Token, conflict, true, http.StatusConflict)
	principal, ok := s.principalForIP(child.TunnelIP)
	if !ok || !principal.Tunnels["revoked"] || principal.peerLifetime != child.Adaptive.LaneID || !s.sessions.childKeyInUse(request.WireGuardPublicKey) {
		t.Fatal("child did not inherit indexed parent grants")
	}

	s.operationMu.Lock()
	renewed, ok := s.sessions.renew(parent.Token, []protocol.Tunnel{{Name: "kept"}}, time.Minute, protocol.ClientInfo{}, s.adaptive.resetFlows)
	if ok {
		s.adaptive.renew(renewed)
	}
	s.operationMu.Unlock()
	if !ok || principal.flowLifetime.Err() == nil || lifetime.Err() == nil {
		t.Fatal("revoked grants did not fence existing parent and child forwarding")
	}
	if now, ok := s.principalForIP(child.TunnelIP); !ok || now.Tunnels["revoked"] || !now.Tunnels["kept"] || now.flowLifetime.Err() != nil {
		t.Fatal("child authorization did not follow renewal")
	}
	control(http.MethodPost, "/v1/session/lanes", parent.Token, request, true, http.StatusUnauthorized)
	parent = renewed
	control(http.MethodPost, "/v1/session/lanes", parent.Token, request, true, http.StatusConflict)

	retire := protocol.LaneRequest{RequestID: "AQAAAAAAAAAAAAAAAAAAAA", Generation: 2}
	s.operationMu.Lock()
	originalStack := s.adaptive.data.stack
	s.adaptive.data.stack = failedLaneRemoval{originalStack}
	s.operationMu.Unlock()
	t.Cleanup(func() {
		s.operationMu.Lock()
		s.adaptive.data.stack = originalStack
		s.operationMu.Unlock()
	})
	path := "/v1/session/lanes/" + child.Adaptive.LaneID
	control(http.MethodDelete, path, parent.Token, retire, true, http.StatusNoContent)
	control(http.MethodDelete, path, parent.Token, retire, true, http.StatusNoContent)
	if _, ok := s.principalForIP(child.TunnelIP); ok || !s.adaptive.isQuarantinedIP(child.TunnelIP) {
		t.Fatal("backend failure left the address authorized or reusable")
	}
	duplicate := protocol.LaneRequest{RequestID: "AgAAAAAAAAAAAAAAAAAAAA", Generation: 2, WireGuardPublicKey: request.WireGuardPublicKey}
	control(http.MethodPost, "/v1/session/lanes", parent.Token, duplicate, true, http.StatusForbidden)

	// Test the timer path with a real registered peer that never handshakes.
	s.operationMu.Lock()
	s.adaptive.data.stack = originalStack
	s.adaptive.lanes[anchor.LaneID].lastLaneCreate = time.Time{}
	s.operationMu.Unlock()
	pending := create(protocol.LaneRequest{RequestID: duplicate.RequestID, Generation: 2, WireGuardPublicKey: generate()})
	s.operationMu.Lock()
	s.adaptive.lanes[pending.Adaptive.LaneID].started = time.Now().Add(-laneQualificationTimeout)
	s.reapSessionsLocked()
	s.operationMu.Unlock()
	control(http.MethodGet, "/v1/transport/lanes/"+pending.Adaptive.LaneID+"/candidates", parent.Token, protocol.LaneRequest{}, true, http.StatusNotFound)
	if _, ok := s.principalForIP(pending.TunnelIP); ok {
		t.Fatal("abandoned lane retained forwarding grants")
	}
}
