package server

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

func TestCarrierPerformance_LaneScopeRateAndRevocation(t *testing.T) {
	udp := wstransport.NewUDPBind(0, nil)
	bind, err := wstransport.NewAdaptiveBind(1, wstransport.Carrier{
		Name: protocol.CarrierDirectUDP, Bind: udp, DatagramMax: 1500,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bind.Close() })
	session := newAdaptiveSession()
	session.Performance = true
	ep, err := bind.RegisterLane(session.LaneID, 1452)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := udp.ParseEndpoint("127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	if err := bind.InstallQualifiedPath(ep, 0, wstransport.QualifiedPath{
		ID: protocol.CarrierDirectUDP, Carrier: protocol.CarrierDirectUDP, Endpoint: remote,
		SendMax: 1452, ReceiveMax: 1452, ValidUntil: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := bind.CommitPath(ep, protocol.CarrierDirectUDP, 0); err != nil {
		t.Fatal(err)
	}

	s := &Server{
		sessions: NewSessions(),
		adaptive: &adaptiveServerPlane{bind: bind, lanes: map[string]*serverCarrierLane{
			session.LaneID: {endpoint: ep, started: time.Now().Add(-time.Second)},
		}},
	}
	v := s.sessions.Create(CreateParams{
		TTL: time.Minute, TunnelIP: "100.78.0.2", Adaptive: session,
		Tunnels: []protocol.Tunnel{{Name: "approved"}},
	})
	stats := s.statsFor(v.TunnelIP, "approved")
	stats.toTarget.Add(100)
	stats.fromTarget.Add(350)
	s.statsFor(v.TunnelIP, "excluded").toTarget.Add(20_000)
	s.statsFor("100.78.0.3", "approved").fromTarget.Add(50_000)

	get := func(token, lane string, secured bool, status int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/v1/transport/lanes/"+lane+"/performance", nil)
		if secured {
			r.TLS = &tls.ConnectionState{}
		}
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("feedback status %d, want %d", w.Code, status)
		}
		return w
	}
	get(v.Token, session.LaneID, false, http.StatusUnauthorized)
	get(v.Token, newAdaptiveSession().LaneID, true, http.StatusNotFound)
	old := *session
	old.Performance = false
	legacy := s.sessions.Create(CreateParams{TTL: time.Minute, TunnelIP: "100.78.0.4", Adaptive: &old})
	get(legacy.Token, old.LaneID, true, http.StatusNotFound)
	reply := get(v.Token, session.LaneID, true, http.StatusOK)
	var sample protocol.CarrierPerformance
	if err := json.Unmarshal(reply.Body.Bytes(), &sample); err != nil || sample.ReceivedBytes != 100 ||
		sample.OfferedBytes != 350 || sample.AuthGeneration != 1 || sample.PathEpoch != 1 ||
		sample.Primary != protocol.CarrierDirectUDP || sample.ElapsedUS < 1_000_000 ||
		reply.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected lane feedback: %+v, %v", sample, err)
	}
	throttled := get(v.Token, session.LaneID, true, http.StatusTooManyRequests)
	if throttled.Header().Get("Retry-After") != "1" {
		t.Fatal("missing retry interval")
	}
	s.sessions.Delete(v.Token)
	get(v.Token, session.LaneID, true, http.StatusUnauthorized)
}
