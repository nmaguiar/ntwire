package server

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

// fakeReflector is a minimal stand-in for pkg/relay's UDP reflector, used so
// server-side tests can exercise EnableDirectUpgrade/selfReflect without
// spinning up a whole ntwire-relay.
func fakeReflector(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback UDP unavailable: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			typ, _, ok := wstransport.DecodeControlFrame(buf[:n])
			if !ok || typ != wstransport.FrameReflectRequest {
				continue
			}
			reply := wstransport.EncodeControlFrame(wstransport.FrameReflectResponse, []byte(addr.String()))
			_, _ = pc.WriteTo(reply, addr)
		}
	}()
	return pc.LocalAddr().String()
}

func TestAdvertisedUDPEndpointResolvesHostname(t *testing.T) {
	s, _, _ := newTestServer(t, nil)
	s.Config.Network.AdvertisedEndpoint = "localhost:51820"
	got := s.advertisedUDPEndpoint()
	host, port, err := net.SplitHostPort(got)
	if err != nil {
		t.Fatalf("advertisedUDPEndpoint() = %q, not host:port: %v", got, err)
	}
	if port != "51820" {
		t.Fatalf("port = %q, want 51820", port)
	}
	if host != "127.0.0.1" && host != "::1" {
		t.Fatalf("host = %q, want a resolved loopback literal", host)
	}
}

func TestAdvertisedUDPEndpointPassesThroughLiteralIP(t *testing.T) {
	s, _, _ := newTestServer(t, nil)
	s.Config.Network.AdvertisedEndpoint = "203.0.113.5:51820"
	if got := s.advertisedUDPEndpoint(); got != "203.0.113.5:51820" {
		t.Fatalf("advertisedUDPEndpoint() = %q, want unchanged literal IP", got)
	}
}

func TestAdvertisedUDPEndpointEmptyStaysEmpty(t *testing.T) {
	s, _, _ := newTestServer(t, nil)
	if got := s.advertisedUDPEndpoint(); got != "" {
		t.Fatalf("advertisedUDPEndpoint() = %q, want empty", got)
	}
}

func TestAdvertisedUDPEndpointUnresolvableHostReturnsEmpty(t *testing.T) {
	s, _, _ := newTestServer(t, nil)
	s.Config.Network.AdvertisedEndpoint = "this-host-does-not-exist.invalid:51820"
	if got := s.advertisedUDPEndpoint(); got != "" {
		t.Fatalf("advertisedUDPEndpoint() = %q, want empty on DNS failure", got)
	}
}

func TestPunchRequiresValidSession(t *testing.T) {
	s, _, _ := newTestServer(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/punch", bytes.NewReader([]byte(`{}`)))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestPunchReturns404WhenDirectUpgradeDisabled(t *testing.T) {
	s, _, _ := newTestServer(t, nil)
	sess := s.sessions.Create(CreateParams{TTL: time.Minute})
	req := httptest.NewRequest(http.MethodPost, "/v1/punch", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer "+sess.Token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d (direct upgrade never enabled)", w.Code, http.StatusNotFound)
	}
}

// TestEnableDirectUpgradeSelfReflectsAndServesCandidate is the end-to-end
// happy path: EnableDirectUpgrade against a fake reflector should populate a
// self-reflected candidate that /v1/punch then hands back to an
// authenticated caller, alongside the relay's reflector address unchanged.
func TestEnableDirectUpgradeSelfReflectsAndServesCandidate(t *testing.T) {
	s, _, _ := newTestServer(t, nil)
	startTestDataPlane(t, s)
	reflectAddr := fakeReflector(t)

	s.EnableDirectUpgrade(reflectAddr)

	deadline := time.Now().Add(5 * time.Second)
	var candidate string
	for time.Now().Before(deadline) {
		s.mu.Lock()
		d := s.direct
		s.mu.Unlock()
		if d != nil {
			candidate = d.selfCandidate()
		}
		if candidate != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if candidate == "" {
		t.Fatal("self-reflection never produced a candidate")
	}

	sess := s.sessions.Create(CreateParams{TTL: time.Minute})
	req := httptest.NewRequest(http.MethodPost, "/v1/punch", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer "+sess.Token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	var resp protocol.PunchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ServerAddr != candidate {
		t.Errorf("PunchResponse.ServerAddr = %q, want %q", resp.ServerAddr, candidate)
	}
	if resp.RelayReflectAddr != reflectAddr {
		t.Errorf("PunchResponse.RelayReflectAddr = %q, want %q", resp.RelayReflectAddr, reflectAddr)
	}
}

// TestPunchPrimesReportedClientAddr checks the other half of /v1/punch: a
// request carrying ClientAddr should make the server fire NAT-priming pings
// straight at that address.
func TestPunchPrimesReportedClientAddr(t *testing.T) {
	s, _, _ := newTestServer(t, nil)
	startTestDataPlane(t, s)
	reflectAddr := fakeReflector(t)
	s.EnableDirectUpgrade(reflectAddr)

	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback UDP unavailable: %v", err)
	}
	defer listener.Close()

	sess := s.sessions.Create(CreateParams{TTL: time.Minute})
	body, _ := json.Marshal(protocol.PunchRequest{ClientAddr: listener.LocalAddr().String()})
	req := httptest.NewRequest(http.MethodPost, "/v1/punch", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+sess.Token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}

	_ = listener.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, _, err := listener.ReadFrom(buf)
	if err != nil {
		t.Fatalf("never received a NAT-priming ping: %v", err)
	}
	typ, _, ok := wstransport.DecodeControlFrame(buf[:n])
	if !ok || typ != wstransport.FramePrime {
		t.Fatalf("unexpected priming datagram: ok=%v typ=%d", ok, typ)
	}
}

func TestEnableDirectUpgradeWithEmptyAddrDisables(t *testing.T) {
	s, _, _ := newTestServer(t, nil)
	startTestDataPlane(t, s)
	reflectAddr := fakeReflector(t)

	s.EnableDirectUpgrade(reflectAddr)
	s.mu.Lock()
	enabled := s.direct != nil
	s.mu.Unlock()
	if !enabled {
		t.Fatal("EnableDirectUpgrade with a real address left s.direct nil")
	}

	s.EnableDirectUpgrade("")
	s.mu.Lock()
	disabled := s.direct == nil
	s.mu.Unlock()
	if !disabled {
		t.Fatal("EnableDirectUpgrade(\"\") left s.direct non-nil")
	}
}
