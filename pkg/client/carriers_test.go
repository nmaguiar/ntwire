package client

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/server"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
)

type recordedCarrier struct {
	conn   net.Conn
	ticket string
}

type carrierUpgradeRecorder struct {
	http.ResponseWriter
	carriers chan<- recordedCarrier
	ticket   string
}

func (w carrierUpgradeRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, buffered, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err == nil {
		w.carriers <- recordedCarrier{conn: c, ticket: w.ticket}
	}
	return c, buffered, err
}

func TestAdaptiveCarrier_ConnectRenewRedialAndRevoke(t *testing.T) {
	f := newReconnectFixture(t)
	multipath := false
	s := f.startServerWithTransport("100.72.0.0/24", 18100, true, server.TransportConfig{Adaptive: true, Multipath: &multipath})
	handler := s.Handler()
	carriers := make(chan recordedCarrier, 16)
	h := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == protocol.CarrierWSSPath {
			w = carrierUpgradeRecorder{ResponseWriter: w, carriers: carriers, ticket: r.Header.Get(protocol.CarrierTicketHeader)}
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(h.Close)
	ca := filepath.Join(f.dir, "server.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	legacyKey, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := authenticateSSH(h.Client(), h.URL, f.key, protocol.ClientInfo{}, legacyKey.Public, Options{})
	if err != nil || legacy.Adaptive != nil || legacy.UDP == "" || legacy.WebSocket == "" {
		t.Fatalf("legacy login lost its ordinary transport advertisement: %v", err)
	}
	c, err := ConnectWithOptions(h.URL, f.key, protocol.ClientInfo{}, Options{
		AdaptiveCarrier: true, CAFile: ca, NoWebUI: true, NoSystemProxy: true,
		StatusFile: filepath.Join(f.dir, "adaptive.json"), Logger: slog.New(slog.DiscardHandler), renewInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	if c.Response.Adaptive == nil || c.Response.Multipath || c.Response.UDP != "" || c.network.adaptive == nil {
		t.Fatal("client did not negotiate an isolated adaptive lane")
	}
	first, bearer, _ := c.network.adaptive.credentials()
	stack := c.Stack
	origin := h.URL + "/v1/transport/lanes/" + first.LaneID
	control := func(method, endpoint, token string, body []byte, want int, tickets ...string) []byte {
		t.Helper()
		req, err := http.NewRequest(method, endpoint, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		for _, ticket := range tickets {
			req.Header.Set(protocol.CarrierTicketHeader, ticket)
		}
		resp, err := h.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != want {
			t.Fatalf("%s %s got status %d, want %d, read err %v", method, endpoint, resp.StatusCode, want, err)
		}
		return data
	}
	control(http.MethodGet, origin+"/candidates", legacy.Token, nil, http.StatusNotFound)
	control(http.MethodGet, h.URL+"/v1/wg", bearer, nil, http.StatusNotFound)
	control(http.MethodGet, h.URL+protocol.CarrierWSSPath, bearer, nil, http.StatusUnauthorized)
	tcp, err := net.DialTimeout("tcp", c.LocalAddresses[0], 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	echo := func(msg string) {
		t.Helper()
		_ = tcp.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.WriteString(tcp, msg); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(tcp, buf); err != nil || string(buf) != msg {
			lastHandshake, _, _ := stack.LastHandshake(c.Response.ServerPublicKey)
			t.Fatalf("TCP echo for %q = %q, %v (last handshake %v, transport %+v)", msg, buf, err, lastHandshake, c.TransportInfo())
		}
	}
	echo("original lane")
	udp, err := net.Dial("udp", c.LocalAddresses[1])
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udpRoundTrip(t, udp)
	var snapshot protocol.CarrierCandidates
	if err := json.Unmarshal(control(http.MethodGet, origin+"/candidates", bearer, nil, http.StatusOK), &snapshot); err != nil || snapshot.PathEpoch != 1 || snapshot.Selected != protocol.CarrierWSS {
		t.Fatalf("initial adaptive path = %+v, %v", snapshot, err)
	}
	var original recordedCarrier
	select {
	case original = <-carriers:
	case <-time.After(5 * time.Second):
		t.Fatal("original carrier was not observed")
	}
	control(http.MethodGet, h.URL+protocol.CarrierWSSPath, bearer, nil, http.StatusUnauthorized, original.ticket)
	control(http.MethodPost, origin+"/attach", bearer, []byte(`{"request_id":"invalid"}`), http.StatusBadRequest)
	control(http.MethodPost, origin+"/attach", bearer, []byte(`{"request_id":"AAAAAAAAAAAAAAAAAAAAAA","auth_generation":1,"expected_path_epoch":0,"candidate_id":"wss"}`), http.StatusConflict)
	if err := c.renew(); err != nil {
		t.Fatal(err)
	}
	second, newBearer, _ := c.network.adaptive.credentials()
	if second.ParentID != first.ParentID || second.LaneID != first.LaneID || second.AuthGeneration != first.AuthGeneration+1 || bearer == newBearer || c.Stack != stack {
		t.Fatal("renewal did not rotate credentials on the original lane")
	}
	control(http.MethodGet, origin+"/candidates", bearer, nil, http.StatusUnauthorized)
	echo("before redial")
	_ = original.conn.Close()
	select {
	case <-carriers:
	case <-time.After(8 * time.Second):
		t.Fatal("adaptive carrier did not redial with the renewed bearer")
	}
	deadline := time.Now().Add(8 * time.Second)
	for info := c.TransportInfo(); info.PathEpoch != 2 || info.Active != protocol.CarrierWSS; info = c.TransportInfo() {
		if time.Now().After(deadline) {
			t.Fatalf("adaptive carrier was not committed after redial: %+v", info)
		}
		time.Sleep(10 * time.Millisecond)
	}
	echo("same TCP stream after redial")
	_, newBearer, _ = c.network.adaptive.credentials()
	if err := json.Unmarshal(control(http.MethodGet, origin+"/candidates", newBearer, nil, http.StatusOK), &snapshot); err != nil || snapshot.PathEpoch != 2 {
		t.Fatalf("reattached adaptive path = %+v, %v", snapshot, err)
	}
	control(http.MethodPost, h.URL+"/v1/disconnect", newBearer, nil, http.StatusNoContent)
	control(http.MethodGet, origin+"/candidates", newBearer, nil, http.StatusUnauthorized)
	control(http.MethodPost, h.URL+"/v1/renew", legacy.Token, []byte(`{}`), http.StatusOK)
}

func TestAdaptiveCarrier_DirectUDPStandbyAfterDemand(t *testing.T) {
	testAdaptiveUDPStandby(t, true, 0)
}

func TestAdaptiveCarrier_DirectUDPStaysOnWSSAtLimitedOuterMTU(t *testing.T) {
	if os.Getenv("NTWIRE_TEST_LIMITED_UDP_MTU") != "1" {
		t.Skip("requires an isolated network namespace with loopback MTU below 1480")
	}
	testAdaptiveUDPStandby(t, false, 0)
}

func TestAdaptiveCarrier_DirectUDPStandbyWithReducedMTU(t *testing.T) {
	testAdaptiveUDPStandby(t, true, 1280)
}

func TestAdaptiveCarrier_AlternateUDPKeepsPeerAcrossSwitchAndRenewal(t *testing.T) {
	f := newReconnectFixture(t)
	// Reserve two distinct ports before starting the adaptive server.
	primary, alternate := reserveAdaptiveUDPTestPorts(t)
	multipath := false
	s := f.startServerWithTransport("100.73.0.0/24", 18121, true,
		server.TransportConfig{Adaptive: true, AdaptiveUDPPort: primary, AdaptiveUDPAltPort: alternate,
			AdaptiveTunnelMTU: 1280, Multipath: &multipath})
	h := httptest.NewTLSServer(s.Handler())
	t.Cleanup(h.Close)
	ca := filepath.Join(f.dir, "udp-alt-server.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := ConnectWithOptions(h.URL, f.key, protocol.ClientInfo{}, Options{
		AdaptiveCarrier: true, CAFile: ca, NoWebUI: true, NoSystemProxy: true, IPVersion: "4",
		StatusFile: filepath.Join(f.dir, "adaptive-udp-alt.json"), Logger: slog.New(slog.DiscardHandler), renewInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	a := c.network.adaptive
	info, _, _ := a.credentials()
	if a.udp == nil || a.altUDP == nil || !protocol.HasCapability(c.Response.TransportCapabilities, protocol.CapabilityAdaptiveUDPAltV1) ||
		info.AlternateUDP != net.JoinHostPort("127.0.0.1", strconv.Itoa(alternate)) {
		t.Fatalf("alternate candidate was not negotiated: %+v", info)
	}
	if !a.beginExploration(time.Now()) {
		t.Fatal("could not reserve the lane's qualification slot")
	}
	defer a.exploration.Store(false)
	echo := newQUICTCPEcho(t, c)
	echo("anchor over WSS")
	stack, key := c.Stack, c.Response.ServerPublicKey
	before, _, err := stack.LastHandshake(key)
	if err != nil || before.IsZero() {
		t.Fatalf("missing anchor handshake: %v, %v", before, err)
	}
	for _, path := range []string{protocol.CarrierDirectUDP, protocol.CarrierAlternateUDP} {
		if err := a.qualifyUDP(t.Context(), path); err != nil {
			t.Fatalf("qualify %s: %v", path, err)
		}
		if err := a.selectPrimary(t.Context(), path); err != nil {
			t.Fatalf("switch to %s: %v", path, err)
		}
		if current := c.TransportDetails(); current.Active != path {
			t.Fatalf("reported path %q, want %q", current.Active, path)
		}
		echo("existing flow over " + path)
	}
	if err := c.renew(); err != nil {
		t.Fatal(err)
	}
	if a.bind.HasQualifiedPath(a.lane, protocol.CarrierDirectUDP) || !a.bind.HasQualifiedPath(a.lane, protocol.CarrierAlternateUDP) {
		t.Fatal("renewal must retain only the selected native UDP proof")
	}
	echo("existing flow after renewal")
	started := time.Now()
	if err := a.altUDP.socket.Close(); err != nil {
		t.Fatal(err)
	}
	echo("existing flow after alternate UDP socket loss")
	if current := c.TransportInfo(); current.Active != protocol.CarrierWSS {
		t.Fatalf("active path after alternate UDP loss = %q", current.Active)
	}
	t.Logf("alternate UDP close to TCP delivery over WSS: %s", time.Since(started))
	if after, _, err := stack.LastHandshake(key); c.Stack != stack || err != nil || !before.Equal(after) {
		t.Fatalf("WireGuard peer changed during switching: %v -> %v, %v", before, after, err)
	}
}

func reserveAdaptiveUDPTestPorts(t *testing.T) (int, int) {
	t.Helper()
	listen := func() *net.UDPConn {
		p, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	primary := listen()
	defer primary.Close()
	alternate := listen()
	defer alternate.Close()
	return primary.LocalAddr().(*net.UDPAddr).Port, alternate.LocalAddr().(*net.UDPAddr).Port
}

func testAdaptiveUDPStandby(t *testing.T, wantQualified bool, mtu int) {
	t.Helper()
	f := newReconnectFixture(t)
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()
	multipath := false
	s := f.startServerWithTransport("100.73.0.0/24", 18120, true,
		server.TransportConfig{Adaptive: true, AdaptiveUDPPort: port, AdaptiveTunnelMTU: mtu, Multipath: &multipath})
	var prepares atomic.Int32
	handler := s.Handler()
	h := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/udp/prepare") {
			prepares.Add(1)
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(h.Close)
	ca := filepath.Join(f.dir, "udp-server.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := ConnectWithOptions(h.URL, f.key, protocol.ClientInfo{}, Options{
		AdaptiveCarrier: true, CAFile: ca, NoWebUI: true, NoSystemProxy: true, IPVersion: "4",
		StatusFile: filepath.Join(f.dir, "adaptive-udp.json"), Logger: slog.New(slog.DiscardHandler), renewInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	if c.network.adaptive == nil || c.network.adaptive.udp == nil || c.Response.Adaptive.DirectUDP != net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) {
		t.Fatal("a dedicated UDP candidate was not negotiated")
	}
	a := c.network.adaptive
	auth, bearer, _ := a.credentials()
	wantMTU := mtu
	if wantMTU == 0 {
		wantMTU = wgnet.DefaultMTU
	}
	if auth.TunnelMTU != wantMTU {
		t.Fatalf("negotiated MTU %d, want %d", auth.TunnelMTU, wantMTU)
	}
	body, err := json.Marshal(protocol.CarrierAttachRequest{
		RequestID: "AAAAAAAAAAAAAAAAAAAAAA", Generation: auth.AuthGeneration,
		ExpectedEpoch: 1, Candidate: protocol.CarrierDirectUDP,
	})
	if err != nil {
		t.Fatal(err)
	}
	var offer protocol.CarrierUDPOffer
	err = a.controlRequest(t.Context(), http.MethodPost, h.URL+"/v1/transport/lanes/"+auth.LaneID+"/udp/prepare", bearer, body, &offer)
	var httpErr *carrierHTTPError
	if !errors.As(err, &httpErr) || httpErr.status != http.StatusConflict || c.TransportInfo().UDPQualified {
		t.Fatalf("UDP prepared before a WireGuard handshake: %v", err)
	}
	tcpRoundTrip(t, c.LocalAddresses[0])
	deadline := time.Now().Add(12 * time.Second)
	if !wantQualified {
		for time.Now().Before(deadline) {
			info := c.TransportInfo()
			if info.Active != protocol.CarrierWSS || info.UDPQualified {
				t.Fatalf("an undersized path changed the primary or qualified: %+v", info)
			}
			time.Sleep(50 * time.Millisecond)
		}
		if prepares.Load() < 2 {
			t.Fatal("client did not attempt qualification after demand")
		}
		tcpRoundTrip(t, c.LocalAddresses[0])
		return
	}
	for current := c.TransportInfo(); ; current = c.TransportInfo() {
		if current.UDPQualified {
			if current.Active != protocol.CarrierWSS || current.UDPProbeRTT <= 0 || current.PathEpoch != 1 {
				t.Fatalf("unexpected qualified standby state: %+v", current)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("direct UDP did not qualify: %+v", current)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := c.renew(); err != nil {
		t.Fatal(err)
	}
	if current := c.TransportInfo(); current.UDPQualified || current.Active != protocol.CarrierWSS {
		t.Fatalf("renewal did not invalidate the standby proof: %+v", current)
	}
	tcpRoundTrip(t, c.LocalAddresses[0])
}
