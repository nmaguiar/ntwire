package client

import (
	"context"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/relay"
	"github.com/nmaguiar/ntwire/pkg/server"
)

func TestAdaptiveRelay_QualifiesAndPreservesTCPAcrossCarrierFailures(t *testing.T) {
	f := newReconnectFixture(t)
	rl, closeRelay := startClientTestUDPRelay(f)
	logger := slog.New(slog.DiscardHandler)
	pool, err := server.NewRelayPool(server.RelayConfig{Enabled: true, Name: "home", IdentityFile: f.key,
		URL: "wss://" + rl.AgentsAddr().String(), Fingerprint: rl.Fingerprint()}, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	pool.Run(t.Context())
	deadline := time.Now().Add(5 * time.Second)
	for !pool.Healthy() {
		if time.Now().After(deadline) {
			t.Fatal("relay did not register")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cfg := f.serverConfig("100.76.0.0/24", 18142, false, server.TransportConfig{Adaptive: true})
	cfg.Relay.Enabled, cfg.Relay.AdaptiveUDP = true, true
	s := server.New(cfg, logger)
	s.SetRelayPool(pool)
	if err := s.StartUserspaceDataPlane(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	type transportConnContextKey struct{}
	var blockWSS atomic.Bool
	wssConn := make(chan net.Conn, 1)
	handler := s.Handler()
	h := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == protocol.CarrierWSSPath {
			if blockWSS.Load() {
				http.Error(w, "fixture WSS outage", http.StatusServiceUnavailable)
				return
			}
			select {
			case wssConn <- r.Context().Value(transportConnContextKey{}).(net.Conn):
			default:
			}
		}
		handler.ServeHTTP(w, r)
	}))
	h.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, transportConnContextKey{}, c)
	}
	h.StartTLS()
	t.Cleanup(h.Close)
	ca := filepath.Join(f.dir, "relay-fixture-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := ConnectWithOptions(h.URL, f.key, protocol.ClientInfo{}, Options{
		AdaptiveCarrier: true, CAFile: ca, NoWebUI: true, NoSystemProxy: true, IPVersion: "4",
		StatusFile: filepath.Join(f.dir, "status-relay.json"), Logger: logger, renewInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	a := c.network.adaptive
	if a == nil || a.relay == nil {
		t.Fatal("adaptive relay selection was not negotiated")
	}
	a.ws.SetRedialBackoff(100*time.Millisecond, time.Second, 3*time.Second)
	echo := newQUICTCPEcho(t, c)
	echo("initial websocket")
	waitRelayTrialObservation(t, c, echo, protocol.CarrierWSS)
	serverKey := c.Response.ServerPublicKey
	before, known, err := c.Stack.LastHandshake(serverKey)
	if err != nil || !known || before.IsZero() {
		t.Fatalf("WireGuard handshake unavailable: %v", err)
	}
	deadline = time.Now().Add(9 * time.Second)
	for {
		path := a.relay.current()
		if path.id != "" && a.bind.HasQualifiedPath(a.lane, path.id) {
			if path.rtt <= 0 {
				t.Fatal("qualified relay omitted its measured RTT")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("forwarding demand did not qualify a relay")
		}
		time.Sleep(20 * time.Millisecond)
	}
	blockWSS.Store(true)
	wssLost := time.Now()
	select {
	case live := <-wssConn:
		_ = live.Close()
	default:
		t.Fatal("fixture did not record the WebSocket connection")
	}
	waitCarrier(t, c, protocol.CarrierRelayUDP)
	echo("relay after websocket loss")
	t.Logf("TCP echo resumed after WebSocket loss in %s", time.Since(wssLost))
	blockWSS.Store(false)
	waitRelayTrialObservation(t, c, echo, a.relay.current().id)
	if err := c.renew(); err != nil {
		t.Fatal(err)
	}
	echo("renewed relay")
	if c.State().Transport.Mode != TransportUDPRelay || c.TransportInfo().Active != protocol.CarrierRelayUDP {
		t.Fatal("renewal lost the selected relay")
	}
	deadline = time.Now().Add(10 * time.Second)
	for {
		if _, err := a.ws.CarrierEndpoint("remote"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("WebSocket did not return as a standby")
		}
		time.Sleep(20 * time.Millisecond)
	}
	relayLost := time.Now()
	if err := closeRelay(); err != nil {
		t.Fatal(err)
	}
	waitCarrier(t, c, protocol.CarrierWSS)
	echo("websocket after relay loss")
	t.Logf("TCP echo resumed after relay loss in %s", time.Since(relayLost))
	after, _, err := c.Stack.LastHandshake(serverKey)
	if err != nil || !before.Equal(after) {
		t.Fatalf("WireGuard handshake changed: %v to %v, %v", before, after, err)
	}
}

func newRelayPerformanceFixture(t testing.TB, firstBandwidth int, observe func(int, protocol.RelayUDPStatsReport)) (*Connection, [2]func() error) {
	t.Helper()
	f := newReconnectFixture(t)
	first, closeFirst := startClientTestUDPRelay(f, func(cfg *relay.Config) {
		cfg.Limits.UDPRelayBytesPerSecond = firstBandwidth
	})
	second, closeSecond := startClientTestUDPRelay(f)
	logger := slog.New(slog.DiscardHandler)
	endpoint := func(r *relay.Relay) server.RelayEndpoint {
		return server.RelayEndpoint{URL: "wss://" + r.AgentsAddr().String(), Fingerprint: r.Fingerprint()}
	}
	relays := server.RelayConfig{Enabled: true, AdaptiveUDP: true, PerformanceRouting: true,
		PerformanceMaxAllocationsPerRelay: 1, Name: "home", IdentityFile: f.key,
		Endpoints: []server.RelayEndpoint{endpoint(first), endpoint(second)}}
	pool, err := server.NewRelayPool(relays, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	if observe != nil {
		for index, agent := range pool.Agents() {
			agent.OnUDPStats = func(report protocol.RelayUDPStatsReport) { observe(index, report) }
		}
	}
	pool.Run(t.Context())
	cfg := f.serverConfig("100.76.5.0/24", 18151, false, server.TransportConfig{Adaptive: true, AdaptiveMaxLanes: 2})
	cfg.Relay = relays
	s := server.New(cfg, logger)
	s.SetRelayPool(pool)
	if err := s.StartUserspaceDataPlane(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	h := httptest.NewTLSServer(s.Handler())
	t.Cleanup(h.Close)
	ca := filepath.Join(f.dir, "relay-performance-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := ConnectWithOptions(h.URL, f.key, protocol.ClientInfo{}, Options{
		AdaptiveCarrier: true, CAFile: ca, NoWebUI: true, NoBrowser: true, NoSystemProxy: true, IPVersion: "4",
		StatusFile: filepath.Join(f.dir, "status-relay-performance.json"), Logger: logger, renewInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	a := c.network.adaptive
	info, token, _ := a.credentials()
	deadline := time.Now().Add(6 * time.Second)
	for {
		var catalog protocol.RelayCandidateCatalog
		url := a.base + "/v1/transport/lanes/" + info.LaneID + "/relay-candidates"
		err := a.controlRequest(t.Context(), http.MethodGet, url, token, nil, &catalog)
		if err == nil && len(catalog.Members) == 2 && catalog.Members[0] != catalog.Members[1] {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("two independent relay registrations did not become eligible: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return c, [2]func() error{closeFirst, closeSecond}
}

func TestAdaptiveRelayPerformance_TrialsAndIndependentLaneRoutes(t *testing.T) {
	c, stopRelays := newRelayPerformanceFixture(t, 0, nil)
	a := c.network.adaptive
	info, _, _ := a.credentials()
	if !info.RelayPerformance || !a.exploration.CompareAndSwap(false, true) {
		t.Fatal("performance relay mode or test exploration slot unavailable")
	}
	defer a.exploration.Store(false)
	anchorFlow := dialLaneTest(t, "tcp", c.LocalAddresses[0])
	echoLaneTest(t, anchorFlow, "anchor WSS")
	before, _, err := c.Stack.LastHandshake(c.Response.ServerPublicKey)
	if err != nil || before.IsZero() {
		t.Fatalf("missing initial peer handshake: %v", err)
	}
	if err := a.qualifyRelay(t.Context()); err != nil {
		t.Fatal(err)
	}
	pathA := a.qualifiedRelayStandby("")
	_, _, _, events := a.bind.LaneDetails(a.lane)
	trialStart := events[len(events)-1].At.Add(adaptiveDwell + time.Second)
	addEvidence := func(path string, end time.Time, rtt time.Duration) {
		for i := 2; i >= 0; i-- {
			a.measurements.record(info.AuthGeneration, AdaptivePerformanceWindow{
				Path: path, End: end.Add(-time.Duration(i) * adaptiveFeedbackInterval), TunnelRTT: rtt, TunnelRTTSamples: 2,
				Upload: &DirectionPerformance{OfferedBPS: 10e6, DeliveredBPS: 8e6},
			})
		}
	}
	// Inject comparable end-to-end timing to exercise the production
	// decision under deterministic conditions. The proof, CAS, and
	// forwarded WireGuard traffic use the real relays.
	addEvidence(protocol.CarrierWSS, trialStart, 100*time.Millisecond)
	a.exploration.Store(false)
	trial := adaptiveTrial{parallelRelays: true}
	a.advanceTrial(t.Context(), &trial, trialStart, false)
	if trial.started.IsZero() || trial.candidate != pathA {
		t.Fatalf("relay canary was not selected: %+v", trial.status)
	}
	echoLaneTest(t, anchorFlow, "anchor over relay A")
	trial.started = trialStart
	trialEnd := trialStart.Add(30 * time.Second)
	addEvidence(pathA, trialEnd, 5*time.Millisecond)
	a.advanceTrial(t.Context(), &trial, trialEnd, false)
	if trial.status.State != "retained candidate" {
		t.Fatalf("measured improvement did not retain the relay: %+v", trial.status)
	}

	if !a.exploration.CompareAndSwap(false, true) {
		t.Fatal("trial retained the exploration lease")
	}
	if err := a.qualifyRelay(t.Context()); err != nil {
		t.Fatalf("qualify B while A is active: %v", err)
	}
	pathB := a.qualifiedRelayStandby(pathA)
	if pathB == "" || a.relay.path(pathB).member == a.relay.path(pathA).member {
		t.Fatal("relay paths were not independently qualified")
	}
	if err := a.selectPrimary(t.Context(), pathB); err != nil {
		t.Fatal(err)
	}
	echoLaneTest(t, anchorFlow, "anchor moved from relay A to B")
	if err := a.selectPrimary(t.Context(), pathA); err != nil {
		t.Fatal(err)
	}
	if err := c.renew(); err != nil {
		t.Fatal(err)
	}
	echoLaneTest(t, anchorFlow, "anchor retained relay A across renewal")
	child, err := c.openAdaptiveLane(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	childFlow := dialLaneTest(t, "tcp", c.LocalAddresses[0])
	echoLaneTest(t, childFlow, "child WSS")
	assertLaneFlows(t, c, child, 1, 1)
	if err := child.adaptive.qualifyRelay(t.Context()); err == nil {
		t.Fatal("child exceeded relay A's configured member budget")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := child.adaptive.qualifyRelay(t.Context()); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("child could not use relay B after renewal retired the standby: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	childRoute := child.adaptive.qualifiedRelayStandby("")
	if a.relay.path(pathA).member == child.adaptive.relay.path(childRoute).member {
		t.Fatal("anchor and child did not select different relay members")
	}
	if err := child.adaptive.selectPrimary(t.Context(), childRoute); err != nil {
		t.Fatal(err)
	}
	echoLaneTest(t, childFlow, "child over relay B")
	if err := stopRelays[0](); err != nil {
		t.Fatal(err)
	}
	waitCarrier(t, c, protocol.CarrierWSS)
	echoLaneTest(t, anchorFlow, "anchor resumed on WSS")
	echoLaneTest(t, childFlow, "child stayed on relay B")
	assertLaneFlows(t, c, child, 1, 1)
	if after, _, err := c.Stack.LastHandshake(c.Response.ServerPublicKey); err != nil || !after.Equal(before) {
		t.Fatalf("the anchor WireGuard peer changed during relay movement: %v, %v", after, err)
	}
}

func TestAdaptiveRelayPerformance_MeasuresChildForwarding(t *testing.T) {
	c, _ := newRelayPerformanceFixture(t, 0, nil)
	parent := c.network
	parent.adaptive.exploration.Store(true)
	defer parent.adaptive.exploration.Store(false)
	anchorFlow := dialLaneTest(t, "tcp", c.LocalAddresses[0])
	echoLaneTest(t, anchorFlow, "hold anchor lease")
	child, err := c.openAdaptiveLane(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	childFlow := dialLaneTest(t, "tcp", c.LocalAddresses[0])
	echoLaneTest(t, childFlow, "confirm child flow placement")
	assertLaneFlows(t, c, child, 1, 1)
	info, _, _ := child.adaptive.credentials()
	load := strings.Repeat("controlled-relay-fixture", 128)
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		echoLaneTest(t, childFlow, load)
		if snapshot := child.adaptive.measurements.snapshot(time.Now(), info.AuthGeneration); snapshot != nil {
			for _, window := range snapshot.Windows {
				if window.Path == protocol.CarrierWSS && window.TunnelRTTSamples > 0 &&
					window.Upload != nil && window.Upload.DeliveredBPS > 0 {
					return
				}
			}
		}
		time.Sleep(75 * time.Millisecond)
	}
	t.Fatal("child did not record lane-local delivery and end-to-end tunnel RTT")
}

// Compare the complete forwarding path using the same fixed tunnel and
// deterministic lease. Relay A has a lab-only forwarding ceiling.
func BenchmarkAdaptiveRelayPerformance(b *testing.B) {
	for _, mode := range []string{"direct-wss", "relay-a", "relay-b"} {
		b.Run(mode, func(b *testing.B) {
			c, _ := newRelayPerformanceFixture(b, 2<<20, nil)
			a := c.network.adaptive
			if !a.exploration.CompareAndSwap(false, true) {
				b.Fatal("test exploration slot is unavailable")
			}
			defer a.exploration.Store(false)
			flow := dialLaneTest(b, "tcp", c.LocalAddresses[0])
			echoLaneTest(b, flow, "warm WireGuard peer")
			if mode != "direct-wss" {
				if err := a.qualifyRelay(b.Context()); err != nil {
					b.Fatal(err)
				}
				path := a.qualifiedRelayStandby("")
				if mode == "relay-b" {
					if err := a.qualifyRelay(b.Context()); err != nil {
						b.Fatal(err)
					}
					path = a.qualifiedRelayStandby(path)
				}
				if err := a.selectPrimary(b.Context(), path); err != nil {
					b.Fatal(err)
				}
			}
			path, _, _ := a.bind.LaneState(a.lane)
			payload := strings.Repeat("ntwire echo data", 1024)
			buf := make([]byte, len(payload))
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			for b.Loop() {
				_ = flow.SetDeadline(time.Now().Add(10 * time.Second))
				if _, err := io.WriteString(flow, payload); err != nil {
					b.Fatal(err)
				}
				if _, err := io.ReadFull(flow, buf); err != nil || string(buf) != payload {
					b.Fatalf("echo mismatch: %v", err)
				}
			}
			if selected, _, _ := a.bind.LaneState(a.lane); selected != path {
				b.Fatal("carrier changed during the comparison")
			}
		})
	}
}

func waitRelayTrialObservation(t *testing.T, c *Connection, echo func(string), path string) {
	t.Helper()
	// Offer steady traffic so the fixture exercises the observer without a
	// large per-request burst competing with echo replies under -race.
	load := strings.Repeat("fixture", 6)
	deadline := time.Now().Add(30 * time.Second)
	var last *AdaptivePerformance
	for time.Now().Before(deadline) {
		echo(load)
		if status := c.TransportDetails().AdaptivePerformance; status != nil {
			last = status
			for _, window := range status.Windows {
				if window.Path == path && window.TunnelRTT > 0 && window.TunnelRTTSamples > 0 &&
					window.Upload != nil && window.Upload.DeliveredBPS > 0 {
					return
				}
			}
		}
		time.Sleep(40 * time.Millisecond)
	}
	if last == nil {
		t.Fatalf("carrier %s did not publish performance feedback", adaptiveTrialCarrier(path))
	}
	var windows, probes, replies int
	for _, window := range last.Windows {
		if window.Path == path {
			windows++
			probes += window.TunnelRTTProbes
			replies += window.TunnelRTTSamples
		}
	}
	t.Fatalf("carrier %s did not publish tunnel RTT alongside measured forwarding: %d windows, %d probes, %d replies, %s",
		adaptiveTrialCarrier(path), windows, probes, replies, last.FeedbackStatus)
}

func TestAdaptiveRelay_BindingChecksConfirmLossSooner(t *testing.T) {
	now := time.Unix(100, 0)
	var observation relayObservation
	observation.noteBinding(now, nil)
	if want := now.Add(relayClientKeepalive); !observation.nextCheck.Equal(want) || observation.missedBinds != 0 {
		t.Fatalf("healthy observation = %+v, want next check %s", observation, want)
	}
	now = observation.nextCheck
	for miss := 1; miss <= 3; miss++ {
		want := now.Add(relayClientRetry)
		observation.noteBinding(now, context.DeadlineExceeded)
		if observation.missedBinds != miss || !observation.nextCheck.Equal(want) {
			t.Fatalf("miss %d observation = %+v, want next check %s", miss, observation, want)
		}
		now = want
	}
	observation.noteBinding(now, nil)
	if observation.missedBinds != 0 || !observation.nextCheck.Equal(now.Add(relayClientKeepalive)) {
		t.Fatalf("recovered observation = %+v", observation)
	}
}
