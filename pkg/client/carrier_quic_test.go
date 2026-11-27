package client

import (
	"bytes"
	"crypto/tls"
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
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/server"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

func TestAdaptiveCarrier_QUICPreservesTCPAcrossSwitchRenewAndFallback(t *testing.T) {
	c, unblock, _ := newQUICTestConnection(t, 1280, false)
	a := c.network.adaptive
	if a == nil || a.quic == nil {
		t.Fatal("client did not negotiate QUIC DATAGRAM")
	}
	echo := newQUICTCPEcho(t, c)
	echo("WebSocket")
	before, exists, err := c.Stack.LastHandshake(c.Response.ServerPublicKey)
	if err != nil || !exists || before.IsZero() {
		t.Fatalf("WireGuard handshake missing: %v, %v, %v", before, exists, err)
	}
	unblock()
	waitCarrier(t, c, protocol.CarrierQUIC)
	echo("QUIC DATAGRAM")
	udp, err := net.Dial("udp", c.LocalAddresses[1])
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udpRoundTrip(t, udp)
	if got := c.TransportInfo().QUIC; got == nil || got.Sent == 0 || got.Received == 0 {
		t.Fatalf("did not observe bidirectional QUIC ciphertext: %+v", got)
	}
	if mode := c.State().Transport.Mode; mode != TransportQUICDatagram {
		t.Fatalf("status reports %s after QUIC promotion", mode)
	}
	if err := c.renew(); err != nil {
		t.Fatal(err)
	}
	echo("renewed QUIC")
	if got := c.TransportInfo(); got.Active != protocol.CarrierQUIC || got.PathEpoch != 2 {
		t.Fatalf("renewal lost the QUIC carrier: %+v", got)
	}
	if err := a.quic.bind.Close(); err != nil {
		t.Fatal(err)
	}
	waitCarrier(t, c, protocol.CarrierWSS)
	echo("WebSocket fallback")
	udpRoundTrip(t, udp)
	after, _, err := c.Stack.LastHandshake(c.Response.ServerPublicKey)
	if err != nil || !after.Equal(before) {
		t.Fatalf("connection changed WireGuard handshake: %v -> %v, %v", before, after, err)
	}
}

func TestAdaptiveMultiLane_QUICChildPreservesPinnedFlow(t *testing.T) {
	connect := newQUICTestFixtureWithLanes(t, 1280, 2, func(next http.Handler) http.Handler { return next })
	c, err := connect(false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	first := dialLaneTest(t, "tcp", c.LocalAddresses[0])
	echoLaneTest(t, first, "anchor")
	waitCarrier(t, c, protocol.CarrierQUIC)
	if !c.Response.Adaptive.LaneCarriers {
		t.Fatal("child carrier capability not negotiated")
	}
	child, err := c.openAdaptiveLane(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	a := child.adaptive
	if primary, _, _ := a.bind.LaneState(a.lane); primary != protocol.CarrierQUIC {
		t.Fatalf("child primary = %q", primary)
	}
	second := dialLaneTest(t, "tcp", c.LocalAddresses[0])
	echoLaneTest(t, second, "child QUIC")
	assertLaneFlows(t, c, child, 1, 1)
	if got := a.quic.bind.Stats(); got.Sent == 0 || got.Received == 0 {
		t.Fatalf("child did not exchange ciphertext over QUIC: %+v", got)
	}
	if err := c.renew(); err != nil {
		t.Fatal(err)
	}
	echoLaneTest(t, second, "child after renewal")
	if err := a.quic.bind.Close(); err != nil {
		t.Fatal(err)
	}
	echoLaneTest(t, second, "child WSS fallback")
	assertLaneFlows(t, c, child, 1, 1)
	if primary, _, _ := a.bind.LaneState(a.lane); primary != protocol.CarrierWSS {
		t.Fatalf("child fallback = %q", primary)
	}
	waitCarrier(t, c, protocol.CarrierQUIC)
	echoLaneTest(t, first, "anchor was unaffected")
}

func TestAdaptiveCarrier_PrimaryReconcilesLostCommit(t *testing.T) {
	var discardResult atomic.Bool
	var delayReconciliation atomic.Bool
	lostRequest := make(chan []byte, 1)
	connect := newQUICTestFixture(t, 1280, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/primary") && discardResult.Swap(false) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				r.Body = io.NopCloser(bytes.NewReader(body))
				record := httptest.NewRecorder()
				next.ServeHTTP(record, r)
				if record.Code == http.StatusOK {
					lostRequest <- body
					delayReconciliation.Store(true)
				}
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/candidates") && delayReconciliation.Swap(false) {
				timer := time.NewTimer(2100 * time.Millisecond)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-r.Context().Done():
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	})
	c, err := connect(false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	waitCarrier(t, c, protocol.CarrierQUIC)
	echo := newQUICTCPEcho(t, c)
	echo("before switch")
	before, _, err := c.Stack.LastHandshake(c.Response.ServerPublicKey)
	if err != nil || before.IsZero() {
		t.Fatalf("WireGuard handshake missing: %v, %v", before, err)
	}

	a := c.network.adaptive
	info, bearer, _ := a.credentials()
	if !info.PathSelect {
		t.Fatal("primary selection was not negotiated")
	}
	discardResult.Store(true)
	if err := a.selectPrimary(t.Context(), protocol.CarrierWSS); err != nil {
		t.Fatalf("reconcile lost commit response: %v", err)
	}
	echo("same flow over WSS")
	if state := c.TransportInfo(); state.Active != protocol.CarrierWSS || state.PathEpoch != 3 {
		t.Fatalf("unexpected selection after reconciliation: %+v", state)
	}
	var requestBody []byte
	select {
	case requestBody = <-lostRequest:
	default:
		t.Fatal("server did not commit before the simulated lost response")
	}
	var repeated protocol.CarrierPrimary
	if err := a.controlRequest(t.Context(), http.MethodPut, c.base+"/v1/transport/lanes/"+info.LaneID+"/primary", bearer, requestBody, &repeated); err != nil ||
		repeated.Candidate != protocol.CarrierWSS || repeated.PathEpoch != 3 {
		t.Fatalf("replay performed a new selection: %+v, %v", repeated, err)
	}
	// A previous epoch cannot undo the confirmed selection. A fresh bearer
	// also has access only to its own lane.
	request := protocol.CarrierAttachRequest{RequestID: "AAAAAAAAAAAAAAAAAAAAAA",
		Generation: info.AuthGeneration, ExpectedEpoch: 2, Candidate: protocol.CarrierQUIC}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		lane string
		want int
	}{
		{info.LaneID, http.StatusConflict},
		{"AAAAAAAAAAAAAAAAAAAAAA", http.StatusNotFound},
	} {
		var result protocol.CarrierPrimary
		err := a.controlRequest(t.Context(), http.MethodPut, c.base+"/v1/transport/lanes/"+tc.lane+"/primary", bearer, body, &result)
		var status *carrierHTTPError
		if !errors.As(err, &status) || status.status != tc.want {
			t.Fatalf("selection status = %v, want %d", err, tc.want)
		}
	}
	if err := a.selectPrimary(t.Context(), protocol.CarrierQUIC); err != nil {
		t.Fatal(err)
	}
	echo("same flow back on QUIC")
	if after, _, err := c.Stack.LastHandshake(c.Response.ServerPublicKey); err != nil || !after.Equal(before) {
		t.Fatalf("WireGuard handshake changed through explicit selection: %v -> %v, %v", before, after, err)
	}
}

func TestAdaptiveCarrier_LegacyQUICProofStillCommits(t *testing.T) {
	var selects atomic.Int32
	connect := newQUICTestFixture(t, 1280, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/primary") {
				selects.Add(1)
			}
			if r.Method == http.MethodPost && r.URL.Path == "/v1/auth" {
				var request protocol.AuthRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				request.TransportCapabilities = slices.DeleteFunc(request.TransportCapabilities, func(capability string) bool {
					return capability == protocol.CapabilityAdaptivePathSelectV1
				})
				body, err := json.Marshal(request)
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				r.Body = io.NopCloser(bytes.NewReader(body))
				r.ContentLength = int64(len(body))
			}
			next.ServeHTTP(w, r)
		})
	})
	c, err := connect(false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	waitCarrier(t, c, protocol.CarrierQUIC)
	tcpRoundTrip(t, c.LocalAddresses[0])
	if c.Response.Adaptive.PathSelect || selects.Load() != 0 {
		t.Fatal("legacy QUIC peer used the explicit selection operation")
	}
}

func TestAdaptiveCarrier_AutoQualifiesStandbyWithoutAnIdleSwitch(t *testing.T) {
	connect := newQUICTestFixture(t, 1280, func(next http.Handler) http.Handler { return next },
		func(options *Options) { options.AdaptiveQUICDiagnostic = false })
	c, err := connect(false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	waitQUICStandby(t, c)
	tcpRoundTrip(t, c.LocalAddresses[0])
	if info := c.TransportInfo(); info.Active != protocol.CarrierWSS || info.PathEpoch != 1 {
		t.Fatalf("short traffic burst triggered a performance trial: %+v", info)
	}
}

func waitQUICStandby(t *testing.T, c *Connection) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		info := c.TransportDetails()
		if info.Active != protocol.CarrierWSS || info.PathEpoch != 1 {
			t.Fatalf("idle qualification changed the selected path: %+v", info)
		}
		if slices.ContainsFunc(info.QualifiedPaths, func(path wstransport.QualifiedCarrier) bool {
			return path.Name == protocol.CarrierQUIC && !path.Primary
		}) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("QUIC standby did not qualify")
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func TestAdaptiveCarrier_WSSFailureRecoversThroughQualifiedQUIC(t *testing.T) {
	testWSSRecoveryThroughQUIC(t, false)
}

func TestAdaptiveCarrier_WSSRecoveryRetriesAfterTransientControlFailure(t *testing.T) {
	testWSSRecoveryThroughQUIC(t, true)
}

func testWSSRecoveryThroughQUIC(t *testing.T, failControl bool) {
	t.Helper()
	upgraded := make(chan recordedCarrier, 4)
	var blockWSS atomic.Bool
	var rejectCandidates atomic.Bool
	connect := newQUICTestFixture(t, 1280, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/candidates") && rejectCandidates.Swap(false) {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if r.URL.Path == protocol.CarrierWSSPath {
				if blockWSS.Load() {
					w.WriteHeader(http.StatusUpgradeRequired)
					return
				}
				w = carrierUpgradeRecorder{ResponseWriter: w, carriers: upgraded}
			}
			next.ServeHTTP(w, r)
		})
	}, func(options *Options) { options.AdaptiveQUICDiagnostic = false })
	c, err := connect(false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	waitQUICStandby(t, c)
	select {
	case <-time.After(5 * time.Second):
		t.Fatal("WebSocket was not upgraded")
	case peer := <-upgraded:
		echo := newQUICTCPEcho(t, c)
		echo("before WSS failure")
		before, _, err := c.Stack.LastHandshake(c.Response.ServerPublicKey)
		if err != nil || before.IsZero() {
			t.Fatalf("WireGuard handshake missing: %v, %v", before, err)
		}
		udp, err := net.Dial("udp", c.LocalAddresses[1])
		if err != nil {
			t.Fatal(err)
		}
		defer udp.Close()
		udpRoundTrip(t, udp)
		blockWSS.Store(true)
		rejectCandidates.Store(failControl)
		started := time.Now()
		_ = peer.conn.Close()
		waitCarrier(t, c, protocol.CarrierQUIC)
		if rejectCandidates.Load() {
			t.Fatal("transient control failure was not exercised")
		}
		echo("same TCP flow on qualified QUIC")
		udpRoundTrip(t, udp)
		t.Logf("WSS close to TCP and UDP delivery over QUIC: %s", time.Since(started))
		after, _, err := c.Stack.LastHandshake(c.Response.ServerPublicKey)
		if err != nil || !after.Equal(before) {
			t.Fatalf("WireGuard handshake changed during hard recovery: %v -> %v, %v", before, after, err)
		}
		if info := c.TransportInfo(); info.PathEpoch != 2 || info.QUIC == nil || info.QUIC.Sent == 0 || info.QUIC.Received == 0 {
			t.Fatalf("QUIC recovery did not commit and carry both directions: %+v", info)
		}
	}
}

func TestAdaptiveCarrier_RequalifiesQUICAfterTransientAttachFailure(t *testing.T) {
	var attempts atomic.Int32
	first := make(chan struct{})
	connect := newQUICTestFixture(t, 1280, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/attach") {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				r.Body = io.NopCloser(bytes.NewReader(body))
				var req protocol.CarrierAttachRequest
				if json.Unmarshal(body, &req) == nil && req.Candidate == protocol.CarrierQUIC && attempts.Add(1) == 1 {
					close(first)
					w.WriteHeader(http.StatusConflict)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}, func(options *Options) {
		options.AdaptiveQUICDiagnostic = false
		options.quicRetryInterval = time.Second
	})
	c, err := connect(false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	select {
	case <-first:
	case <-time.After(10 * time.Second):
		t.Fatal("initial QUIC attachment was not attempted")
	}
	time.Sleep(2300 * time.Millisecond)
	if attempts.Load() != 1 {
		t.Fatal("idle lane retried qualification")
	}
	echo := newQUICTCPEcho(t, c)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		echo(strings.Repeat("authorized traffic", 5))
		if c.network.adaptive.bind.HasQualifiedPath(c.network.adaptive.lane, protocol.CarrierQUIC) {
			if primary := c.TransportInfo().Active; primary != protocol.CarrierWSS || attempts.Load() != 2 {
				t.Fatalf("qualification interfered with WSS: primary=%q attempts=%d", primary, attempts.Load())
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("live demand did not restore the QUIC standby")
}

func newQUICTCPEcho(t *testing.T, c *Connection) func(string) {
	t.Helper()
	tcp, err := net.DialTimeout("tcp", c.LocalAddresses[0], 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcp.Close() })
	return func(msg string) {
		t.Helper()
		payload := bytes.Repeat([]byte(msg), 100)
		_ = tcp.SetDeadline(time.Now().Add(20 * time.Second))
		if _, err := tcp.Write(payload); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, len(payload))
		if _, err := io.ReadFull(tcp, buffer); err != nil || !bytes.Equal(payload, buffer) {
			t.Fatalf("TCP echo failed for %s over %s: %v", msg, c.TransportInfo().Active, err)
		}
	}
}

func TestAdaptiveCarrier_QUICStaysOnWSSAtLimitedOuterMTU(t *testing.T) {
	if os.Getenv("NTWIRE_TEST_LIMITED_UDP_MTU") != "1" {
		t.Skip("requires an isolated network namespace with loopback MTU 1380 or less")
	}
	c, unblock, attempted := newQUICTestConnection(t, wgnet.DefaultMTU, false)
	if c.network.adaptive.quic == nil {
		t.Fatal("pilot did not negotiate its QUIC candidate")
	}
	tcpRoundTrip(t, c.LocalAddresses[0])
	unblock()
	select {
	case <-attempted:
	case <-time.After(2 * time.Second):
		t.Fatal("QUIC candidate was not attempted")
	}
	deadline := time.Now().Add(16 * time.Second)
	for time.Now().Before(deadline) {
		if got := c.TransportInfo(); got.Active != protocol.CarrierWSS || got.PathEpoch != 1 {
			t.Fatalf("undersized path changed the primary: %+v", got)
		}
		time.Sleep(50 * time.Millisecond)
	}
	tcpRoundTrip(t, c.LocalAddresses[0])
}

func TestAdaptiveCarrier_QUICRespectsNoDirectUpgrade(t *testing.T) {
	c, unblock, _ := newQUICTestConnection(t, 1280, true)
	defer unblock()
	if c.Response.Adaptive == nil || c.Response.Adaptive.QUIC != "" || c.network.adaptive.quic != nil {
		t.Fatal("no-direct option still negotiated QUIC")
	}
	tcpRoundTrip(t, c.LocalAddresses[0])
}

func waitCarrier(t *testing.T, c *Connection, want string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for info := c.TransportInfo(); info.Active != want; info = c.TransportInfo() {
		if time.Now().After(deadline) {
			t.Fatalf("active carrier = %+v, want %s", info, want)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func TestAdaptiveCarrier_QUICStartsWhenWebSocketUpgradeUnavailable(t *testing.T) {
	var allowWSS atomic.Bool
	var upgrades atomic.Int32
	connect := newQUICTestFixture(t, 1280, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == protocol.CarrierWSSPath {
				upgrades.Add(1)
				if !allowWSS.Load() {
					w.WriteHeader(http.StatusUpgradeRequired)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	})
	c, err := connect(false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	a := c.network.adaptive
	if info := c.TransportInfo(); info.Active != protocol.CarrierQUIC || info.PathEpoch != 1 || upgrades.Load() == 0 {
		t.Fatalf("expected initial QUIC path after rejected upgrade, got %+v", info)
	}
	if got := c.TransportReason(); got != "WebSocket unavailable at startup, qualified QUIC DATAGRAM" {
		t.Fatalf("unexpected startup reason %q", got)
	}
	echo := newQUICTCPEcho(t, c)
	echo("QUIC startup")
	udp, err := net.Dial("udp", c.LocalAddresses[1])
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udpRoundTrip(t, udp)
	if stats := c.TransportInfo().QUIC; stats == nil || stats.Sent == 0 || stats.Received == 0 {
		t.Fatalf("initial path carried no bidirectional WireGuard datagrams: %+v", stats)
	}
	paths := c.TransportDetails().QualifiedPaths
	if len(paths) != 1 || paths[0].Name != protocol.CarrierQUIC || paths[0].RTT <= 0 {
		t.Fatalf("missing carrier RTT on the active QUIC path: %+v", paths)
	}

	allowWSS.Store(true)
	deadline := time.Now().Add(25 * time.Second)
	for {
		if slices.ContainsFunc(c.TransportDetails().QualifiedPaths, func(path wstransport.QualifiedCarrier) bool {
			return path.Name == protocol.CarrierWSS
		}) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("WebSocket did not return as standby")
		}
		time.Sleep(25 * time.Millisecond)
	}
	if got := c.TransportInfo().Active; got != protocol.CarrierQUIC {
		t.Fatalf("returning standby displaced healthy QUIC: %q", got)
	}
	if err := a.quic.bind.Close(); err != nil {
		t.Fatal(err)
	}
	waitCarrier(t, c, protocol.CarrierWSS)
	echo("WebSocket fallback")
	udpRoundTrip(t, udp)
	events := c.TransportDetails().Events
	if len(events) != 2 || events[0].To != protocol.CarrierQUIC || events[0].Reason != "initial" ||
		events[1].From != protocol.CarrierQUIC || events[1].To != protocol.CarrierWSS || events[1].Reason != "carrier_failure" {
		t.Fatalf("unexpected committed carrier history: %+v", events)
	}
	if events := c.TransportInfo().Events; len(events) != 0 {
		t.Fatalf("basic transport status contains switch history: %+v", events)
	}
}

func TestAdaptiveCarrier_QUICStartupPreservesWebSocketAuthorizationFailure(t *testing.T) {
	var quicAttach, disconnects atomic.Int32
	connect := newQUICTestFixture(t, 1280, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == protocol.CarrierWSSPath:
				w.WriteHeader(http.StatusForbidden)
				return
			case strings.HasSuffix(r.URL.Path, "/attach"):
				if fixtureAttachCandidate(r) == protocol.CarrierQUIC {
					quicAttach.Add(1)
				}
			case r.URL.Path == "/v1/disconnect":
				disconnects.Add(1)
			}
			next.ServeHTTP(w, r)
		})
	})
	c, err := connect(false)
	if c != nil {
		c.Close()
		t.Fatal("connection survived an explicit authorization denial")
	}
	if err == nil || !strings.Contains(err.Error(), "403") || quicAttach.Load() != 0 || disconnects.Load() != 1 {
		t.Fatalf("authorization failure did not close the session: err=%v quic_attach=%d disconnects=%d", err, quicAttach.Load(), disconnects.Load())
	}
}

func TestAdaptiveCarrier_QUICStartupFailsClosedWithoutAvailableCarrier(t *testing.T) {
	var quicAttach, disconnects atomic.Int32
	connect := newQUICTestFixture(t, 1280, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == protocol.CarrierWSSPath:
				w.WriteHeader(http.StatusUpgradeRequired)
				return
			case strings.HasSuffix(r.URL.Path, "/attach") && fixtureAttachCandidate(r) == protocol.CarrierQUIC:
				quicAttach.Add(1)
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			case r.URL.Path == "/v1/disconnect":
				disconnects.Add(1)
			}
			next.ServeHTTP(w, r)
		})
	})
	c, err := connect(false)
	if c != nil {
		c.Close()
		t.Fatal("connection started without an authorized carrier")
	}
	if err == nil || !strings.Contains(err.Error(), "adaptive QUIC startup") || quicAttach.Load() == 0 || disconnects.Load() != 1 {
		t.Fatalf("failed startup was not cleaned up: err=%v quic_attach=%d disconnects=%d", err, quicAttach.Load(), disconnects.Load())
	}
	quicAttach.Store(0)
	c, err = connect(true)
	if c != nil {
		c.Close()
		t.Fatal("connection started with direct carriers disabled and WebSocket unavailable")
	}
	if err == nil || quicAttach.Load() != 0 || disconnects.Load() != 2 {
		t.Fatalf("disabled direct carrier was attempted: err=%v quic_attach=%d disconnects=%d", err, quicAttach.Load(), disconnects.Load())
	}
}

func fixtureAttachCandidate(r *http.Request) string {
	data, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(data))
	var req protocol.CarrierAttachRequest
	if err != nil || json.Unmarshal(data, &req) != nil {
		return ""
	}
	return req.Candidate
}

func TestUnavailableWebSocketUpgrade(t *testing.T) {
	for _, tc := range []struct {
		status int
		err    error
		want   bool
	}{
		{http.StatusUpgradeRequired, errors.New("upgrade unavailable"), true},
		{http.StatusForbidden, errors.New("access denied"), false},
		{http.StatusUnauthorized, errors.New("no credentials"), false},
		{http.StatusFound, errors.New("redirect"), false},
		{http.StatusSwitchingProtocols, errors.New("invalid handshake"), false},
		{0, io.EOF, true},
		{0, errors.New("unexpected control failure"), false},
	} {
		if got := unavailableWebSocketUpgrade(tc.status, tc.err); got != tc.want {
			t.Errorf("status %d and error %v classified as unavailable=%v", tc.status, tc.err, got)
		}
	}
}

func newQUICTestConnection(t *testing.T, mtu int, noDirect bool) (*Connection, func(), <-chan struct{}) {
	t.Helper()
	proceed := make(chan struct{})
	attempted := make(chan struct{}, 1)
	connect := newQUICTestFixture(t, mtu, func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Hold the background candidate discovery until the test exchanges
			// application data through the original WebSocket carrier.
			if strings.HasSuffix(r.URL.Path, "/candidates") {
				select {
				case <-proceed:
				case <-r.Context().Done():
					return
				}
			}
			if strings.HasSuffix(r.URL.Path, "/attach") {
				select {
				case attempted <- struct{}{}:
				default:
				}
			}
			handler.ServeHTTP(w, r)
		})
	})
	c, err := connect(noDirect)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	// Forget the already-completed WebSocket attach to observe QUIC's POST.
	select {
	case <-attempted:
	default:
		t.Fatal("missing WebSocket attach request")
	}
	return c, func() { close(proceed) }, attempted
}

func newQUICTestFixture(t *testing.T, mtu int, wrap func(http.Handler) http.Handler, configure ...func(*Options)) func(noDirect bool) (*Connection, error) {
	return newQUICTestFixtureWithLanes(t, mtu, 0, wrap, configure...)
}

func newQUICTestFixtureWithLanes(t *testing.T, mtu, maxLanes int, wrap func(http.Handler) http.Handler, configure ...func(*Options)) func(noDirect bool) (*Connection, error) {
	t.Helper()
	f := newReconnectFixture(t)
	reservation, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := reservation.LocalAddr().String()
	_ = reservation.Close()
	multipath := false
	config := f.serverConfig("100.74.0.0/24", 18140, true, server.TransportConfig{
		Adaptive: true, Multipath: &multipath, AdaptiveTunnelMTU: mtu, QUICListen: listen, AdaptiveMaxLanes: maxLanes,
	})
	config.TLS.Ephemeral = true
	manager, err := server.NewTLSManager(config)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	s := server.New(config, logger)
	s.SetTLSManager(manager)
	if err := s.StartUserspaceDataPlane(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	h := httptest.NewUnstartedServer(wrap(s.Handler()))
	h.TLS = manager.Config()
	pair, err := h.TLS.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	h.TLS.Certificates = []tls.Certificate{*pair}
	h.StartTLS()
	t.Cleanup(h.Close)
	ca := filepath.Join(f.dir, "quic-server.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	return func(noDirect bool) (*Connection, error) {
		opts := Options{
			AdaptiveCarrier: true, AdaptiveQUICDiagnostic: true, CAFile: ca, NoWebUI: true, NoSystemProxy: true, NoDirectUpgrade: noDirect, IPVersion: "4",
			StatusFile: filepath.Join(f.dir, "adaptive-quic.json"), Logger: logger, renewInterval: time.Hour,
		}
		for _, apply := range configure {
			apply(&opts)
		}
		return ConnectWithOptions(h.URL, f.key, protocol.ClientInfo{}, opts)
	}
}
