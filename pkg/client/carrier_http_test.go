package client

import (
	"encoding/pem"
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
	"github.com/nmaguiar/ntwire/pkg/server"
)

func newHTTP2CarrierFixture(t testing.TB, rejectUpgrade int, enableHTTP2 bool, mtu int) (*httptest.Server, *atomic.Int32, func() (*Connection, error)) {
	t.Helper()
	f := newReconnectFixture(t)
	logger := slog.New(slog.DiscardHandler)
	s := server.New(f.serverConfig("100.74.8.0/24", 18150, true, server.TransportConfig{
		Adaptive: true, AdaptiveHTTP2: true, AdaptiveMaxLanes: 2, AdaptiveTunnelMTU: mtu,
	}), logger)
	if err := s.StartUserspaceDataPlane(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	handler := s.Handler()
	var attempts atomic.Int32
	h := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == protocol.CarrierWSSPath && rejectUpgrade != 0 {
			w.WriteHeader(rejectUpgrade)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/http2") {
			attempts.Add(1)
		}
		handler.ServeHTTP(w, r)
	}))
	h.EnableHTTP2 = enableHTTP2
	h.StartTLS()
	t.Cleanup(h.Close)
	ca := filepath.Join(f.dir, "http2-carrier.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return h, &attempts, func() (*Connection, error) {
		return ConnectWithOptions(h.URL, f.key, protocol.ClientInfo{}, Options{
			AdaptiveCarrier: true, CAFile: ca, NoWebUI: true, NoSystemProxy: true, NoDirectUpgrade: true,
			StatusFile: filepath.Join(f.dir, "adaptive-http2.json"), Logger: logger, renewInterval: time.Hour,
		})
	}
}

func TestAdaptiveCarrier_HTTP2FallbackRenewAndRevoke(t *testing.T) {
	h, attempts, connect := newHTTP2CarrierFixture(t, http.StatusUpgradeRequired, true, 0)
	c, err := connect()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	if info := c.TransportInfo(); info.Active != protocol.CarrierHTTP2 || info.PathEpoch != 1 || attempts.Load() != 1 {
		t.Fatalf("expected one HTTP/2 attachment: %+v, attempts=%d", info, attempts.Load())
	}
	a := c.network.adaptive
	if !a.laneReady(true) {
		t.Fatal("HTTP/2 lane is not ready for admissions")
	}
	tcp, err := net.DialTimeout("tcp", c.LocalAddresses[0], 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	echoLaneTest(t, tcp, "HTTP/2 carried TCP")
	udp, err := net.Dial("udp", c.LocalAddresses[1])
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udpRoundTrip(t, udp)
	stack := c.Stack
	before, originalBearer, _ := a.credentials()
	if err := c.renew(); err != nil {
		t.Fatal(err)
	}
	after, bearer, _ := a.credentials()
	if c.Stack != stack || before.LaneID != after.LaneID || before.AuthGeneration+1 != after.AuthGeneration || originalBearer == bearer {
		t.Fatal("renewal did not retain the HTTP/2 lane and rotate credentials")
	}
	echoLaneTest(t, tcp, "HTTP/2 TCP survived renewal")
	udpRoundTrip(t, udp)

	endpoint := h.URL + "/v1/transport/lanes/" + after.LaneID + "/http2"
	send := func(url, token string, want int) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", protocol.CarrierHTTP2Media)
		resp, err := h.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("status = %d, want %d", resp.StatusCode, want)
		}
	}
	send(endpoint, originalBearer, http.StatusUnauthorized)
	send(endpoint, bearer, http.StatusUnauthorized) // No unconsumed ticket.
	send(h.URL+"/v1/disconnect", bearer, http.StatusNoContent)
	send(endpoint, bearer, http.StatusUnauthorized)
	deadline := time.Now().Add(5 * time.Second)
	for a.laneReady(true) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if a.laneReady(true) {
		t.Fatal("revoked HTTP/2 stream was retained")
	}
}

func TestAdaptiveCarrier_HTTP2BootstrapEligibility(t *testing.T) {
	for _, tt := range []struct {
		name    string
		reject  int
		http2   bool
		wantWSS bool
	}{
		{name: "healthy WSS", http2: true, wantWSS: true},
		{name: "WSS denied", reject: http.StatusForbidden, http2: true},
		{name: "HTTP1 only", reject: http.StatusUpgradeRequired},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, attempts, connect := newHTTP2CarrierFixture(t, tt.reject, tt.http2, 0)
			c, err := connect()
			if c != nil {
				defer c.Close()
			}
			if tt.wantWSS {
				if err != nil {
					t.Fatal(err)
				}
				if info := c.TransportInfo(); info.Active != protocol.CarrierWSS {
					t.Fatalf("healthy WSS was replaced: %+v", info)
				}
			} else if err == nil {
				t.Fatal("unexpected carrier connection")
			}
			if attempts.Load() != 0 {
				t.Fatalf("unexpected HTTP/2 attachment request: %d", attempts.Load())
			}
		})
	}
}

func TestAdaptiveCarrier_HTTP2ReconnectKeepsListeners(t *testing.T) {
	_, _, connect := newHTTP2CarrierFixture(t, http.StatusUpgradeRequired, true, 0)
	c, err := connect()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	address := c.LocalAddresses[0]
	newQUICTCPEcho(t, c)("before HTTP/2 loss")
	initial := c.Stack
	if err := c.network.adaptive.http2.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for c.network.adaptive.laneReady(true) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if err := c.renew(); err == nil {
		t.Fatal("lost HTTP/2 carrier did not request reconnect")
	}
	if err := c.reconnect(); err != nil {
		t.Fatal(err)
	}
	if c.LocalAddresses[0] != address || c.Stack == initial || c.TransportInfo().Active != protocol.CarrierHTTP2 {
		t.Fatalf("reconnect did not rebuild the HTTP/2 lane on the same listener: %+v", c.TransportInfo())
	}
	newQUICTCPEcho(t, c)("after HTTP/2 reconnect")
}

func BenchmarkAdaptiveHTTPCarrier(b *testing.B) {
	for _, carrier := range []string{protocol.CarrierWSS, protocol.CarrierHTTP2, protocol.CarrierHTTP3} {
		for _, workload := range []struct {
			name string
			size int
		}{{"request", 29}, {"bulk", 64 << 10}} {
			b.Run(carrier+"/"+workload.name, func(b *testing.B) {
				var connect func() (*Connection, error)
				switch carrier {
				case protocol.CarrierHTTP3:
					_, _, connect = newHTTP3CarrierFixture(b, 1280, false)
				case protocol.CarrierHTTP2:
					_, _, connect = newHTTP2CarrierFixture(b, http.StatusUpgradeRequired, true, 1280)
				default:
					_, _, connect = newHTTP2CarrierFixture(b, 0, true, 1280)
				}
				c, err := connect()
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(c.Close)
				if active := c.TransportInfo().Active; active != carrier {
					b.Fatalf("selected %s, expected %s", active, carrier)
				}
				tcp, err := net.DialTimeout("tcp", c.LocalAddresses[0], 5*time.Second)
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(func() { _ = tcp.Close() })
				payload := strings.Repeat("x", workload.size)
				echoLaneTest(b, tcp, payload)
				b.ReportAllocs()
				b.SetBytes(int64(len(payload)))
				for b.Loop() {
					echoLaneTest(b, tcp, payload)
				}
			})
		}
	}
}
