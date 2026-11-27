package client

import (
	"encoding/pem"
	"log/slog"
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

func TestAdaptiveDefault_ConnectSelectionAndDenial(t *testing.T) {
	for _, tc := range []struct {
		name          string
		serverAllows  bool
		clientAllows  bool
		upgradeStatus int
		attachStatus  int
		wantAdaptive  bool
		wantAuths     int32
		wantError     bool
		reconnect     bool
	}{
		{name: "enabled server", serverAllows: true, clientAllows: true, wantAdaptive: true, wantAuths: 1},
		{name: "legacy server", clientAllows: true, wantAuths: 1},
		{name: "client rollback", serverAllows: true, wantAuths: 1},
		{name: "unavailable adaptive upgrade", serverAllows: true, clientAllows: true, upgradeStatus: http.StatusUpgradeRequired, wantAuths: 2},
		{name: "upgrade denied", serverAllows: true, clientAllows: true, upgradeStatus: http.StatusForbidden, wantAuths: 1, wantError: true},
		{name: "attach unauthorized", serverAllows: true, clientAllows: true, attachStatus: http.StatusUnauthorized, wantAuths: 1, wantError: true},
		{name: "attach unavailable", serverAllows: true, clientAllows: true, attachStatus: http.StatusServiceUnavailable, wantAuths: 1, wantError: true},
		{name: "reconnect uses legacy WireGuard", serverAllows: true, clientAllows: true, wantAdaptive: true, wantAuths: 1, reconnect: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newReconnectFixture(t)
			s := f.startServerWithTransport("100.74.16.0/24", 18160, false, server.TransportConfig{Adaptive: tc.serverAllows})
			handler := s.Handler()
			var auths, disconnected atomic.Int32
			var upgradeStatus atomic.Int32
			upgradeStatus.Store(int32(tc.upgradeStatus))
			h := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/v1/auth":
					auths.Add(1)
				case r.URL.Path == "/v1/disconnect":
					disconnected.Add(1)
				case strings.HasSuffix(r.URL.Path, "/attach") && tc.attachStatus != 0:
					w.WriteHeader(tc.attachStatus)
					return
				}
				if status := upgradeStatus.Load(); status != 0 && r.URL.Path == protocol.CarrierWSSPath {
					w.WriteHeader(int(status))
					return
				}
				handler.ServeHTTP(w, r)
			}))
			t.Cleanup(h.Close)
			ca := filepath.Join(f.dir, "ca.pem")
			if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			c, err := ConnectWithOptions(h.URL, f.key, protocol.ClientInfo{}, Options{
				AdaptiveCarrier: tc.clientAllows, AdaptiveFallback: true, CAFile: ca,
				NoWebUI: true, NoSystemProxy: true, NoDirectUpgrade: true, renewInterval: time.Hour,
				StatusFile: filepath.Join(f.dir, "status.json"), Logger: slog.New(slog.DiscardHandler),
			})
			if c != nil {
				t.Cleanup(c.Close)
			}
			if (err != nil) != tc.wantError {
				t.Fatalf("connect error = %v", err)
			}
			if got := auths.Load(); got != tc.wantAuths {
				t.Fatalf("auth requests = %d, want %d", got, tc.wantAuths)
			}
			if tc.wantAuths == 2 && disconnected.Load() != 1 {
				t.Fatal("failed adaptive session was not disconnected before retry")
			}
			if c == nil {
				return
			}
			if c.TransportInfo().AdaptiveCarrier != tc.wantAdaptive {
				t.Fatalf("adaptive carrier = %v, want %v", c.TransportInfo().AdaptiveCarrier, tc.wantAdaptive)
			}
			newQUICTCPEcho(t, c)("authorized fixed tunnel")
			if tc.reconnect {
				address := c.LocalAddresses[0]
				upgradeStatus.Store(http.StatusUpgradeRequired)
				if err := c.reconnect(); err != nil {
					t.Fatal(err)
				}
				if c.TransportInfo().AdaptiveCarrier || c.LocalAddresses[0] != address || auths.Load() != 3 || disconnected.Load() != 1 {
					t.Fatalf("reconnect did not retain the listener and retry once, transport=%+v auths=%d disconnects=%d", c.TransportInfo(), auths.Load(), disconnected.Load())
				}
				newQUICTCPEcho(t, c)("authorized fixed tunnel after reconnect")
			}
		})
	}
}

func TestAdaptiveDefault_RequiredCapabilityPreventsRetry(t *testing.T) {
	o := Options{AdaptiveCarrier: true, AdaptiveFallback: true}
	response := protocol.AuthResponse{
		Adaptive:                      &protocol.AdaptiveSession{},
		RequiredTransportCapabilities: []string{protocol.CapabilityAdaptiveCarrierV1},
	}
	if _, ok := o.legacyCarrierRetry(response, errAdaptiveCarrierUnavailable); ok {
		t.Fatal("retried without a required capability")
	}
}
