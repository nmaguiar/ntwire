package client

import (
	"crypto/tls"
	"encoding/pem"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/server"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func newHTTP3CarrierFixture(t testing.TB, mtu int, enableHTTP2 bool) (*httptest.Server, string, func() (*Connection, error)) {
	t.Helper()
	f := newReconnectFixture(t)
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := socket.LocalAddr().String()
	_ = socket.Close()
	cfg := f.serverConfig("100.74.9.0/24", 18151, true, server.TransportConfig{
		Adaptive: true, HTTP3Listen: listen, AdaptiveTunnelMTU: mtu, AdaptiveHTTP2: enableHTTP2,
	})
	cfg.TLS.Ephemeral = true
	manager, err := server.NewTLSManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	s := server.New(cfg, logger)
	s.SetTLSManager(manager)
	if err := s.StartUserspaceDataPlane(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	handler := s.Handler()
	h := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == protocol.CarrierWSSPath {
			w.WriteHeader(http.StatusUpgradeRequired)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	h.EnableHTTP2 = enableHTTP2
	h.TLS = manager.Config()
	pair, err := h.TLS.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	h.TLS.Certificates = []tls.Certificate{*pair}
	h.StartTLS()
	t.Cleanup(h.Close)
	ca := filepath.Join(f.dir, "http3-carrier.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	opts := Options{
		AdaptiveCarrier: true, CAFile: ca, NoWebUI: true, NoSystemProxy: true, IPVersion: "4",
		StatusFile: filepath.Join(f.dir, "adaptive-http3.json"), Logger: logger, renewInterval: time.Hour,
	}
	return h, listen, func() (*Connection, error) {
		return ConnectWithOptions(h.URL, f.key, protocol.ClientInfo{}, opts)
	}
}

func TestAdaptiveCarrier_HTTP3ConnectUDP(t *testing.T) {
	h, listen, connect := newHTTP3CarrierFixture(t, 1280, false)
	c, err := connect()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	if info := c.TransportInfo(); info.Active != protocol.CarrierHTTP3 || info.PathEpoch != 1 {
		t.Fatalf("HTTP/3 did not bootstrap: %+v", info)
	}
	echo := newQUICTCPEcho(t, c)
	echo("before renewal")
	udp, err := net.Dial("udp", c.LocalAddresses[1])
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udpRoundTrip(t, udp)
	if err := c.renew(); err != nil {
		t.Fatal(err)
	}
	echo("after renewal")

	// The HTTP/3 listener is not a general CONNECT-UDP proxy.
	a := c.network.adaptive
	for _, tc := range []struct {
		path string
		want int
	}{
		{path: "/.well-known/masque/udp/127.0.0.1/53/", want: http.StatusNotFound},
		{path: protocol.CarrierHTTP3Path, want: http.StatusUnauthorized},
	} {
		func() {
			config := wstransport.HTTP3QUICConfig(false)
			tlsConfig := c.http.Transport.(*secureControlTransport).TLSClientConfig.Clone()
			tlsConfig.NextProtos = []string{http3.NextProtoH3}
			tlsConfig.ServerName = "127.0.0.1"
			peer, err := quic.DialAddr(t.Context(), listen, tlsConfig, config)
			if err != nil {
				t.Fatal(err)
			}
			defer peer.CloseWithError(0, "fixture closed")
			client := (&http3.Transport{EnableDatagrams: true}).NewClientConn(peer)
			stream, err := client.OpenRequestStream(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
			req, err := http.NewRequest(http.MethodConnect, h.URL+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Proto = "connect-udp"
			req.Header.Set("Capsule-Protocol", "?1")
			info, _, _ := a.credentials()
			req.Header.Set(protocol.CarrierLaneHeader, info.LaneID)
			if err := stream.SendRequestHeader(req); err != nil {
				t.Fatal(err)
			}
			resp, err := stream.ReadResponse()
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.want)
			}
		}()
	}
}

func TestAdaptiveCarrier_HTTP3SmallMTUUsesHTTP2(t *testing.T) {
	if os.Getenv("NTWIRE_TEST_LIMITED_UDP_MTU") != "1" {
		t.Skip("requires an isolated network namespace with loopback MTU 1380 or less")
	}
	_, _, connect := newHTTP3CarrierFixture(t, 1420, true)
	c, err := connect()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	if info := c.TransportInfo(); info.Active != protocol.CarrierHTTP2 || info.PathEpoch != 1 {
		t.Fatalf("undersized HTTP/3 path was admitted: %+v", info)
	}
	tcpRoundTrip(t, c.LocalAddresses[0])
}
