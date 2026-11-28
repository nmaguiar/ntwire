package client

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/server"
)

// Run with NTWIRE_TEST_HAPROXY=1 in a test environment with HAProxy on PATH.
func TestAdaptiveCarrier_HTTP2HAProxyIngress(t *testing.T) {
	if os.Getenv("NTWIRE_TEST_HAPROXY") != "1" {
		t.Skip("requires NTWIRE_TEST_HAPROXY=1 and HAProxy")
	}
	f := newReconnectFixture(t)
	s := f.startServerWithTransport("100.74.8.0/24", 18150, true, server.TransportConfig{Adaptive: true, AdaptiveHTTP2: true})
	handler := s.Handler()
	var streams atomic.Int32
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == protocol.CarrierWSSPath {
			t.Error("blocked WebSocket reached origin")
		}
		if strings.HasSuffix(r.URL.Path, "/http2") && r.ProtoMajor == 2 {
			streams.Add(1)
		}
		handler.ServeHTTP(w, r)
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	t.Cleanup(origin.Close)

	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw})
	key, err := x509.MarshalPKCS8PrivateKey(origin.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(f.dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	ca := write("ca.pem", cert)
	identity := write("proxy.pem", append(cert, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})...))
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	config := fmt.Sprintf(`defaults
  mode http
  timeout connect 3s
  timeout client 30s
  timeout server 30s
frontend restricted
  bind %s ssl crt "%s" alpn h2,http/1.1
  http-request return status 426 if { req.hdr(Upgrade) -i websocket }
  default_backend ntwire
backend ntwire
  server origin %s ssl alpn h2 verify required ca-file "%s" verifyhost example.com
`, address, identity, origin.Listener.Addr(), ca)
	proxy := exec.Command("haproxy", "-db", "-f", write("haproxy.cfg", []byte(config)))
	var logs bytes.Buffer
	proxy.Stdout, proxy.Stderr = &logs, &logs
	if err := proxy.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = proxy.Process.Kill()
		_ = proxy.Wait()
		if t.Failed() {
			t.Log(logs.String())
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		probe, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if err == nil {
			probe.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("HAProxy listener did not start", err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	testSingleAdaptiveLane(t, f, "https://"+address, origin.Certificate().Raw, protocol.CarrierHTTP2)
	if streams.Load() != 1 {
		t.Fatalf("expected one full-duplex HTTP/2 stream on the origin, got %d", streams.Load())
	}
}
