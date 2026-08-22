package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

type fullDuplexRecorder struct{ *httptest.ResponseRecorder }

func (fullDuplexRecorder) EnableFullDuplex() error { return nil }

func TestMASQUEGateway_CONNECTOnlyMapsGrantedFixedTarget(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		conn, acceptErr := target.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		body, _ := io.ReadAll(conn)
		_, _ = conn.Write(append([]byte("reply:"), body...))
	}()

	address := target.Addr().String()
	s := New(Config{Tunnels: []TunnelConfig{{Name: "reports", Target: address, VirtualPort: 443}}}, nil)
	session := s.sessions.Create(CreateParams{Method: "oidc", Identity: "alice@example.test", TTL: time.Minute, Tunnels: []protocol.Tunnel{{Name: "reports", VirtualPort: 443}}})
	gateway := &MASQUEGateway{server: s, config: MASQUEConfig{Tunnels: map[string]string{"reports.private.example.test": "reports"}}}

	req := httptest.NewRequest(http.MethodConnect, "https://reports.private.example.test:443", bytes.NewBufferString("hello"))
	req.Host = "reports.private.example.test:443"
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{SubjectKeyId: []byte(session.ID)}}}
	w := fullDuplexRecorder{httptest.NewRecorder()}
	gateway.connect(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if got := w.Body.String(); got != "reply:hello" {
		t.Fatalf("response = %q", got)
	}
}

func TestMASQUEGateway_RejectsUnmappedOrUnauthorizedTunnel(t *testing.T) {
	s := New(Config{Tunnels: []TunnelConfig{{Name: "reports", Target: "127.0.0.1:1", VirtualPort: 443}}}, nil)
	session := s.sessions.Create(CreateParams{Method: "oidc", Identity: "alice@example.test", TTL: time.Minute})
	gateway := &MASQUEGateway{server: s, config: MASQUEConfig{Tunnels: map[string]string{"reports.private.example.test": "reports"}}}
	req := httptest.NewRequest(http.MethodConnect, "https://reports.private.example.test:443", nil)
	req.Host, req.TLS = "reports.private.example.test:443", &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{SubjectKeyId: []byte(session.ID)}}}
	w := fullDuplexRecorder{httptest.NewRecorder()}
	gateway.connect(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}

}
