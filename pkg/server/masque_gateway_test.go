package server

import (
	"bytes"
	"context"
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

func TestMASQUEGateway_HTTP2Streaming(t *testing.T) {
	t.Run("half-close then cancel", func(t *testing.T) { testMASQUEHTTP2Streaming(t, false) })
	t.Run("target closes during upload", func(t *testing.T) { testMASQUEHTTP2Streaming(t, true) })
}

func testMASQUEHTTP2Streaming(t *testing.T, closeTarget bool) {
	t.Helper()
	target, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		conn, err := target.AcceptTCP()
		if err == nil {
			accepted <- conn
		}
	}()
	s := New(Config{Tunnels: []TunnelConfig{{Name: "reports", Target: target.Addr().String(), VirtualPort: 443}}}, nil)
	session := s.sessions.Create(CreateParams{TTL: time.Minute, Tunnels: []protocol.Tunnel{{Name: "reports"}}})
	gateway := &MASQUEGateway{server: s, config: MASQUEConfig{Tunnels: map[string]string{"reports.private": "reports"}}}
	handlerDone := make(chan struct{})
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(handlerDone)
		// Inject the already-authenticated session identity. Transport and
		// response buffering use a real TLS HTTP/2 connection.
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{SubjectKeyId: []byte(session.ID)}}}
		gateway.connect(w, r)
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	upload, send := io.Pipe()
	defer send.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, ts.URL, upload)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "reports.private:443"
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ProtoMajor != 2 {
		t.Fatalf("CONNECT response = %s %s", resp.Proto, resp.Status)
	}
	var conn *net.TCPConn
	select {
	case conn = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	checkRead := func(r io.Reader, want string) {
		t.Helper()
		buf := make([]byte, len(want))
		if _, err := io.ReadFull(r, buf); err != nil || string(buf) != want {
			t.Fatalf("read = %q, %v, want %q", buf, err, want)
		}
	}
	if _, err := send.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	checkRead(conn, "request")
	if _, err := conn.Write([]byte("short")); err != nil {
		t.Fatal(err)
	}
	checkRead(resp.Body, "short")
	if closeTarget {
		_ = conn.Close()
		if _, err := resp.Body.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("response after target closed = %v, want EOF", err)
		}
		return
	}
	_ = send.Close()
	if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("target read after upload EOF = %v", err)
	}
	if _, err := conn.Write([]byte("final")); err != nil {
		t.Fatal(err)
	}
	checkRead(resp.Body, "final")
	cancel()
	select {
	case <-handlerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not release the target after cancellation")
	}
}
