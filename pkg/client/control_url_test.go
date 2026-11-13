package client

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coder/websocket"
)

func TestControlURLPolicy(t *testing.T) {
	for _, raw := range []string{"http://example.test", "http://192.0.2.1", "http://localhost", "http://127.0.0.1.example.test", "http://2130706433", "http://[::]", "https://user:secret@example.test"} {
		if _, err := NormalizeServerURL(raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
		if _, err := httpClient(raw, Options{Insecure: true}); err == nil {
			t.Errorf("client accepted %q", raw)
		}
	}
	for _, raw := range []string{"https://example.test", "http://127.0.0.1:8080", "http://127.2.3.4", "http://[::1]:8080", "http://[::ffff:127.0.0.1]:8080"} {
		if _, err := NormalizeServerURL(raw); err != nil {
			t.Errorf("rejected %q: %v", raw, err)
		}
	}
}

func TestControlTransportRejectsPlaintextBeforeDial(t *testing.T) {
	dialed := false
	h := resilientHTTPClient(nil, nil, func(context.Context, string, string) (net.Conn, error) { dialed = true; return nil, net.ErrClosed })
	for _, raw := range []string{"http://example.test/v1/auth/oidc", "http://192.0.2.1/v1/renew"} {
		req, _ := http.NewRequest(http.MethodPost, raw, strings.NewReader(`{"id_token":"secret"}`))
		req.Header.Set("Authorization", "Bearer secret")
		if _, err := h.Do(req); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	if _, _, err := websocket.Dial(context.Background(), "ws://example.test/v1/wg", &websocket.DialOptions{HTTPClient: h, HTTPHeader: http.Header{"Authorization": {"Bearer secret"}}}); err == nil {
		t.Fatal("accepted plaintext WebSocket")
	}
	if dialed {
		t.Fatal("unsafe request reached dialer")
	}
}

func TestControlTransportRedirectAndLegitimateRequests(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://example.test/v1/auth/oidc", http.StatusTemporaryRedirect)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer s.Close()
	h, err := httpClient(s.URL, Options{NoSystemProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	defer h.CloseIdleConnections()
	resp, err := h.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatal(resp.Status)
	}
	if _, err := h.Post(s.URL+"/redirect", "application/json", strings.NewReader(`{"id_token":"secret"}`)); err == nil || !strings.Contains(err.Error(), "requires HTTPS") {
		t.Fatalf("redirect = %v", err)
	}
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer tlsServer.Close()
	secure, err := httpClient(tlsServer.URL, Options{Insecure: true, NoSystemProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	defer secure.CloseIdleConnections()
	resp, err = secure.Get(tlsServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatal(resp.Status)
	}
}

func TestLoopbackHTTPRejectsRemoteProxy(t *testing.T) {
	for _, proxy := range []string{"http://192.0.2.1:8080", "socks5://192.0.2.1:1080", "socks5h://proxy.example:1080"} {
		h, err := httpClient("https://example.test", Options{HTTPSProxy: proxy})
		if err != nil {
			t.Fatal(err)
		}
		dialed := false
		h.Transport.(*secureControlTransport).DialContext = func(context.Context, string, string) (net.Conn, error) { dialed = true; return nil, net.ErrClosed }
		_, err = h.Post("http://127.0.0.1:8080/v1/auth/oidc", "application/json", strings.NewReader(`{"id_token":"secret"}`))
		if err == nil || !strings.Contains(err.Error(), "remote proxy") || dialed {
			t.Fatalf("proxy %s: err=%v dialed=%v", proxy, err, dialed)
		}
	}
}
