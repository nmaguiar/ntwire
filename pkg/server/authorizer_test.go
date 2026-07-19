package server

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthorizeWebhookAndFailure(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		_, _ = w.Write([]byte(`{"allow":true,"allowed_tunnels":["reports"],"ttl_seconds":30,"risk_score":2}`))
	})
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listeners unavailable: %v", err)
	}
	h := &httptest.Server{Listener: l, Config: &http.Server{Handler: handler}}
	h.Start()
	defer h.Close()
	got, err := Authorize(context.Background(), AuthorizerConfig{WebhookURL: h.URL, Timeout: time.Second}, AuthorizationInput{SessionID: "s"})
	if err != nil || !got.Allow || got.TTLSeconds != 30 || got.RiskScore != 2 {
		t.Fatalf("result=%+v err=%v", got, err)
	}
	if _, err := Authorize(context.Background(), AuthorizerConfig{WebhookURL: "http://127.0.0.1:1", Timeout: time.Millisecond}, AuthorizationInput{}); err == nil {
		t.Fatal("unreachable authorizer was allowed")
	}
}
