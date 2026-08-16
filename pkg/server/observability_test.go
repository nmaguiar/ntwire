package server

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/logging"
	"github.com/nmaguiar/ntwire/pkg/protocol"
)

func TestAuthorizationHookDenialIsAuditedAndCountedWithoutSensitiveFields(t *testing.T) {
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"allow":false,"reason":"operator-specific detail"}`))
	}))
	defer hook.Close()

	var audit bytes.Buffer
	s := New(Config{Authorizer: AuthorizerConfig{WebhookURL: hook.URL, Timeout: time.Second}}, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	s.SetAuditLog(slog.New(logging.NewLogstashHandler(&audit, slog.LevelInfo)))
	_, _, err := s.authorize(httptest.NewRequest(http.MethodPost, "https://server.test/v1/auth", nil), authContext{Method: "oidc", Identity: "alice@example.test"}, protocol.ClientInfo{}, nil)
	if err == nil {
		t.Fatal("authorize() allowed a denied hook response")
	}
	line := audit.String()
	for _, want := range []string{`"event":"authorization_hook_denied"`, `"method":"oidc"`, `"reason":"hook_denied"`} {
		if !strings.Contains(line, want) {
			t.Fatalf("audit record missing %q: %s", want, line)
		}
	}
	for _, forbidden := range []string{"alice@example.test", "operator-specific detail", hook.URL} {
		if strings.Contains(line, forbidden) {
			t.Fatalf("audit record leaked %q: %s", forbidden, line)
		}
	}

	rec := httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(rec.Body.String(), `ntwire_lifecycle_events_total{event="authorization_hook_denied",method="oidc"} 1`) {
		t.Fatalf("metrics missing hook denial counter:\n%s", rec.Body.String())
	}
}

func TestAuthenticationFailureIsAuditedAndCountedWithoutRequestData(t *testing.T) {
	var audit bytes.Buffer
	s := New(Config{}, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	s.SetAuditLog(slog.New(logging.NewLogstashHandler(&audit, slog.LevelInfo)))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/auth", strings.NewReader(`{"public_key":"request-secret"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	line := audit.String()
	for _, want := range []string{`"event":"authentication_failed"`, `"method":"ssh"`, `"reason":"rejected"`} {
		if !strings.Contains(line, want) {
			t.Fatalf("audit record missing %q: %s", want, line)
		}
	}
	if strings.Contains(line, "request-secret") {
		t.Fatalf("audit record leaked request data: %s", line)
	}
	rec = httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(rec.Body.String(), `ntwire_lifecycle_events_total{event="authentication_failed",method="ssh"} 1`) {
		t.Fatalf("metrics missing authentication failure counter:\n%s", rec.Body.String())
	}
}
