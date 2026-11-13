package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

func TestOIDCSessionQuotaPrincipal(t *testing.T) {
	a, b := newFakeIdP(t), newFakeIdP(t)
	cfg := Config{}
	cfg.Auth.SessionTTL = time.Minute
	cfg.Auth.MaxSessionsPerKey = 1
	cfg.Auth.OIDC.Issuers = []OIDCIssuerConfig{
		{Name: "a", Issuer: a.server.URL, ClientID: "client-1"},
		{Name: "b", Issuer: b.server.URL, ClientID: "client-1"},
		{Name: "alias", Issuer: a.server.URL, ClientID: "client-1"},
	}
	s := New(cfg, nil)
	handler := s.Handler()
	auth := func(idp *fakeIdP, issuer, subject, email string, query bool, want int) protocol.AuthResponse {
		t.Helper()
		tok := idp.token(t, map[string]any{"sub": subject, "aud": "client-1", "email": email, "email_verified": true})
		body, err := json.Marshal(protocol.OIDCAuthRequest{Version: protocol.Version, IssuerName: issuer, IDToken: tok, Timestamp: time.Now().UTC().Format(time.RFC3339), QueryOnly: query})
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("POST", "/v1/auth/oidc", bytes.NewReader(body)))
		if w.Code != want {
			t.Fatalf("issuer=%s subject=%s email=%s query=%v: status %d, want %d: %s", issuer, subject, email, query, w.Code, want, w.Body.String())
		}
		var out protocol.AuthResponse
		if want == http.StatusOK {
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
		}
		return out
	}
	first := auth(a, "a", "user-1", "same@example.com", false, http.StatusOK)
	if first.Identity != "same@example.com" || first.Token == "" {
		t.Fatalf("display identity/session changed: %+v", first)
	}
	// Neither another issuer nor another subject shares this principal's cap.
	auth(b, "b", "user-1", "same@example.com", false, http.StatusOK)
	auth(a, "a", "user-2", "same@example.com", false, http.StatusOK)
	// Email changes and configured aliases cannot bypass the original cap.
	auth(a, "a", "user-1", "changed@example.com", false, http.StatusTooManyRequests)
	auth(a, "alias", "user-1", "same@example.com", false, http.StatusTooManyRequests)
	query := auth(a, "a", "user-1", "same@example.com", true, http.StatusOK)
	if query.Token != "" {
		t.Fatal("query-only created session")
	}
	// Renewal must retain quota ownership even though it rotates session tokens.
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/renew", bytes.NewBufferString(`{}`))
	req.Header.Set("Authorization", "Bearer "+first.Token)
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("renew: %d %s", w.Code, w.Body.String())
	}
	auth(a, "a", "user-1", "changed@example.com", false, http.StatusTooManyRequests)
	auth(b, "b", "user-1", "same@example.com", false, http.StatusTooManyRequests)
}

func TestSessionQuotaExpiryAndSSH(t *testing.T) {
	s := NewSessions()
	s.Create(CreateParams{Method: "oidc", Identity: "old-email", OIDCIssuer: "issuer", OIDCSubject: "subject", TTL: time.Minute})
	s.Create(CreateParams{Method: "oidc", Identity: "new-email", OIDCIssuer: "issuer", OIDCSubject: "subject", TTL: -time.Second})
	s.Create(CreateParams{Method: "ssh", Identity: "fp", TTL: time.Minute})
	s.Create(CreateParams{Method: "ssh", Identity: "other", TTL: time.Minute})
	for _, tc := range []struct {
		method, identity, issuer, subject string
		want                              int
	}{
		{"oidc", "new-email", "issuer", "subject", 1},
		{"oidc", "old-email", "other-issuer", "subject", 0},
		{"oidc", "old-email", "issuer", "other-subject", 0},
		{"ssh", "fp", "", "", 1},
		{"ssh", "old-email", "", "", 0},
	} {
		if got := s.CountIdentity(tc.method, tc.identity, tc.issuer, tc.subject); got != tc.want {
			t.Fatalf("%+v: got %d", tc, got)
		}
	}
	if len(s.All()) != 4 {
		t.Fatal("count discarded expired cleanup record")
	}
	if len(s.Reap()) != 1 {
		t.Fatal("expired session not reaped")
	}
}
