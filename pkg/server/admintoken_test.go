package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func adminServer(t *testing.T) *Server {
	t.Helper()
	c := Config{}
	c.Admin.WebUIToken = adminTestToken
	return New(c, nil)
}

// TestDashboardRejectsQueryStringToken is the regression test for the admin
// credential travelling in the URL: every dashboard poll wrote it into access
// logs and browser history. Only GET / still accepts it, and only to exchange
// it for a cookie.
func TestDashboardRejectsQueryStringToken(t *testing.T) {
	s := adminServer(t)
	rec := httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/dashboard?token="+adminTestToken, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for a query-string token", rec.Code)
	}
}

// TestDashboardBootstrapSetsCookieAndStripsToken covers the operator's way in:
// GET / accepts the token once, sets an HttpOnly cookie, and redirects to a URL
// without it.
func TestDashboardBootstrapSetsCookieAndStripsToken(t *testing.T) {
	s := adminServer(t)
	rec := httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/?token="+adminTestToken, nil))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "token") {
		t.Fatalf("redirect still carries the token: %s", loc)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != adminCookie || cookies[0].Value != adminTestToken {
		t.Fatalf("cookie = %+v", cookies)
	}
	if !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie must be HttpOnly and SameSite=Strict: %+v", cookies[0])
	}

	// The cookie then authenticates the page's own polling.
	poll := httptest.NewRequest(http.MethodGet, "/v1/dashboard", nil)
	poll.AddCookie(cookies[0])
	rec = httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(rec, poll)
	if rec.Code != http.StatusOK {
		t.Fatalf("cookie-authenticated poll status = %d", rec.Code)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("dashboard data lists live identities and must not be cached")
	}
}

// TestDashboardBootstrapRejectsWrongToken keeps the one query-string entry
// point from becoming an oracle.
func TestDashboardBootstrapRejectsWrongToken(t *testing.T) {
	s := adminServer(t)
	rec := httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/?token=wrong", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("a wrong token must not set a cookie")
	}
}

// TestRevokeRejectsCookieAuth is the CSRF guard: a browser attaches the
// dashboard cookie to a cross-site POST but cannot attach an Authorization
// header, so revoke must require the header.
func TestRevokeRejectsCookieAuth(t *testing.T) {
	s := adminServer(t)
	session := s.sessions.Create(CreateParams{Method: "ssh", Identity: "fp", TTL: time.Minute})

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/sessions/"+session.ID+"/revoke", nil)
	req.AddCookie(&http.Cookie{Name: adminCookie, Value: adminTestToken})
	rec := httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for cookie-only revoke", rec.Code)
	}
	if _, ok := s.sessions.Get(session.Token); !ok {
		t.Fatal("session was revoked by a cookie-authenticated request")
	}
}

// TestAdminSurfaceIsRateLimited covers the per-source cap: the operator token is
// hand-chosen and is the only credential on this surface.
func TestAdminSurfaceIsRateLimited(t *testing.T) {
	s := adminServer(t)
	h := s.MetricsHandler()
	var last int
	for i := 0; i < maxAdminRequestsPerMinute+1; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/dashboard", nil))
		last = rec.Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("status = %d after %d requests, want 429", last, maxAdminRequestsPerMinute+1)
	}
}

// TestShortAdminTokenRejected covers the config-load strength check.
func TestShortAdminTokenRejected(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/ntwire.yaml"
	yaml := "listen:\n  https: \"127.0.0.1:8443\"\nauth:\n  authorized_keys_dir: " + dir + "\nadmin:\n  web_ui_token: \"short\"\ntunnels: []\n"
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "web_ui_token") {
		t.Fatalf("err = %v, want an admin.web_ui_token length error", err)
	}
}
