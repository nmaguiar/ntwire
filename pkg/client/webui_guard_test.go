package client

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// uiClient returns a running connection's local status UI URL plus an HTTP
// client that does not follow redirects, so the bootstrap can be inspected.
func startTestUI(t *testing.T) (*Connection, string, *http.Client) {
	t.Helper()
	c := &Connection{}
	c.startWebUI()
	t.Cleanup(func() {
		if c.ui != nil {
			_ = c.ui.Close()
		}
	})
	if c.UIURL == "" {
		t.Fatal("status UI did not start")
	}
	return c, c.UIURL, &http.Client{
		Timeout:       3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func uiToken(t *testing.T, uiURL string) (base, token string) {
	t.Helper()
	u, err := url.Parse(uiURL)
	if err != nil {
		t.Fatal(err)
	}
	token = u.Query().Get("token")
	u.RawQuery = ""
	u.Path = ""
	return u.String(), token
}

// TestStatusUISetsSecurityHeaders covers the headers this origin needs: it holds
// a token that can rebind a tunnel listener onto a LAN interface and launch
// browsers, so it must not leak through a Referer, be framed, or be cached.
func TestStatusUISetsSecurityHeaders(t *testing.T) {
	_, uiURL, h := startTestUI(t)
	resp, err := h.Get(uiURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	for header, want := range map[string]string{
		"Referrer-Policy":        "no-referrer",
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"Cache-Control":          "no-store",
	} {
		if got := resp.Header.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "connect-src 'self'") {
		t.Errorf("CSP should bound where this page can send the token: %q", csp)
	}
}

// TestStatusUIBootstrapStripsToken is the regression test for the access token
// living in the page URL, where it reached browser history and any Referer.
func TestStatusUIBootstrapStripsToken(t *testing.T) {
	_, uiURL, h := startTestUI(t)
	resp, err := h.Get(uiURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); strings.Contains(loc, "token") {
		t.Fatalf("redirect still carries the token: %s", loc)
	}
	cookies := resp.Cookies()
	if len(cookies) != 1 || cookies[0].Name != uiCookie || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie = %+v", cookies)
	}
}

// TestStatusUIRejectsQueryTokenOnAPIRoutes checks that only the root exchanges a
// query token; the polling routes must not accept a credential in a URL.
func TestStatusUIRejectsQueryTokenOnAPIRoutes(t *testing.T) {
	_, uiURL, h := startTestUI(t)
	base, token := uiToken(t, uiURL)
	resp, err := h.Get(base + "/status?token=" + token)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for a query-string token", resp.StatusCode)
	}
}

// TestStatusUIAcceptsHeaderToken keeps the CLI path working: `ntwire status`
// and friends fetch /status with the token as a bearer header.
func TestStatusUIAcceptsHeaderToken(t *testing.T) {
	_, uiURL, h := startTestUI(t)
	base, token := uiToken(t, uiURL)
	req, _ := http.NewRequest(http.MethodGet, base+"/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := h.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// TestStatusUIRejectsCrossOriginWrite is the CSRF guard: the cookie is attached
// by the browser to a request forged by any page the user visits, so a
// state-changing route must also require a same-origin (or absent) Origin.
func TestStatusUIRejectsCrossOriginWrite(t *testing.T) {
	_, uiURL, h := startTestUI(t)
	base, token := uiToken(t, uiURL)

	req, _ := http.NewRequest(http.MethodPut, base+"/tunnels/reports", strings.NewReader(`{"local_port":1234}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a cross-origin write", resp.StatusCode)
	}
}

// TestFetchWebStatusUsesHeader checks that the CLI helper moves the token out of
// the URL, which is what let the API routes stop accepting a query credential.
func TestFetchWebStatusUsesHeader(t *testing.T) {
	var sawQuery, sawHeader bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawQuery = r.URL.Query().Get("token") != ""
		sawHeader = strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"connected":true}`))
	}))
	defer srv.Close()

	if _, err := FetchWebStatus(srv.URL + "/?token=secret"); err != nil {
		t.Fatal(err)
	}
	if sawQuery {
		t.Fatal("token was sent in the query string")
	}
	if !sawHeader {
		t.Fatal("token was not sent as a bearer header")
	}
}
