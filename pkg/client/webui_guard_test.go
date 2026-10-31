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
	return startTestUIWithOptions(t, Options{})
}

func startTestUIWithOptions(t *testing.T, options Options) (*Connection, string, *http.Client) {
	t.Helper()
	c := &Connection{options: options}
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

func TestStatusUISettingsFramePolicy(t *testing.T) {
	cases := []struct {
		name, settingsURL, want string
	}{
		{"GUI settings", "http://127.0.0.1:54321/?token=secret&setup=1", "http://127.0.0.1:54321"},
		{"CLI settings", "http://127.0.0.1:54322/?token=secret", "http://127.0.0.1:54322"},
		{"HTTPS loopback", "https://127.0.0.1:54323/path?token=secret#settings", "https://127.0.0.1:54323"},
		{"default port", "http://127.0.0.1/?token=secret", "http://127.0.0.1"},
		{"IPv6 loopback", "http://[::1]:54321/?token=secret", "http://[::1]:54321"},
		{"absent", "", "'none'"},
		{"malformed", "://bad", "'none'"},
		{"relative", "/settings?token=secret", "'none'"},
		{"remote", "https://example.com/?token=secret", "'none'"},
		{"non-loopback", "http://192.168.1.1:54321/", "'none'"},
		{"DNS host", "http://localhost:54321/", "'none'"},
		{"userinfo", "http://user:secret@127.0.0.1:54321/", "'none'"},
		{"unsupported scheme", "ftp://127.0.0.1:54321/", "'none'"},
		{"port wildcard", "http://127.0.0.1:*/", "'none'"},
		{"port out of range", "http://127.0.0.1:65536/", "'none'"},
		{"zero port", "http://127.0.0.1:0/", "'none'"},
		{"IPv6 zone", "http://[::1%25lo0]:54321/", "'none'"},
		{"directive injection", "http://127.0.0.1:54321; frame-src */", "'none'"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			uiSecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}), tc.settingsURL).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
			if rr.Code != http.StatusNoContent {
				t.Fatalf("wrapped handler status = %d", rr.Code)
			}
			csp := rr.Header().Get("Content-Security-Policy")
			want := "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-src " + tc.want + "; form-action 'none'; frame-ancestors 'none'; base-uri 'none'"
			if csp != want {
				t.Errorf("CSP = %q, want %q", csp, want)
			}
			for header, want := range map[string]string{
				"Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
				"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
			} {
				if got := rr.Header().Get(header); got != want {
					t.Errorf("%s = %q, want %q", header, got, want)
				}
			}
			if strings.Contains(csp, "secret") || strings.Contains(csp, "setup=") {
				t.Error("CSP contains settings credentials or query parameters")
			}
		})
	}
}

func TestStatusUIAllowsConfiguredSettingsFrame(t *testing.T) {
	settingsURL := "http://127.0.0.1:54321/?token=secret"
	_, uiURL, h := startTestUIWithOptions(t, Options{SettingsURL: settingsURL})
	resp, err := h.Get(uiURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	base, _ := uiToken(t, uiURL)
	req, _ := http.NewRequest(http.MethodGet, base+"/", nil)
	for _, cookie := range resp.Cookies() {
		req.AddCookie(cookie)
	}
	resp, err = h.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dashboard status = %d, want 200", resp.StatusCode)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "; frame-src http://127.0.0.1:54321;") || strings.Contains(csp, "secret") {
		t.Fatalf("dashboard CSP does not allow exactly the configured settings origin: %q", csp)
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
	if len(cookies) != 1 || cookies[0].Name != uiCookie || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
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

// TestNewUIRequestReachesEveryRoute is the regression test for the out-of-process
// CLI commands (`ntwire port`, `ntwire transport`, `ntwire status`). They live in
// a separate process and reach a running client only over this UI, carrying the
// token from Status.UIURL. When the routes stopped accepting a query-string
// token, anything that kept passing UIURL's raw query silently started 404ing --
// a break no package-level test would have caught.
func TestNewUIRequestReachesEveryRoute(t *testing.T) {
	c, uiURL, h := startTestUI(t)
	c.tunnels = []*localTunnel{{name: "reports", localAddr: "127.0.0.1:58080"}}

	cases := []struct {
		name, method, path string
		body               string
		wantNot            int
	}{
		{"status", http.MethodGet, "/status", "", http.StatusNotFound},
		{"transport read", http.MethodGet, "/transport", "", http.StatusNotFound},
		{"transport write", http.MethodPut, "/transport", `{"transport":""}`, http.StatusNotFound},
		{"replace port", http.MethodPut, "/tunnels/reports", `{"local_port":58081}`, http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var body *strings.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}
			var req *http.Request
			var err error
			if body != nil {
				req, err = NewUIRequest(uiURL, tc.method, tc.path, body)
			} else {
				req, err = NewUIRequest(uiURL, tc.method, tc.path, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			if q := req.URL.RawQuery; q != "" {
				t.Fatalf("token left in the query string: %q", q)
			}
			if !strings.HasPrefix(req.Header.Get("Authorization"), "Bearer ") {
				t.Fatal("token was not moved to a bearer header")
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := h.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode == tc.wantNot {
				t.Fatalf("%s %s returned 404: the CLI cannot reach this route", tc.method, tc.path)
			}
		})
	}
}
