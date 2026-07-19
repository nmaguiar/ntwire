package oidcclient

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"golang.org/x/oauth2"
)

// fakeIdP is a minimal OAuth2/OIDC provider used to exercise the PKCE and
// device flows without a real browser or IdP. /authorize "logs the user in"
// immediately and redirects straight back to the client's redirect_uri, as
// PLAN-SSO.md's verification section describes.
type fakeIdP struct {
	server *httptest.Server
	signer jose.Signer
	jwk    jose.JSONWebKey

	mu       sync.Mutex
	codes    map[string]string // code -> code_challenge
	refresh  map[string]bool   // valid refresh tokens
	email    string
	scopes   []string // scopes_supported to advertise; controls the offline_access branch
	deviceOK bool
}

func newFakeIdP(t *testing.T, scopesSupported []string, deviceOK bool) *fakeIdP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.JSONWebKey{Key: priv.Public(), KeyID: "test-key", Algorithm: "RS256", Use: "sig"}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       jose.JSONWebKey{Key: priv, KeyID: "test-key", Algorithm: "RS256", Use: "sig"},
	}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{signer: signer, jwk: jwk, codes: map[string]string{}, refresh: map[string]bool{}, email: "alice@corp.com", scopes: scopesSupported, deviceOK: deviceOK}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"issuer":                 f.server.URL,
			"authorization_endpoint": f.server.URL + "/authorize",
			"token_endpoint":         f.server.URL + "/token",
			"jwks_uri":               f.server.URL + "/jwks",
			"scopes_supported":       f.scopes,
		}
		if f.deviceOK {
			doc["device_authorization_endpoint"] = f.server.URL + "/device"
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{f.jwk}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := "code-" + randHex(t)
		f.mu.Lock()
		f.codes[code] = q.Get("code_challenge")
		f.mu.Unlock()
		redirect, _ := url.Parse(q.Get("redirect_uri"))
		rq := redirect.Query()
		rq.Set("code", code)
		rq.Set("state", q.Get("state"))
		redirect.RawQuery = rq.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	})
	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code":      "devcode-1",
			"user_code":        "ABCD-EFGH",
			"verification_uri": f.server.URL + "/device/verify",
			"expires_in":       600,
			"interval":         1,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			code := r.Form.Get("code")
			f.mu.Lock()
			challenge, ok := f.codes[code]
			delete(f.codes, code)
			f.mu.Unlock()
			if !ok {
				http.Error(w, "invalid_grant", http.StatusBadRequest)
				return
			}
			if challenge != "" {
				sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
				if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
					http.Error(w, "invalid_grant: pkce mismatch", http.StatusBadRequest)
					return
				}
			}
			f.writeTokenResponse(t, w, true)
		case "urn:ietf:params:oauth:grant-type:device_code":
			f.writeTokenResponse(t, w, true)
		case "refresh_token":
			f.mu.Lock()
			ok := f.refresh[r.Form.Get("refresh_token")]
			f.mu.Unlock()
			if !ok {
				http.Error(w, "invalid_grant", http.StatusBadRequest)
				return
			}
			f.writeTokenResponse(t, w, false)
		default:
			http.Error(w, "unsupported_grant_type", http.StatusBadRequest)
		}
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeIdP) writeTokenResponse(t *testing.T, w http.ResponseWriter, newRefresh bool) {
	t.Helper()
	refreshToken := "refresh-" + randHex(t)
	if newRefresh {
		f.mu.Lock()
		f.refresh[refreshToken] = true
		f.mu.Unlock()
	}
	idToken := f.mintIDToken(t)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  "access-" + randHex(t),
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": refreshToken,
		"id_token":      idToken,
	})
}

func (f *fakeIdP) mintIDToken(t *testing.T) string {
	t.Helper()
	claims := map[string]any{
		"iss": f.server.URL, "sub": "user-1", "aud": "client-1",
		"email": f.email, "email_verified": true,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	}
	tok, err := jwt.Signed(f.signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func randHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// browserAsHTTPGet simulates "the browser" by GETing the authorization URL
// with a client that follows redirects, which drives the fake IdP's
// immediate redirect straight back to our loopback callback — completing
// the PKCE round trip without ever opening a real browser window.
func browserAsHTTPGet(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func TestLoginPKCE(t *testing.T) {
	idp := newFakeIdP(t, []string{"openid", "email", "offline_access"}, false)
	tok, err := Login(context.Background(), idp.server.URL, LoginOptions{
		ClientID: "client-1", Scopes: []string{"openid", "email"}, OpenBrowser: browserAsHTTPGet,
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if tok.IDToken == "" || tok.RefreshToken == "" {
		t.Fatalf("tokens = %+v", tok)
	}
	if tok.Expiry.IsZero() || tok.Expiry.Before(time.Now()) {
		t.Fatalf("expiry not parsed: %v", tok.Expiry)
	}
}

func TestLoginPKCEAccessTypeOfflineFallback(t *testing.T) {
	// No offline_access in scopes_supported: buildOAuth2Config must fall
	// back to access_type=offline (the Google-style quirk) and the flow
	// must still complete and return a refresh token.
	idp := newFakeIdP(t, []string{"openid", "email"}, false)
	tok, err := Login(context.Background(), idp.server.URL, LoginOptions{
		ClientID: "client-1", Scopes: []string{"openid", "email"}, OpenBrowser: browserAsHTTPGet,
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if tok.RefreshToken == "" {
		t.Fatal("expected a refresh token via access_type=offline fallback")
	}
}

func TestLoginPKCEBrowserOpenFailureFallsBackToDevice(t *testing.T) {
	idp := newFakeIdP(t, []string{"openid", "email"}, true)
	var prompted bool
	tok, err := Login(context.Background(), idp.server.URL, LoginOptions{
		ClientID:    "client-1",
		Scopes:      []string{"openid", "email"},
		OpenBrowser: func(string) error { return errors.New("no browser binary found") },
		DevicePrompt: func(da *oauth2.DeviceAuthResponse) {
			prompted = true
		},
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !prompted {
		t.Fatal("expected device flow prompt after browser-open failure")
	}
	if tok.IDToken == "" {
		t.Fatalf("tokens = %+v", tok)
	}
}

func TestLoginNoBrowserUsesDeviceFlow(t *testing.T) {
	idp := newFakeIdP(t, []string{"openid", "email"}, true)
	tok, err := Login(context.Background(), idp.server.URL, LoginOptions{
		ClientID: "client-1", Scopes: []string{"openid", "email"}, NoBrowser: true,
		DevicePrompt: func(da *oauth2.DeviceAuthResponse) {},
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if tok.IDToken == "" {
		t.Fatalf("tokens = %+v", tok)
	}
}

func TestLoginNoBrowserErrorsWithoutDeviceSupport(t *testing.T) {
	idp := newFakeIdP(t, []string{"openid", "email"}, false)
	if _, err := Login(context.Background(), idp.server.URL, LoginOptions{ClientID: "client-1", NoBrowser: true}); err == nil {
		t.Fatal("expected an error when the issuer has no device authorization endpoint")
	}
}

func TestRefresh(t *testing.T) {
	idp := newFakeIdP(t, []string{"openid", "email", "offline_access"}, false)
	initial, err := Login(context.Background(), idp.server.URL, LoginOptions{
		ClientID: "client-1", Scopes: []string{"openid", "email"}, OpenBrowser: browserAsHTTPGet,
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	refreshed, err := Refresh(context.Background(), idp.server.URL, "client-1", initial.RefreshToken, []string{"openid", "email"})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if refreshed.IDToken == "" {
		t.Fatalf("tokens = %+v", refreshed)
	}
}

func TestCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/tokens.json"
	c, err := OpenCache(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get("https://server", "google"); ok {
		t.Fatal("expected empty cache")
	}
	entry := CacheEntry{RefreshToken: "r1", IDToken: "id1", Expiry: time.Now().Add(time.Hour).Truncate(time.Second)}
	if err := c.Put("https://server", "google", entry); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenCache(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reopened.Get("https://server", "google")
	if !ok || got.RefreshToken != "r1" || got.IDToken != "id1" || !got.Expiry.Equal(entry.Expiry) {
		t.Fatalf("got = %+v", got)
	}
	if _, ok := reopened.Get("https://server", "entra"); ok {
		t.Fatal("different issuer on the same server must not collide")
	}

	if err := reopened.DeleteServer("https://server"); err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.Get("https://server", "google"); ok {
		t.Fatal("DeleteServer should remove the entry")
	}
}

func TestTokensForIssuerUsesCacheThenRefreshesThenLogsIn(t *testing.T) {
	idp := newFakeIdP(t, []string{"openid", "email", "offline_access"}, false)
	issuer := protocol.OIDCIssuerInfo{Name: "test", Issuer: idp.server.URL, ClientID: "client-1", Scopes: []string{"openid", "email"}}

	dir := t.TempDir()
	cache, err := OpenCache(dir + "/tokens.json")
	if err != nil {
		t.Fatal(err)
	}

	var opened int
	opts := ForIssuerOptions{OpenBrowser: func(u string) error { opened++; return browserAsHTTPGet(u) }}

	first, err := TokensForIssuer(context.Background(), cache, "https://myserver", issuer, opts)
	if err != nil {
		t.Fatalf("TokensForIssuer (login): %v", err)
	}
	if opened != 1 {
		t.Fatalf("opened = %d, want 1 (interactive login)", opened)
	}
	if first.IDToken == "" {
		t.Fatalf("first = %+v", first)
	}

	second, err := TokensForIssuer(context.Background(), cache, "https://myserver", issuer, opts)
	if err != nil {
		t.Fatalf("TokensForIssuer (refresh): %v", err)
	}
	if opened != 1 {
		t.Fatalf("opened = %d, want still 1 (silent refresh, no browser)", opened)
	}
	if second.IDToken == "" {
		t.Fatalf("second = %+v", second)
	}
}
