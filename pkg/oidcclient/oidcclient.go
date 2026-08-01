// Package oidcclient runs the IdP-facing side of SSO login: PKCE in the
// system browser with an OAuth Device Authorization (RFC 8628) fallback for
// headless machines, plus a local token cache so a long-running connection
// can silently refresh instead of reopening the browser.
package oidcclient

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Tokens is the result of a successful login or refresh.
type Tokens struct {
	IDToken      string
	RefreshToken string
	Expiry       time.Time // ID token expiry, best-effort; zero if it could not be parsed.
}

// LoginOptions configures how Login obtains tokens from one issuer.
type LoginOptions struct {
	ClientID string
	// ClientSecret is only needed for IdPs (e.g. Google's "Desktop app"
	// client type) whose token endpoint requires it even for a
	// public/PKCE registration; see docs/OIDC-SETUP.md. Leave empty
	// otherwise.
	ClientSecret string
	Scopes       []string
	NoBrowser    bool // skip PKCE and go straight to the device flow

	// OpenBrowser launches url in the user's browser. Defaults to the
	// platform opener (open/xdg-open/rundll32). Tests substitute a fake that
	// drives the authorization endpoint directly.
	OpenBrowser func(url string) error

	// DevicePrompt tells the user to visit the verification URI and enter
	// the user code. Defaults to printing to stderr.
	DevicePrompt func(*oauth2.DeviceAuthResponse)
}

// Login runs the PKCE browser flow, falling back to the device flow when
// NoBrowser is set or the browser could not be launched. It returns an error
// naming the issuer when device flow is required but unsupported.
func Login(ctx context.Context, issuerURL string, opts LoginOptions) (Tokens, error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return Tokens{}, fmt.Errorf("discover issuer %s: %w", issuerURL, err)
	}
	cfg, extraAuthOpts := buildOAuth2Config(provider, opts.ClientID, opts.Scopes)
	cfg.ClientSecret = opts.ClientSecret

	if !opts.NoBrowser {
		tok, err := loginPKCE(ctx, cfg, opts, extraAuthOpts)
		if err == nil {
			return tok, nil
		}
		if cfg.Endpoint.DeviceAuthURL == "" {
			return Tokens{}, err
		}
	}
	if cfg.Endpoint.DeviceAuthURL == "" {
		return Tokens{}, fmt.Errorf("issuer %s does not support device authorization and no browser is available", issuerURL)
	}
	return loginDevice(ctx, cfg, opts, extraAuthOpts)
}

// buildOAuth2Config adds "offline_access" to the requested scopes when the
// issuer advertises it, and otherwise falls back to the Google-style
// access_type=offline query parameter — the one provider quirk worth
// special-casing to get a refresh token from every configured issuer.
func buildOAuth2Config(provider *oidc.Provider, clientID string, scopes []string) (*oauth2.Config, []oauth2.AuthCodeOption) {
	var claims struct {
		ScopesSupported []string `json:"scopes_supported"`
	}
	supportsOfflineAccessScope := false
	if provider.Claims(&claims) == nil {
		for _, s := range claims.ScopesSupported {
			if s == "offline_access" {
				supportsOfflineAccessScope = true
			}
		}
	}
	finalScopes := append([]string(nil), scopes...)
	if supportsOfflineAccessScope && !containsString(finalScopes, "offline_access") {
		finalScopes = append(finalScopes, "offline_access")
	}
	cfg := &oauth2.Config{ClientID: clientID, Endpoint: provider.Endpoint(), Scopes: finalScopes}
	var extra []oauth2.AuthCodeOption
	if !supportsOfflineAccessScope {
		extra = append(extra, oauth2.AccessTypeOffline)
	}
	return cfg, extra
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

type callbackResult struct {
	code string
	err  error
}

// loginPKCE runs Auth Code + PKCE against a loopback redirect. authOpts are
// appended after the S256 challenge on the authorization URL.
func loginPKCE(ctx context.Context, cfg *oauth2.Config, opts LoginOptions, authOpts []oauth2.AuthCodeOption) (Tokens, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return Tokens{}, err
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	cfgCopy := *cfg
	cfgCopy.RedirectURL = fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	verifier := oauth2.GenerateVerifier()
	state, err := randomState()
	if err != nil {
		return Tokens{}, err
	}

	resultCh := make(chan callbackResult, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("state") != state {
			http.Error(w, "invalid state", http.StatusBadRequest)
			select {
			case resultCh <- callbackResult{err: fmt.Errorf("callback state mismatch")}:
			default:
			}
			return
		}
		if e := q.Get("error"); e != "" {
			http.Error(w, "login failed", http.StatusBadRequest)
			select {
			case resultCh <- callbackResult{err: fmt.Errorf("authorization error: %s", e)}:
			default:
			}
			return
		}
		fmt.Fprint(w, "Login complete; you may close this window.")
		select {
		case resultCh <- callbackResult{code: q.Get("code")}:
		default:
		}
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(listener) }()
	defer srv.Close()

	opener := opts.OpenBrowser
	if opener == nil {
		opener = defaultOpenBrowser
	}
	allOpts := append([]oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier)}, authOpts...)
	authURL := cfgCopy.AuthCodeURL(state, allOpts...)
	if err := opener(authURL); err != nil {
		return Tokens{}, fmt.Errorf("open browser: %w", err)
	}

	select {
	case res := <-resultCh:
		if res.err != nil {
			return Tokens{}, res.err
		}
		tok, err := cfgCopy.Exchange(ctx, res.code, oauth2.VerifierOption(verifier))
		if err != nil {
			return Tokens{}, err
		}
		return tokensFromOAuth2(tok)
	case <-time.After(5 * time.Minute):
		return Tokens{}, fmt.Errorf("timed out waiting for browser login")
	case <-ctx.Done():
		return Tokens{}, ctx.Err()
	}
}

func loginDevice(ctx context.Context, cfg *oauth2.Config, opts LoginOptions, authOpts []oauth2.AuthCodeOption) (Tokens, error) {
	da, err := cfg.DeviceAuth(ctx, authOpts...)
	if err != nil {
		return Tokens{}, fmt.Errorf("start device authorization: %w", err)
	}
	prompt := opts.DevicePrompt
	if prompt == nil {
		prompt = defaultDevicePrompt
	}
	prompt(da)
	tok, err := cfg.DeviceAccessToken(ctx, da, authOpts...)
	if err != nil {
		return Tokens{}, err
	}
	return tokensFromOAuth2(tok)
}

func defaultDevicePrompt(da *oauth2.DeviceAuthResponse) {
	if da.VerificationURIComplete != "" {
		fmt.Printf("To sign in, visit: %s\n", da.VerificationURIComplete)
	} else {
		fmt.Printf("To sign in, visit %s and enter code %s\n", da.VerificationURI, da.UserCode)
	}
}

// Refresh silently mints a fresh ID token from a cached refresh token.
func Refresh(ctx context.Context, issuerURL, clientID, clientSecret, refreshToken string, scopes []string) (Tokens, error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return Tokens{}, fmt.Errorf("discover issuer %s: %w", issuerURL, err)
	}
	cfg := &oauth2.Config{ClientID: clientID, ClientSecret: clientSecret, Endpoint: provider.Endpoint(), Scopes: scopes}
	tok, err := cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		return Tokens{}, err
	}
	return tokensFromOAuth2(tok)
}

func tokensFromOAuth2(tok *oauth2.Token) (Tokens, error) {
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return Tokens{}, fmt.Errorf("token response did not include an id_token")
	}
	return Tokens{IDToken: raw, RefreshToken: tok.RefreshToken, Expiry: idTokenExpiry(raw)}, nil
}

// idTokenExpiry reads the exp claim without verifying the signature: the
// server is the security boundary that verifies the token, this is only
// used client-side to decide when the cache needs a refresh.
func idTokenExpiry(raw string) time.Time {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return time.Time{}
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(b, &claims) != nil || claims.Exp == 0 {
		return time.Time{}
	}
	return time.Unix(claims.Exp, 0)
}

func randomState() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func defaultOpenBrowser(url string) error {
	var command string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		command, args = "open", []string{url}
	case "windows":
		command, args = "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default:
		command, args = "xdg-open", []string{url}
	}
	return exec.Command(command, args...).Start()
}
