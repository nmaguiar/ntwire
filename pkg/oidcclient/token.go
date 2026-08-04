package oidcclient

import (
	"context"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"golang.org/x/oauth2"
)

// ForIssuerOptions controls how TokensForIssuer obtains a fresh token when
// the cache is empty or refresh fails.
type ForIssuerOptions struct {
	NoBrowser    bool
	OpenBrowser  func(url string) error
	DevicePrompt func(*oauth2.DeviceAuthResponse)
	// ClientSecret is local client configuration. It is never supplied by the
	// ntwire server's public /v1/info response.
	ClientSecret string
}

// TokensForIssuer returns a usable ID token for (serverURL, issuer),
// preferring a silent refresh from the cache and falling back to full
// interactive login (which also refreshes the cache) on any cache miss or
// refresh failure.
func TokensForIssuer(ctx context.Context, cache *Cache, serverURL string, issuer protocol.OIDCIssuerInfo, opts ForIssuerOptions) (Tokens, error) {
	if e, ok := cache.Get(serverURL, issuer.Name); ok && e.RefreshToken != "" {
		if tok, err := Refresh(ctx, issuer.Issuer, issuer.ClientID, opts.ClientSecret, e.RefreshToken, issuer.Scopes); err == nil {
			if tok.RefreshToken == "" {
				tok.RefreshToken = e.RefreshToken
			}
			_ = cache.Put(serverURL, issuer.Name, CacheEntry{RefreshToken: tok.RefreshToken, IDToken: tok.IDToken, Expiry: tok.Expiry})
			return tok, nil
		}
	}
	tok, err := Login(ctx, issuer.Issuer, LoginOptions{
		ClientID: issuer.ClientID, ClientSecret: opts.ClientSecret, Scopes: issuer.Scopes, NoBrowser: opts.NoBrowser,
		OpenBrowser: opts.OpenBrowser, DevicePrompt: opts.DevicePrompt,
	})
	if err != nil {
		return Tokens{}, err
	}
	if err := cache.Put(serverURL, issuer.Name, CacheEntry{RefreshToken: tok.RefreshToken, IDToken: tok.IDToken, Expiry: tok.Expiry}); err != nil {
		return Tokens{}, err
	}
	return tok, nil
}
