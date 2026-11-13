package oidcauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// fakeIdP is a minimal OIDC provider backed by a generated RSA key: it serves
// discovery + JWKS and mints signed test ID tokens.
type fakeIdP struct {
	server *httptest.Server
	signer jose.Signer
	jwk    jose.JSONWebKey
}

func newFakeIdP(t *testing.T) *fakeIdP {
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
	f := &fakeIdP{signer: signer, jwk: jwk}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 f.server.URL,
			"authorization_endpoint": f.server.URL + "/auth",
			"token_endpoint":         f.server.URL + "/token",
			"jwks_uri":               f.server.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{f.jwk}})
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeIdP) token(t *testing.T, claims map[string]any) string {
	t.Helper()
	if claims["iss"] == nil {
		claims["iss"] = f.server.URL
	}
	if claims["iat"] == nil {
		claims["iat"] = time.Now().Unix()
	}
	if claims["exp"] == nil {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	tok, err := jwt.Signed(f.signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestVerifyValid(t *testing.T) {
	idp := newFakeIdP(t)
	v := NewVerifiers([]IssuerConfig{{Name: "test", Issuer: idp.server.URL, ClientID: "client-1", RequireVerifiedEmail: true}}, nil)
	tok := idp.token(t, map[string]any{"sub": "user-1", "aud": "client-1", "email": "alice@corp.com", "email_verified": true})
	id, err := v.Verify(context.Background(), "test", tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if id.Email != "alice@corp.com" || id.Domain != "@corp.com" || id.Subject != "user-1" || id.IssuerName != "test" {
		t.Fatalf("identity = %+v", id)
	}
}

func TestVerifyWrongAudience(t *testing.T) {
	idp := newFakeIdP(t)
	v := NewVerifiers([]IssuerConfig{{Name: "test", Issuer: idp.server.URL, ClientID: "client-1"}}, nil)
	tok := idp.token(t, map[string]any{"sub": "user-1", "aud": "someone-else", "email": "alice@corp.com", "email_verified": true})
	if _, err := v.Verify(context.Background(), "test", tok); err == nil {
		t.Fatal("expected audience mismatch to be rejected")
	}
}

func TestVerifyExpired(t *testing.T) {
	idp := newFakeIdP(t)
	v := NewVerifiers([]IssuerConfig{{Name: "test", Issuer: idp.server.URL, ClientID: "client-1"}}, nil)
	tok := idp.token(t, map[string]any{
		"sub": "user-1", "aud": "client-1", "email": "alice@corp.com", "email_verified": true,
		"iat": time.Now().Add(-2 * time.Hour).Unix(), "exp": time.Now().Add(-time.Hour).Unix(),
	})
	if _, err := v.Verify(context.Background(), "test", tok); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestVerifyUnverifiedEmailRejected(t *testing.T) {
	idp := newFakeIdP(t)
	v := NewVerifiers([]IssuerConfig{{Name: "test", Issuer: idp.server.URL, ClientID: "client-1", RequireVerifiedEmail: true}}, nil)
	tok := idp.token(t, map[string]any{"sub": "user-1", "aud": "client-1", "email": "alice@corp.com", "email_verified": false})
	if _, err := v.Verify(context.Background(), "test", tok); err == nil {
		t.Fatal("expected unverified email to be rejected")
	}
}

func TestVerifyUnverifiedEmailAllowedWhenNotRequired(t *testing.T) {
	idp := newFakeIdP(t)
	v := NewVerifiers([]IssuerConfig{{Name: "test", Issuer: idp.server.URL, ClientID: "client-1", RequireVerifiedEmail: false}}, nil)
	tok := idp.token(t, map[string]any{"sub": "user-1", "aud": "client-1", "email": "alice@corp.com", "email_verified": false})
	if _, err := v.Verify(context.Background(), "test", tok); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyGroupsClaim(t *testing.T) {
	idp := newFakeIdP(t)
	v := NewVerifiers([]IssuerConfig{{Name: "test", Issuer: idp.server.URL, ClientID: "client-1", GroupsClaim: "groups"}}, nil)
	tok := idp.token(t, map[string]any{
		"sub": "user-1", "aud": "client-1", "email": "alice@corp.com", "email_verified": true,
		"groups": []string{"engineering", "sre"},
	})
	id, err := v.Verify(context.Background(), "test", tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(id.Groups) != 2 || id.Groups[0] != "engineering" || id.Groups[1] != "sre" {
		t.Fatalf("groups = %+v", id.Groups)
	}
}

func TestVerifyUnknownIssuer(t *testing.T) {
	v := NewVerifiers(nil, nil)
	if _, err := v.Verify(context.Background(), "nope", "x"); err == nil {
		t.Fatal("expected unknown issuer error")
	}
}

func TestVerifyMissingSubject(t *testing.T) {
	idp := newFakeIdP(t)
	v := NewVerifiers([]IssuerConfig{{Name: "test", Issuer: idp.server.URL, ClientID: "client-1", RequireVerifiedEmail: true}}, nil)
	for _, subject := range []any{nil, ""} {
		claims := map[string]any{"aud": "client-1", "email": "alice@corp.com", "email_verified": true}
		if subject != nil {
			claims["sub"] = subject
		}
		if _, err := v.Verify(context.Background(), "test", idp.token(t, claims)); err == nil {
			t.Fatal("accepted token without a stable subject")
		}
	}
}

func TestVerifyGoogleIssuerQuotaIdentity(t *testing.T) {
	idp := newFakeIdP(t)
	const issuer = "https://accounts.google.com"
	// Use a real signature verifier and local JWKS without external discovery.
	cfg := IssuerConfig{Name: "google", Issuer: issuer, ClientID: "client-1", RequireVerifiedEmail: true}
	verifier := oidc.NewVerifier(issuer, oidc.NewRemoteKeySet(context.Background(), idp.server.URL+"/jwks"), &oidc.Config{ClientID: cfg.ClientID})
	v := &Verifiers{issuers: map[string]*issuerEntry{"google": {cfg: cfg, verifier: verifier}}}
	for _, claim := range []string{issuer, "accounts.google.com"} {
		tok := idp.token(t, map[string]any{"iss": claim, "sub": "user-1", "aud": "client-1", "email": "alice@corp.com", "email_verified": true})
		id, err := v.Verify(context.Background(), "google", tok)
		if err != nil {
			t.Fatal(err)
		}
		if id.Issuer != issuer || id.Subject != "user-1" {
			t.Fatalf("quota identity for %q: %+v", claim, id)
		}
	}
}
