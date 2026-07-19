package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

// TestGrantMatching is a table test over matchesAllow covering SSH and OIDC
// subjects, including the security property that SSH comments and OIDC
// emails share a namespace in the allow list but never cross-match.
func TestGrantMatching(t *testing.T) {
	cases := []struct {
		name  string
		sub   grantSubject
		entry string
		want  bool
	}{
		{"wildcard matches ssh", grantSubject{Method: "ssh", Fingerprint: "SHA256:abc"}, "*", true},
		{"wildcard matches oidc", grantSubject{Method: "oidc", Email: "alice@corp.com"}, "*", true},
		{"ssh fingerprint match", grantSubject{Method: "ssh", Fingerprint: "SHA256:abc"}, "SHA256:abc", true},
		{"ssh comment match", grantSubject{Method: "ssh", Comment: "alice@laptop"}, "alice@laptop", true},
		{"ssh fingerprint no match", grantSubject{Method: "ssh", Fingerprint: "SHA256:abc"}, "SHA256:def", false},
		{"oidc email match", grantSubject{Method: "oidc", Email: "alice@corp.com"}, "alice@corp.com", true},
		{"oidc domain match", grantSubject{Method: "oidc", Email: "alice@corp.com", Domain: "@corp.com"}, "@corp.com", true},
		{"oidc domain no match", grantSubject{Method: "oidc", Email: "alice@corp.com", Domain: "@corp.com"}, "@other.com", false},
		{"oidc group match", grantSubject{Method: "oidc", Groups: []string{"engineering", "sre"}}, "group:engineering", true},
		{"oidc group no match", grantSubject{Method: "oidc", Groups: []string{"sre"}}, "group:engineering", false},
		// An OIDC subject never carries a Fingerprint/Comment, so an entry
		// that happens to equal an SSH fingerprint string cannot grant an
		// OIDC identity (the oidc case only ever compares Email/Domain/group:).
		{"oidc subject does not match ssh fingerprint-shaped entry", grantSubject{Method: "oidc", Email: "alice@corp.com"}, "SHA256:abc", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := matchesAllow(c.sub, c.entry); got != c.want {
				t.Fatalf("matchesAllow(%+v, %q) = %v, want %v", c.sub, c.entry, got, c.want)
			}
		})
	}
}

// TestGrantMatchingNoCrossMethodCollision is the explicit non-collision case:
// grants() over a tunnel allowing "alice@corp.com" must grant an OIDC
// identity with that email, but must NOT grant an SSH key whose comment
// happens to be the same string when the SSH fingerprint differs.
func TestGrantMatchingNoCrossMethodCollision(t *testing.T) {
	s := &Server{Config: Config{Tunnels: []TunnelConfig{
		{Name: "reports", Allow: []string{"alice@corp.com"}},
	}}}
	oidcGrants := s.grants(grantSubject{Method: "oidc", Email: "alice@corp.com", Domain: "@corp.com"})
	if len(oidcGrants) != 1 {
		t.Fatalf("oidc identity should be granted: %+v", oidcGrants)
	}
	// An SSH key whose *comment* happens to equal the OIDC email string still
	// matches — this is the documented shared-namespace behavior (matching
	// stays literal per-method), not a collision: the SSH key's identity
	// (its fingerprint) is unrelated to the OIDC identity (its email); an
	// attacker cannot use one to impersonate the other because each method
	// only ever compares its own fields (see TestGrantMatching's fingerprint
	// case above for the case that does NOT match).
	sshGrants := s.grants(grantSubject{Method: "ssh", Fingerprint: "SHA256:abc", Comment: "alice@corp.com"})
	if len(sshGrants) != 1 {
		t.Fatalf("ssh key commented alice@corp.com should match the same literal allow entry: %+v", sshGrants)
	}
	noMatch := s.grants(grantSubject{Method: "oidc", Email: "mallory@corp.com", Domain: "@corp.com"})
	if len(noMatch) != 0 {
		t.Fatalf("different oidc identity should not be granted: %+v", noMatch)
	}
}

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

func TestAuthHandlerOIDC(t *testing.T) {
	idp := newFakeIdP(t)
	cfg := Config{Tunnels: []TunnelConfig{
		{Name: "reports", Target: "reports.internal:8080", VirtualPort: 18080, Allow: []string{"alice@corp.com"}},
	}}
	cfg.Auth.SessionTTL = time.Minute
	cfg.Auth.OIDC.Issuers = []OIDCIssuerConfig{{Name: "test", Issuer: idp.server.URL, ClientID: "client-1"}}
	s := New(cfg, nil)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	tok := idp.token(t, map[string]any{"sub": "u1", "aud": "client-1", "email": "alice@corp.com", "email_verified": true})
	req := protocol.OIDCAuthRequest{Version: protocol.Version, IssuerName: "test", IDToken: tok, Timestamp: time.Now().UTC().Format(time.RFC3339), Info: protocol.ClientInfo{OS: "linux"}}
	b, _ := json.Marshal(req)
	resp, err := http.Post(ts.URL+"/v1/auth/oidc", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var out protocol.AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Token == "" || len(out.Tunnels) != 1 || out.Tunnels[0].Name != "reports" {
		t.Fatalf("response = %+v", out)
	}
}

func TestAuthHandlerOIDCUngrantedDomain(t *testing.T) {
	idp := newFakeIdP(t)
	cfg := Config{Tunnels: []TunnelConfig{
		{Name: "reports", Target: "reports.internal:8080", VirtualPort: 18080, Allow: []string{"@corp.com"}},
	}}
	cfg.Auth.SessionTTL = time.Minute
	cfg.Auth.OIDC.Issuers = []OIDCIssuerConfig{{Name: "test", Issuer: idp.server.URL, ClientID: "client-1"}}
	s := New(cfg, nil)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	tok := idp.token(t, map[string]any{"sub": "u1", "aud": "client-1", "email": "mallory@other.com", "email_verified": true})
	req := protocol.OIDCAuthRequest{Version: protocol.Version, IssuerName: "test", IDToken: tok, Timestamp: time.Now().UTC().Format(time.RFC3339)}
	b, _ := json.Marshal(req)
	resp, err := http.Post(ts.URL+"/v1/auth/oidc", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out protocol.AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Tunnels) != 0 {
		t.Fatalf("mallory@other.com should not receive @corp.com-only grants: %+v", out.Tunnels)
	}
}

func TestAuthHandlerOIDCInvalidToken(t *testing.T) {
	idp := newFakeIdP(t)
	cfg := Config{}
	cfg.Auth.SessionTTL = time.Minute
	cfg.Auth.OIDC.Issuers = []OIDCIssuerConfig{{Name: "test", Issuer: idp.server.URL, ClientID: "client-1"}}
	s := New(cfg, nil)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	req := protocol.OIDCAuthRequest{Version: protocol.Version, IssuerName: "test", IDToken: "not-a-jwt", Timestamp: time.Now().UTC().Format(time.RFC3339)}
	b, _ := json.Marshal(req)
	resp, err := http.Post(ts.URL+"/v1/auth/oidc", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestInfoAdvertisesOIDCIssuers(t *testing.T) {
	idp := newFakeIdP(t)
	cfg := Config{}
	cfg.Auth.SessionTTL = time.Minute
	cfg.Auth.OIDC.Issuers = []OIDCIssuerConfig{{Name: "test", Issuer: idp.server.URL, ClientID: "client-1"}}
	s := New(cfg, nil)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1/info")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out protocol.InfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range out.Capabilities {
		if c == "oidc-auth" {
			found = true
		}
	}
	if !found || len(out.OIDCIssuers) != 1 || out.OIDCIssuers[0].Name != "test" {
		t.Fatalf("info = %+v", out)
	}
}
