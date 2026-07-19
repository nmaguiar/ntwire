package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/server"
	"golang.org/x/crypto/ssh"
)

// fakeIdP serves discovery, JWKS, and an RFC 8628 device flow, so tests can
// drive an SSO login end to end (through the real /v1/auth/oidc handler)
// without a browser: the device grant hands back a signed ID token on the
// first poll.
type fakeIdP struct {
	server *httptest.Server
	signer jose.Signer
	jwk    jose.JSONWebKey
	email  string
}

func newFakeIdP(t *testing.T, email string) *fakeIdP {
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
	f := &fakeIdP{signer: signer, jwk: jwk, email: email}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                        f.server.URL,
			"authorization_endpoint":        f.server.URL + "/authorize",
			"token_endpoint":                f.server.URL + "/token",
			"device_authorization_endpoint": f.server.URL + "/device",
			"jwks_uri":                      f.server.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{f.jwk}})
	})
	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": "devcode-1", "user_code": "ABCD-EFGH",
			"verification_uri": f.server.URL + "/device/verify", "expires_in": 600, "interval": 1,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := map[string]any{
			"iss": f.server.URL, "sub": "user-1", "aud": "client-1",
			"email": f.email, "email_verified": true,
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		}
		tok, err := jwt.Signed(f.signer).Claims(claims).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access-1", "token_type": "Bearer", "expires_in": 3600,
			"refresh_token": "refresh-1", "id_token": tok,
		})
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

// genTestSSHKey writes an ed25519 private key and returns its path, the
// OpenSSH authorized_keys line for the matching public key, and its
// fingerprint. The CLI's SSH auth request carries only the bare public key
// (sshkey.PublicFromPrivate never attaches a comment), so grants keyed on
// the fingerprint are what the real client flow actually exercises.
func genTestSSHKey(t *testing.T, comment string) (privPath, authorizedLine, fingerprint string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	privPath = filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := string(ssh.MarshalAuthorizedKey(sshPub))
	line = line[:len(line)-1] + " " + comment
	return privPath, line, ssh.FingerprintSHA256(sshPub)
}

func TestAuthenticateDefaultsToSSOWhenNoKey(t *testing.T) {
	idp := newFakeIdP(t, "alice@corp.com")
	cfg := server.Config{Tunnels: []server.TunnelConfig{
		{Name: "reports", Target: "x:1", VirtualPort: 1, Allow: []string{"alice@corp.com"}},
	}}
	cfg.Auth.SessionTTL = time.Minute
	cfg.Auth.OIDC.Issuers = []server.OIDCIssuerConfig{{Name: "test", Issuer: idp.server.URL, ClientID: "client-1"}}
	s := server.New(cfg, nil)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	cachePath := filepath.Join(t.TempDir(), "tokens.json")
	r, err := AuthenticateWithOptions(ts.URL, "", protocol.ClientInfo{OS: "linux"}, Options{NoBrowser: true, TokenCacheFile: cachePath})
	if err != nil {
		t.Fatalf("AuthenticateWithOptions: %v", err)
	}
	if len(r.Tunnels) != 1 || r.Tunnels[0].Name != "reports" {
		t.Fatalf("tunnels = %+v", r.Tunnels)
	}
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("expected token cache to be written: %v", err)
	}
}

func TestAuthenticatePrefersSSHKeyOverSSO(t *testing.T) {
	idp := newFakeIdP(t, "alice@corp.com")
	keyDir := t.TempDir()
	privPath, authLine, fp := genTestSSHKey(t, "alice@laptop")
	if err := os.WriteFile(filepath.Join(keyDir, "alice.pub"), []byte(authLine+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := server.Config{Tunnels: []server.TunnelConfig{
		{Name: "ssh-only", Target: "x:1", VirtualPort: 1, Allow: []string{fp}},
		{Name: "oidc-only", Target: "x:2", VirtualPort: 2, Allow: []string{"alice@corp.com"}},
	}}
	cfg.Auth.AuthorizedKeysDir = keyDir
	cfg.Auth.SessionTTL = time.Minute
	cfg.Auth.OIDC.Issuers = []server.OIDCIssuerConfig{{Name: "test", Issuer: idp.server.URL, ClientID: "client-1"}}
	s := server.New(cfg, nil)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	r, err := AuthenticateWithOptions(ts.URL, privPath, protocol.ClientInfo{OS: "linux"}, Options{})
	if err != nil {
		t.Fatalf("AuthenticateWithOptions: %v", err)
	}
	if len(r.Tunnels) != 1 || r.Tunnels[0].Name != "ssh-only" {
		t.Fatalf("expected the ssh key path to be preferred and granted only ssh-only: %+v", r.Tunnels)
	}
}

func TestAuthenticateExplicitSSOOverridesAvailableKey(t *testing.T) {
	idp := newFakeIdP(t, "alice@corp.com")
	keyDir := t.TempDir()
	privPath, authLine, fp := genTestSSHKey(t, "alice@laptop")
	if err := os.WriteFile(filepath.Join(keyDir, "alice.pub"), []byte(authLine+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := server.Config{Tunnels: []server.TunnelConfig{
		{Name: "ssh-only", Target: "x:1", VirtualPort: 1, Allow: []string{fp}},
		{Name: "oidc-only", Target: "x:2", VirtualPort: 2, Allow: []string{"alice@corp.com"}},
	}}
	cfg.Auth.AuthorizedKeysDir = keyDir
	cfg.Auth.SessionTTL = time.Minute
	cfg.Auth.OIDC.Issuers = []server.OIDCIssuerConfig{{Name: "test", Issuer: idp.server.URL, ClientID: "client-1"}}
	s := server.New(cfg, nil)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	cachePath := filepath.Join(t.TempDir(), "tokens.json")
	r, err := AuthenticateWithOptions(ts.URL, privPath, protocol.ClientInfo{OS: "linux"}, Options{SSO: true, NoBrowser: true, TokenCacheFile: cachePath})
	if err != nil {
		t.Fatalf("AuthenticateWithOptions: %v", err)
	}
	if len(r.Tunnels) != 1 || r.Tunnels[0].Name != "oidc-only" {
		t.Fatalf("expected --sso to override the available key and be granted only oidc-only: %+v", r.Tunnels)
	}
}

func TestLogoutClearsCache(t *testing.T) {
	idp := newFakeIdP(t, "alice@corp.com")
	cfg := server.Config{Tunnels: []server.TunnelConfig{{Name: "reports", Target: "x:1", VirtualPort: 1, Allow: []string{"alice@corp.com"}}}}
	cfg.Auth.SessionTTL = time.Minute
	cfg.Auth.OIDC.Issuers = []server.OIDCIssuerConfig{{Name: "test", Issuer: idp.server.URL, ClientID: "client-1"}}
	s := server.New(cfg, nil)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	cachePath := filepath.Join(t.TempDir(), "tokens.json")
	if _, err := AuthenticateWithOptions(ts.URL, "", protocol.ClientInfo{}, Options{NoBrowser: true, TokenCacheFile: cachePath}); err != nil {
		t.Fatalf("AuthenticateWithOptions: %v", err)
	}
	b, err := os.ReadFile(cachePath)
	if err != nil || string(b) == "{}" {
		t.Fatalf("expected a populated cache before logout: %v %s", err, b)
	}
	if err := Logout(cachePath, ts.URL); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	b, err = os.ReadFile(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	var entries map[string]any
	if err := json.Unmarshal(b, &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected logout to clear the cache, got %v", entries)
	}
}
