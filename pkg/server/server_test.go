package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
	"golang.org/x/crypto/ssh"
)

// genTestKey writes an ed25519 private key PEM to dir/priv and returns the
// private key path plus the OpenSSH authorized_keys line for its public key.
func genTestKey(t *testing.T, dir, comment string) (privPath, authorizedLine string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	privPath = filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := string(ssh.MarshalAuthorizedKey(sshPub))
	line = line[:len(line)-1] // trim trailing newline
	if comment != "" {
		line += " " + comment
	}
	return privPath, line
}

func newTestServer(t *testing.T, tunnels []TunnelConfig) (*Server, string, string) {
	t.Helper()
	keysDir := t.TempDir()
	privPath, authLine := genTestKey(t, t.TempDir(), "alice@laptop")
	if err := os.WriteFile(filepath.Join(keysDir, "alice.pub"), []byte(authLine+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Tunnels: tunnels}
	cfg.Auth.AuthorizedKeysDir = keysDir
	cfg.Auth.SessionTTL = time.Minute
	s := New(cfg, nil)
	return s, privPath, authLine
}

func signedAuthRequest(t *testing.T, privPath, publicKeyLine string) protocol.AuthRequest {
	t.Helper()
	n := make([]byte, 16)
	_, _ = rand.Read(n)
	r := protocol.AuthRequest{
		Version:   protocol.Version,
		PublicKey: publicKeyLine,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Nonce:     base64.RawURLEncoding.EncodeToString(n),
		Info:      protocol.ClientInfo{OS: "linux"},
	}
	p, err := protocol.SigningPayload(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Signature, err = sshkey.SignFile(privPath, p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAuthHandlerSSH(t *testing.T) {
	s, privPath, authLine := newTestServer(t, []TunnelConfig{
		{Name: "reports", Target: "reports.internal:8080", VirtualPort: 18080, Allow: []string{"alice@laptop"}},
	})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	req := signedAuthRequest(t, privPath, authLine)
	b, _ := json.Marshal(req)
	resp, err := http.Post(ts.URL+"/v1/auth", "application/json", bytes.NewReader(b))
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
	if out.Token == "" || out.SessionID == "" {
		t.Fatalf("empty session: %+v", out)
	}
	if len(out.Tunnels) != 1 || out.Tunnels[0].Name != "reports" {
		t.Fatalf("tunnels = %+v", out.Tunnels)
	}
}

func TestAuthHandlerSSHUnknownKey(t *testing.T) {
	s, _, _ := newTestServer(t, nil)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	otherPriv, otherPub := genTestKey(t, t.TempDir(), "mallory@evil")
	req := signedAuthRequest(t, otherPriv, otherPub)
	b, _ := json.Marshal(req)
	resp, err := http.Post(ts.URL+"/v1/auth", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestInfoHandler(t *testing.T) {
	s, _, _ := newTestServer(t, nil)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1/info")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	caps, _ := out["capabilities"].([]any)
	found := false
	for _, c := range caps {
		if c == "ssh-auth" {
			found = true
		}
	}
	if !found {
		t.Fatalf("capabilities missing ssh-auth: %+v", out["capabilities"])
	}
}

func TestAllowSourcePrunesStaleEntries(t *testing.T) {
	s := New(Config{}, nil)
	s.rates["198.51.100.1"] = &rateState{n: 20, since: time.Now().Add(-2 * time.Minute)}

	if !s.allowSource("198.51.100.2:12345") {
		t.Fatal("a fresh source should be allowed")
	}
	if _, ok := s.rates["198.51.100.1"]; ok {
		t.Fatal("a rate entry older than the window should have been pruned")
	}
}
