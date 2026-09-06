package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

// withComment replaces (or adds) the comment on an authorized_keys line,
// leaving the key blob itself untouched -- exactly what a client can do to the
// public_key field of its own signed authentication request.
func withComment(line, comment string) string {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return line
	}
	out := fields[0] + " " + fields[1]
	if comment != "" {
		out += " " + comment
	}
	return out
}

// serverWithKey builds a server whose authorized-key directory holds one key,
// carrying fileComment, and returns the private key path and the matching
// authorized_keys line.
func serverWithKey(t *testing.T, fileComment string, tunnels []TunnelConfig) (*Server, string, string) {
	t.Helper()
	keysDir := t.TempDir()
	privPath, authLine := genTestKey(t, t.TempDir(), fileComment)
	if err := os.WriteFile(filepath.Join(keysDir, "key.pub"), []byte(authLine+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Tunnels: tunnels}
	cfg.Auth.AuthorizedKeysDir = keysDir
	cfg.Auth.SessionTTL = time.Minute
	return New(cfg, nil), privPath, authLine
}

func postAuth(t *testing.T, url string, req protocol.AuthRequest) (int, protocol.AuthResponse) {
	t.Helper()
	b, _ := json.Marshal(req)
	resp, err := http.Post(url+"/v1/auth", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out protocol.AuthResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestSSHCommentGrantIgnoresRequestComment is the regression test for the SSH
// grant-escalation finding: the comment used for grant matching must come from
// the server's own authorized_keys entry, never from the client's request.
// Otherwise the holder of any authorized key can claim any comment-shaped
// allow entry -- including one an operator wrote as an OIDC email, which
// docs/PROTOCOL.md promises is impossible.
func TestSSHCommentGrantIgnoresRequestComment(t *testing.T) {
	s, privPath, authLine := serverWithKey(t, "attacker@laptop", []TunnelConfig{
		{Name: "payroll", Target: "payroll.internal:8080", VirtualPort: 18080, Allow: []string{"victim@corp.com"}},
	})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	req := signedAuthRequest(t, privPath, withComment(authLine, "victim@corp.com"))
	status, out := postAuth(t, ts.URL, req)
	if status != http.StatusOK {
		t.Fatalf("an authorized key should still authenticate: status = %d", status)
	}
	if len(out.Tunnels) != 0 {
		t.Fatalf("a request-supplied comment must not match an allow entry, got tunnels %+v", out.Tunnels)
	}
}

// TestSSHCommentGrantUsesAuthorizedKeysComment is the positive half: a comment
// recorded on the key file itself does grant, so the fix narrows the source of
// the comment without removing the documented feature.
func TestSSHCommentGrantUsesAuthorizedKeysComment(t *testing.T) {
	s, privPath, authLine := serverWithKey(t, "ops@corp.com", []TunnelConfig{
		{Name: "reports", Target: "reports.internal:8080", VirtualPort: 18080, Allow: []string{"ops@corp.com"}},
	})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	// The client sends no comment at all -- as the reference client does.
	req := signedAuthRequest(t, privPath, withComment(authLine, ""))
	status, out := postAuth(t, ts.URL, req)
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if len(out.Tunnels) != 1 || out.Tunnels[0].Name != "reports" {
		t.Fatalf("a comment on the key file should grant, got %+v", out.Tunnels)
	}
}

// TestReloadKeepsCommentGrantedSession checks that Reload re-evaluates an SSH
// session with the same comment source auth() used, instead of dropping a
// comment-granted session on every reload for lack of a comment.
func TestReloadKeepsCommentGrantedSession(t *testing.T) {
	tunnels := []TunnelConfig{
		{Name: "reports", Target: "reports.internal:8080", VirtualPort: 18080, Allow: []string{"ops@corp.com"}},
	}
	s, privPath, authLine := serverWithKey(t, "ops@corp.com", tunnels)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	status, out := postAuth(t, ts.URL, signedAuthRequest(t, privPath, authLine))
	if status != http.StatusOK || out.Token == "" {
		t.Fatalf("setup: status = %d, token = %q", status, out.Token)
	}

	next := s.Config
	next.Tunnels = tunnels
	s.Reload(next)

	if _, ok := s.sessions.Get(out.Token); !ok {
		t.Fatal("a comment-granted session should survive a reload that changes nothing")
	}
}

// TestAuthDoesNotConsumeNonceOnBadSignature is the regression test for the
// pre-authentication nonce-cache finding: an unauthenticated request must not
// be able to burn a nonce slot. The same nonce must still work once presented
// with a valid signature.
func TestAuthDoesNotConsumeNonceOnBadSignature(t *testing.T) {
	s, privPath, authLine := serverWithKey(t, "alice@laptop", []TunnelConfig{
		{Name: "reports", Target: "reports.internal:8080", VirtualPort: 18080, Allow: []string{"*"}},
	})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	good := signedAuthRequest(t, privPath, authLine)

	forged := good
	forged.Signature = signedAuthRequest(t, privPath, withComment(authLine, "other")).Signature
	if status, _ := postAuth(t, ts.URL, forged); status != http.StatusUnauthorized {
		t.Fatalf("a forged signature should be rejected: status = %d", status)
	}

	if status, out := postAuth(t, ts.URL, good); status != http.StatusOK || out.Token == "" {
		t.Fatalf("the nonce must survive a rejected request: status = %d, token = %q", status, out.Token)
	}
}

// TestAuthRejectsReplayedNonce keeps the replay protection itself covered, so
// the reordering above cannot silently disable it.
func TestAuthRejectsReplayedNonce(t *testing.T) {
	s, privPath, authLine := serverWithKey(t, "alice@laptop", []TunnelConfig{
		{Name: "reports", Target: "reports.internal:8080", VirtualPort: 18080, Allow: []string{"*"}},
	})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	req := signedAuthRequest(t, privPath, authLine)
	if status, _ := postAuth(t, ts.URL, req); status != http.StatusOK {
		t.Fatalf("first use should succeed: status = %d", status)
	}
	if status, _ := postAuth(t, ts.URL, req); status != http.StatusUnauthorized {
		t.Fatalf("a replayed nonce should be rejected: status = %d", status)
	}
}
