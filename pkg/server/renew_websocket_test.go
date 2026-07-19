package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

// TestRenewKeepsWebSocketFallbackConnectionOpen guards against a session
// renewal silently killing the WebSocket data-plane fallback: /v1/renew
// mints a new session ID, and the fallback peer used to be registered under
// that ID, so dropSession(old) (called unconditionally by the old renew
// implementation) closed the very connection the client keeps using without
// ever reopening it. The fix keys the fallback connection by the stable
// WireGuardPublicKey instead, which does not change across a renewal.
func TestRenewKeepsWebSocketFallbackConnectionOpen(t *testing.T) {
	_, authLine := genTestKey(t, t.TempDir(), "")
	pub, _, err := sshkey.ParsePublicString(authLine)
	if err != nil {
		t.Fatal(err)
	}
	fp := sshkey.Fingerprint(pub)
	keysDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(keysDir, "key.pub"), []byte(authLine+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{Tunnels: []TunnelConfig{{Name: "reports", Target: "x:1", VirtualPort: 1, Allow: []string{"*"}}}}
	cfg.Auth.AuthorizedKeysDir = keysDir
	cfg.Auth.SessionTTL = time.Minute
	s := New(cfg, nil)
	startTestDataPlane(t, s)

	const wgKey = "test-wireguard-public-key"
	session := s.sessions.Create(CreateParams{
		Method: "ssh", Identity: fp, Fingerprint: fp,
		WireGuardPublicKey: wgKey, TunnelIP: "100.64.0.9",
		Tunnels: []protocol.Tunnel{{Name: "reports"}}, TTL: time.Minute,
	})

	// Register a fallback WebSocket connection exactly as the /v1/wg handler
	// does: keyed by the session's WireGuardPublicKey.
	wsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := s.data.ws.WebSocket.ServeHTTP(w, r, wgKey); err != nil {
			t.Error(err)
		}
	})
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listeners unavailable: %v", err)
	}
	wsSrv := &httptest.Server{Listener: l, Config: &http.Server{Handler: wsHandler}}
	wsSrv.Start()
	defer wsSrv.Close()

	client := wstransport.NewClient("ws"+wsSrv.URL[len("http"):], wsSrv.Client(), nil)
	if _, _, err := client.Open(0); err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Renew the session over the real HTTP handler.
	ctrl := httptest.NewServer(s.Handler())
	defer ctrl.Close()
	body, _ := json.Marshal(protocol.RenewRequest{})
	req, _ := http.NewRequest(http.MethodPost, ctrl.URL+"/v1/renew", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+session.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("renew status=%d body=%s", resp.StatusCode, b)
	}

	// The fallback connection the client opened before renewal must still be
	// usable: a datagram send over it should not fail because the server
	// closed it out from under the client during renewal.
	ep, err := client.ParseEndpoint("127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Send([][]byte{make([]byte, 16)}, ep); err != nil {
		t.Fatalf("WebSocket fallback connection was closed by renewal: %v", err)
	}
}
