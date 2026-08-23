package api

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/internal/gui/config"
	"github.com/nmaguiar/ntwire/internal/gui/manager"
	"github.com/nmaguiar/ntwire/pkg/browseropen"
	"github.com/nmaguiar/ntwire/pkg/client"
	"github.com/nmaguiar/ntwire/pkg/protocol"
)

// fakeConnector never touches the network; every Connect call succeeds
// immediately, which is all these HTTP-layer tests need -- the manager
// package's own tests already exercise the state machine's harder paths
// (TOFU, passphrase prompts, port collisions).
type fakeConnector struct{}

func (fakeConnector) Connect(server, keyPath string, info protocol.ClientInfo, opts client.Options) (manager.Handle, error) {
	return fakeHandle{}, nil
}
func (fakeConnector) Authenticate(server, keyPath string, info protocol.ClientInfo, opts client.Options) (protocol.AuthResponse, error) {
	return protocol.AuthResponse{Tunnels: []protocol.Tunnel{{Name: "web", VirtualPort: 8080}}}, nil
}

type fakeHandle struct{}

func (fakeHandle) State() client.ConnectionState {
	return client.ConnectionState{
		Connected: true,
		Tunnels: []client.ListenerState{
			{Name: "web", LocalAddress: "127.0.0.1:8080"},
			{Name: "socks", LocalAddress: "127.0.0.1:1080", TargetHint: "socks"},
		},
	}
}
func (fakeHandle) ReplaceListener(name, host string, port int) (string, error) {
	if host == "" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("%s:%d", host, port), nil
}
func (fakeHandle) DashboardURL() string { return "http://127.0.0.1:0/?token=fake" }
func (fakeHandle) Close()               {}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	mgr, err := manager.New(fakeConnector{}, filepath.Join(dir, "gui.yaml"), filepath.Join(dir, "no-such-config.yaml"))
	if err != nil {
		t.Fatalf("manager.New() error = %v", err)
	}
	s, err := New(mgr)
	if err != nil {
		t.Fatalf("api.New() error = %v", err)
	}
	go s.Serve()
	t.Cleanup(func() { s.Close() })
	return s
}

func (s *Server) get(t *testing.T, path string) *http.Response {
	t.Helper()
	resp, err := http.Get(s.urlFor(path))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func (s *Server) do(t *testing.T, method, path string, body any) *http.Response {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, s.urlFor(path), r)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func (s *Server) urlFor(path string) string {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return fmt.Sprintf("http://%s%s%stoken=%s", s.Addr(), path, sep, s.token)
}

func decode[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	defer resp.Body.Close()
	var v T
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return v
}

func TestRequestsWithoutTokenAre404(t *testing.T) {
	s := newTestServer(t)
	resp, err := http.Get(fmt.Sprintf("http://%s/api/profiles", s.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (matching pkg/client's startWebUI convention of not confirming endpoint existence)", resp.StatusCode)
	}
}

func TestRequestsWithWrongTokenAre404(t *testing.T) {
	s := newTestServer(t)
	resp, err := http.Get(fmt.Sprintf("http://%s/api/profiles?token=wrong", s.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestProfileCRUD(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)

	s := newTestServer(t)

	resp := s.do(t, http.MethodPost, "/api/profiles", config.Profile{Name: "home-lab", Server: "https://home.example:8443"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/profiles status = %d, want 201", resp.StatusCode)
	}
	created := decode[config.Profile](t, resp)
	if created.ID == "" {
		t.Fatal("created profile has no ID")
	}

	resp = s.get(t, "/api/profiles")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/profiles status = %d, want 200", resp.StatusCode)
	}
	list := decode[[]manager.Snapshot](t, resp)
	if len(list) != 1 || list[0].Profile.Name != "home-lab" {
		t.Fatalf("GET /api/profiles = %+v, want the created profile", list)
	}

	created.Name = "renamed"
	resp = s.do(t, http.MethodPut, "/api/profiles/"+created.ID, created)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /api/profiles/{id} status = %d, want 200", resp.StatusCode)
	}

	bpDir := filepath.Join(homeDir, ".ntwire", "browser-profiles", created.ID+"-socks")
	if err := os.MkdirAll(bpDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	resp = s.do(t, http.MethodDelete, "/api/profiles/"+created.ID, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /api/profiles/{id} status = %d, want 204", resp.StatusCode)
	}

	if _, err := os.Stat(bpDir); !os.IsNotExist(err) {
		t.Errorf("browser profile %s still exists after DELETE /api/profiles/{id}", bpDir)
	}

	resp = s.get(t, "/api/profiles")
	list = decode[[]manager.Snapshot](t, resp)
	if len(list) != 0 {
		t.Fatalf("GET /api/profiles after delete = %+v, want empty", list)
	}
}

func TestProfileOIDCClientSecretIsWriteOnly(t *testing.T) {
	s := newTestServer(t)
	const secret = "not-for-api-responses"

	resp := s.do(t, http.MethodPost, "/api/profiles", map[string]string{
		"Name": "sso", "Server": "https://home.example:8443", "OIDCClientSecret": secret,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/profiles status = %d, want 201", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte(secret)) || bytes.Contains(body, []byte("OIDCClientSecret")) {
		t.Fatalf("create response leaked OIDC secret: %s", body)
	}
	var created config.Profile
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}

	resp = s.get(t, "/api/profiles")
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte(secret)) || bytes.Contains(body, []byte("OIDCClientSecret")) {
		t.Fatalf("profile response leaked OIDC secret: %s", body)
	}

	// The form omits its blank write-only input on edit. That must retain the
	// stored value rather than replacing it with an empty string.
	resp = s.do(t, http.MethodPut, "/api/profiles/"+created.ID, map[string]string{
		"Name": "renamed", "Server": "https://home.example:8443",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /api/profiles/{id} status = %d, want 200", resp.StatusCode)
	}
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte(secret)) || bytes.Contains(body, []byte("OIDCClientSecret")) {
		t.Fatalf("update response leaked OIDC secret: %s", body)
	}
	if got, ok := s.mgr.Snapshot(created.ID); !ok || got.Profile.OIDCClientSecret != secret {
		t.Fatalf("stored OIDC secret after blank update = %q, want preserved secret", got.Profile.OIDCClientSecret)
	}
}

func TestConnectDisconnectAndReplacePort(t *testing.T) {
	s := newTestServer(t)
	resp := s.do(t, http.MethodPost, "/api/profiles", config.Profile{Name: "home-lab", Server: "https://home.example:8443"})
	created := decode[config.Profile](t, resp)

	resp = s.do(t, http.MethodPost, "/api/profiles/"+created.ID+"/connect", nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("connect status = %d, want 202", resp.StatusCode)
	}

	var snap manager.Snapshot
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp = s.get(t, "/api/profiles")
		list := decode[[]manager.Snapshot](t, resp)
		if len(list) == 1 && list[0].State == manager.StateConnected {
			snap = list[0]
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if snap.State != manager.StateConnected {
		t.Fatalf("profile did not reach StateConnected in time; last state observed differs")
	}
	if snap.Connection == nil || !snap.Connection.Connected {
		t.Fatalf("connected profile has no typed connection snapshot: %+v", snap.Connection)
	}

	resp = s.do(t, http.MethodPut, "/api/profiles/"+created.ID+"/tunnels/web", map[string]int{"local_port": 9090})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("replace port status = %d, want 200", resp.StatusCode)
	}
	out := decode[map[string]string](t, resp)
	if out["local_address"] != "127.0.0.1:9090" {
		t.Errorf("local_address = %q, want 127.0.0.1:9090", out["local_address"])
	}

	resp = s.do(t, http.MethodPost, "/api/profiles/"+created.ID+"/disconnect", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("disconnect status = %d, want 204", resp.StatusCode)
	}
}

// TestOpenBrowserRejectsNonSocksAndUnknownTunnels exercises the validation
// handleOpenBrowser performs before ever touching browseropen.OpenSocks (and
// thus before it would need a real Chrome/Chromium binary, which a test
// environment may not have) -- an unconnected profile, an unknown tunnel
// name, and a tunnel that isn't a SOCKS target must all fail with 400
// without launching anything.
func TestOpenBrowserRejectsNonSocksAndUnknownTunnels(t *testing.T) {
	s := newTestServer(t)
	resp := s.do(t, http.MethodPost, "/api/profiles", config.Profile{Name: "home-lab", Server: "https://home.example:8443"})
	created := decode[config.Profile](t, resp)

	resp = s.do(t, http.MethodPost, "/api/profiles/"+created.ID+"/tunnels/socks/open-browser", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("open-browser before connect status = %d, want 400", resp.StatusCode)
	}

	resp = s.do(t, http.MethodPost, "/api/profiles/"+created.ID+"/connect", nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("connect status = %d, want 202", resp.StatusCode)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp = s.get(t, "/api/profiles")
		list := decode[[]manager.Snapshot](t, resp)
		if len(list) == 1 && list[0].State == manager.StateConnected {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	resp = s.do(t, http.MethodPost, "/api/profiles/"+created.ID+"/tunnels/does-not-exist/open-browser", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("open-browser for unknown tunnel status = %d, want 400", resp.StatusCode)
	}

	resp = s.do(t, http.MethodPost, "/api/profiles/"+created.ID+"/tunnels/web/open-browser", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("open-browser for non-SOCKS tunnel status = %d, want 400", resp.StatusCode)
	}

	// Resetting a profile that was never opened is a deterministic, Chrome-
	// independent no-op success -- CleanProfile treats a missing directory
	// as nothing to clean.
	resp = s.do(t, http.MethodPost, "/api/profiles/"+created.ID+"/tunnels/socks/reset-browser-profile", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("reset-browser-profile status = %d, want 204", resp.StatusCode)
	}
}

func TestProbeReturnsTunnelsWithoutConnecting(t *testing.T) {
	s := newTestServer(t)
	resp := s.do(t, http.MethodPost, "/api/profiles", config.Profile{Name: "home-lab", Server: "https://home.example:8443"})
	created := decode[config.Profile](t, resp)

	resp = s.do(t, http.MethodPost, "/api/profiles/"+created.ID+"/probe", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("probe status = %d, want 200", resp.StatusCode)
	}
	tunnels := decode[[]protocol.Tunnel](t, resp)
	if len(tunnels) != 1 || tunnels[0].Name != "web" {
		t.Fatalf("probe tunnels = %+v, want [{Name: web}]", tunnels)
	}

	// Probe must not have connected the profile.
	resp = s.get(t, "/api/profiles")
	list := decode[[]manager.Snapshot](t, resp)
	if len(list) != 1 || list[0].State != manager.StateIdle {
		t.Fatalf("state after probe = %+v, want StateIdle (probe must not connect)", list)
	}
}

func TestKeygenCreatesIdentity(t *testing.T) {
	s := newTestServer(t)
	path := filepath.Join(t.TempDir(), "id")
	resp := s.do(t, http.MethodPost, "/api/keygen", map[string]string{"path": path})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("keygen status = %d, want 200", resp.StatusCode)
	}
	out := decode[map[string]string](t, resp)
	if out["fingerprint"] == "" {
		t.Error("keygen response has no fingerprint")
	}
	if !strings.HasPrefix(out["public_key"], "ssh-ed25519 ") {
		t.Errorf("public_key = %q, want an ssh-ed25519 OpenSSH line", out["public_key"])
	}
}

func TestLogoutSucceedsForKnownProfile(t *testing.T) {
	s := newTestServer(t)
	resp := s.do(t, http.MethodPost, "/api/profiles", config.Profile{
		Name: "home-lab", Server: "https://home.example:8443",
		TokenCacheFile: filepath.Join(t.TempDir(), "tokens.json"),
	})
	created := decode[config.Profile](t, resp)

	resp = s.do(t, http.MethodPost, "/api/profiles/"+created.ID+"/logout", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout status = %d, want 204", resp.StatusCode)
	}
}

func TestSettingsGetAndPut(t *testing.T) {
	s := newTestServer(t)
	resp := s.do(t, http.MethodPut, "/api/settings", config.Settings{StartAtLogin: true, Notifications: true})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /api/settings status = %d, want 200", resp.StatusCode)
	}
	resp = s.get(t, "/api/settings")
	got := decode[config.Settings](t, resp)
	if !got.StartAtLogin || !got.Notifications {
		t.Errorf("GET /api/settings = %+v, want the saved settings back", got)
	}
}

// TestEventsStreamsInitialSnapshotThenUpdate checks the SSE stream both
// sends every existing profile's state immediately on connect (so a
// freshly opened settings window isn't blank until the next change) and
// then streams a live update when a profile connects.
func TestEventsStreamsInitialSnapshotThenUpdate(t *testing.T) {
	s := newTestServer(t)
	resp := s.do(t, http.MethodPost, "/api/profiles", config.Profile{Name: "home-lab", Server: "https://home.example:8443"})
	created := decode[config.Profile](t, resp)

	req, err := http.NewRequest(http.MethodGet, s.urlFor("/api/events"), nil)
	if err != nil {
		t.Fatal(err)
	}
	// A bounded client timeout, not just the loop below's deadline check,
	// keeps a hung stream from blocking readEvent's ReadString forever
	// instead of failing the test.
	eventsClient := &http.Client{Timeout: 8 * time.Second}
	eventsResp, err := eventsClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer eventsResp.Body.Close()
	if ct := eventsResp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}

	reader := bufio.NewReader(eventsResp.Body)
	readEvent := func() manager.Update {
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("reading SSE stream: %v", err)
			}
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			var u manager.Update
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &u); err != nil {
				t.Fatalf("unmarshal SSE event: %v", err)
			}
			return u
		}
	}

	initial := readEvent()
	if initial.ProfileID != created.ID || initial.Snapshot.State != manager.StateIdle {
		t.Fatalf("initial SSE event = %+v, want idle snapshot for %s", initial, created.ID)
	}

	if resp := s.do(t, http.MethodPost, "/api/profiles/"+created.ID+"/connect", nil); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("connect status = %d, want 202", resp.StatusCode)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		u := readEvent()
		if u.ProfileID == created.ID && u.Snapshot.State == manager.StateConnected {
			return
		}
	}
	t.Fatal("did not observe a StateConnected event on the SSE stream in time")
}

func TestBrowserProfilesListAndClean(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)

	s := newTestServer(t)

	// 1. List against missing profiles dir -> returns empty list []
	resp := s.get(t, "/api/browser-profiles")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/browser-profiles status = %d, want 200", resp.StatusCode)
	}
	initialList := decode[[]browseropen.ProfileEntry](t, resp)
	if len(initialList) != 0 {
		t.Fatalf("initial GET /api/browser-profiles = %+v, want empty slice", initialList)
	}

	// 2. Create locked + unlocked dirs
	base := filepath.Join(homeDir, ".ntwire", "browser-profiles")
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	unlockedDir := filepath.Join(base, "unlocked-prof")
	if err := os.MkdirAll(unlockedDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	lockedDir := filepath.Join(base, "locked-prof")
	if err := os.MkdirAll(lockedDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	lock := filepath.Join(lockedDir, "SingletonLock")
	if err := os.Symlink("target", lock); err != nil {
		if err := os.WriteFile(lock, []byte("123"), 0o600); err != nil {
			t.Fatalf("WriteFile() lock error = %v", err)
		}
	}

	// List with locked + unlocked dir
	resp = s.get(t, "/api/browser-profiles")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/browser-profiles status = %d, want 200", resp.StatusCode)
	}
	entries := decode[[]browseropen.ProfileEntry](t, resp)
	if len(entries) != 2 {
		t.Fatalf("GET /api/browser-profiles returned %d entries, want 2", len(entries))
	}
	if entries[0].Key != "locked-prof" || !entries[0].InUse {
		t.Errorf("entries[0] = %+v, want Key: locked-prof, InUse: true", entries[0])
	}
	if entries[1].Key != "unlocked-prof" || entries[1].InUse {
		t.Errorf("entries[1] = %+v, want Key: unlocked-prof, InUse: false", entries[1])
	}

	// 3. Clean of nonexistent key is a no-op (no error in errors map)
	resp = s.do(t, http.MethodPost, "/api/browser-profiles/clean", map[string]any{
		"keys": []string{"nonexistent-profile"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/browser-profiles/clean status = %d, want 200", resp.StatusCode)
	}
	cleanResult := decode[map[string]map[string]string](t, resp)
	if len(cleanResult["errors"]) != 0 {
		t.Errorf("clean of nonexistent profile returned errors = %+v, want empty", cleanResult["errors"])
	}

	// 4. Clean of locked key comes back in errors map without deleting it, while unlocked key is deleted
	resp = s.do(t, http.MethodPost, "/api/browser-profiles/clean", map[string]any{
		"keys": []string{"locked-prof", "unlocked-prof"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/browser-profiles/clean status = %d, want 200", resp.StatusCode)
	}
	cleanResult = decode[map[string]map[string]string](t, resp)
	if errStr, ok := cleanResult["errors"]["locked-prof"]; !ok || !strings.Contains(errStr, "in use") {
		t.Errorf("cleanResult errors for locked-prof = %q, want 'in use' error", errStr)
	}
	if _, ok := cleanResult["errors"]["unlocked-prof"]; ok {
		t.Errorf("cleanResult errors contained unlocked-prof: %v", cleanResult["errors"])
	}

	if _, err := os.Stat(unlockedDir); !os.IsNotExist(err) {
		t.Errorf("unlockedDir still exists on disk, stat err = %v", err)
	}
	if _, err := os.Stat(lockedDir); err != nil {
		t.Errorf("lockedDir should still exist on disk, stat err = %v", err)
	}
}
