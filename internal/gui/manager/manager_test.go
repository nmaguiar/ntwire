package manager

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/internal/gui/config"
	"github.com/nmaguiar/ntwire/pkg/client"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
	"golang.org/x/crypto/ssh"
)

func newTestManager(t *testing.T, connector Connector) (*Manager, string) {
	t.Helper()
	dir := t.TempDir()
	guiPath := filepath.Join(dir, "gui.yaml")
	// Point cliConfigPath at a nonexistent file so New's one-time import is
	// a no-op and tests don't depend on any real ~/.ntwire/config.yaml.
	m, err := New(connector, guiPath, filepath.Join(dir, "no-such-config.yaml"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return m, guiPath
}

func waitForState(t *testing.T, m *Manager, id string, want State, timeout time.Duration) Snapshot {
	t.Helper()
	updates, unsubscribe := m.Subscribe()
	defer unsubscribe()

	if snap, ok := m.Snapshot(id); ok && snap.State == want {
		return snap
	}
	deadline := time.After(timeout)
	for {
		select {
		case u := <-updates:
			if u.ProfileID == id && u.Snapshot.State == want {
				return u.Snapshot
			}
		case <-deadline:
			snap, _ := m.Snapshot(id)
			t.Fatalf("timed out waiting for profile %q to reach state %q; last snapshot: %+v", id, want, snap)
		}
	}
}

func TestAddProfilePersistsToDisk(t *testing.T) {
	m, guiPath := newTestManager(t, &fakeConnector{})
	p, err := m.AddProfile(config.Profile{Name: "home-lab", Server: "https://home.example:8443"})
	if err != nil {
		t.Fatalf("AddProfile() error = %v", err)
	}
	if p.ID == "" {
		t.Fatal("AddProfile() did not assign an ID")
	}

	cfg, err := config.Load(guiPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.Profiles) != 1 || cfg.Profiles[0].Name != "home-lab" {
		t.Fatalf("persisted profiles = %+v, want the added profile", cfg.Profiles)
	}
}

func TestConnectSucceedsAndSnapshotReportsStatus(t *testing.T) {
	fc := &fakeConnector{connectFunc: func(server, keyPath string, opts client.Options) (Handle, error) {
		return &fakeHandle{status: client.WebStatus{Connected: true, Server: server}}, nil
	}}
	m, _ := newTestManager(t, fc)
	p, err := m.AddProfile(config.Profile{Name: "home-lab", Server: "https://home.example:8443"})
	if err != nil {
		t.Fatal(err)
	}

	if err := m.Connect(p.ID); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	snap := waitForState(t, m, p.ID, StateConnected, 5*time.Second)
	if snap.Status == nil || !snap.Status.Connected {
		t.Fatalf("Snapshot().Status = %+v, want Connected=true", snap.Status)
	}
	if fc.callCount() != 1 {
		t.Errorf("connector called %d times, want 1", fc.callCount())
	}
}

func TestConnectRefusesWhileAlreadyConnecting(t *testing.T) {
	block := make(chan struct{})
	fc := &fakeConnector{connectFunc: func(server, keyPath string, opts client.Options) (Handle, error) {
		<-block
		return &fakeHandle{}, nil
	}}
	m, _ := newTestManager(t, fc)
	p, _ := m.AddProfile(config.Profile{Name: "home-lab", Server: "https://home.example:8443"})

	if err := m.Connect(p.ID); err != nil {
		t.Fatal(err)
	}
	waitForState(t, m, p.ID, StateConnecting, 2*time.Second)
	if err := m.Connect(p.ID); err == nil {
		t.Fatal("Connect() while already connecting = nil error, want an error")
	}
	close(block)
	waitForState(t, m, p.ID, StateConnected, 2*time.Second)
}

func TestConnectWithUnknownCertificateThenTrustSucceeds(t *testing.T) {
	dir := t.TempDir()
	known := filepath.Join(dir, "known_servers")
	first := true
	fc := &fakeConnector{connectFunc: func(server, keyPath string, opts client.Options) (Handle, error) {
		if first {
			first = false
			return nil, &client.UnknownCertificateError{Host: "home.example:8443", Fingerprint: "SHA256:abc"}
		}
		return &fakeHandle{}, nil
	}}
	m, _ := newTestManager(t, fc)
	p, _ := m.AddProfile(config.Profile{Name: "home-lab", Server: "https://home.example:8443", KnownServersFile: known})

	if err := m.Connect(p.ID); err != nil {
		t.Fatal(err)
	}
	snap := waitForState(t, m, p.ID, StateAwaitingTrust, 5*time.Second)
	if snap.Prompt == nil || snap.Prompt.Kind != PromptTrust || snap.Prompt.Host != "home.example:8443" {
		t.Fatalf("Prompt = %+v, want a trust prompt for home.example:8443", snap.Prompt)
	}

	if err := m.AnswerTrust(p.ID, true); err != nil {
		t.Fatalf("AnswerTrust() error = %v", err)
	}
	waitForState(t, m, p.ID, StateConnected, 5*time.Second)
	if _, err := os.Stat(known); err != nil {
		t.Errorf("known_servers file not written: %v", err)
	}
	if fc.callCount() != 2 {
		t.Errorf("connector called %d times, want 2 (initial + retry after trust)", fc.callCount())
	}
}

func TestConnectWithUnknownCertificateThenRejectFails(t *testing.T) {
	fc := &fakeConnector{connectFunc: func(server, keyPath string, opts client.Options) (Handle, error) {
		return nil, &client.UnknownCertificateError{Host: "home.example:8443", Fingerprint: "SHA256:abc"}
	}}
	m, _ := newTestManager(t, fc)
	p, _ := m.AddProfile(config.Profile{Name: "home-lab", Server: "https://home.example:8443", KnownServersFile: filepath.Join(t.TempDir(), "known_servers")})

	if err := m.Connect(p.ID); err != nil {
		t.Fatal(err)
	}
	waitForState(t, m, p.ID, StateAwaitingTrust, 5*time.Second)
	if err := m.AnswerTrust(p.ID, false); err != nil {
		t.Fatalf("AnswerTrust() error = %v", err)
	}
	snap := waitForState(t, m, p.ID, StateFailed, 5*time.Second)
	if snap.Err == "" {
		t.Error("Snapshot().Err is empty after a rejected trust prompt, want an explanation")
	}
	if fc.callCount() != 1 {
		t.Errorf("connector called %d times, want 1 (no retry after rejection)", fc.callCount())
	}
}

func TestConnectWithEncryptedKeyPromptsForPassphrase(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id")
	writeRealEncryptedKey(t, keyPath, "s3cret")

	var gotPassphrase string
	fc := &fakeConnector{connectFunc: func(server, keyPath string, opts client.Options) (Handle, error) {
		gotPassphrase = opts.KeyPassphrase
		return &fakeHandle{}, nil
	}}
	m, _ := newTestManager(t, fc)
	p, _ := m.AddProfile(config.Profile{Name: "home-lab", Server: "https://home.example:8443", IdentityFile: keyPath})

	if err := m.Connect(p.ID); err != nil {
		t.Fatal(err)
	}
	snap := waitForState(t, m, p.ID, StateAwaitingPassphrase, 5*time.Second)
	if snap.Prompt == nil || snap.Prompt.Kind != PromptPassphrase || snap.Prompt.KeyPath != keyPath {
		t.Fatalf("Prompt = %+v, want a passphrase prompt for %q", snap.Prompt, keyPath)
	}

	if err := m.AnswerPassphrase(p.ID, "s3cret", false); err != nil {
		t.Fatalf("AnswerPassphrase() error = %v", err)
	}
	waitForState(t, m, p.ID, StateConnected, 5*time.Second)
	if gotPassphrase != "s3cret" {
		t.Errorf("client.Options.KeyPassphrase = %q, want %q", gotPassphrase, "s3cret")
	}
}

func TestConnectWithEncryptedKeyCancelFails(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id")
	writeRealEncryptedKey(t, keyPath, "s3cret")

	m, _ := newTestManager(t, &fakeConnector{})
	p, _ := m.AddProfile(config.Profile{Name: "home-lab", Server: "https://home.example:8443", IdentityFile: keyPath})

	if err := m.Connect(p.ID); err != nil {
		t.Fatal(err)
	}
	waitForState(t, m, p.ID, StateAwaitingPassphrase, 5*time.Second)
	if err := m.AnswerPassphrase(p.ID, "", true); err != nil {
		t.Fatalf("AnswerPassphrase() error = %v", err)
	}
	waitForState(t, m, p.ID, StateFailed, 5*time.Second)
}

func TestPortCollisionRejectsSecondProfileWithoutCallingConnector(t *testing.T) {
	fc := &fakeConnector{}
	m, _ := newTestManager(t, fc)
	a, _ := m.AddProfile(config.Profile{Name: "a", Server: "https://a.example:8443", Ports: map[string]int{"web": 8080}})
	b, _ := m.AddProfile(config.Profile{Name: "b", Server: "https://b.example:8443", Ports: map[string]int{"web": 8080}})

	if err := m.Connect(a.ID); err != nil {
		t.Fatal(err)
	}
	waitForState(t, m, a.ID, StateConnected, 5*time.Second)

	if err := m.Connect(b.ID); err != nil {
		t.Fatal(err)
	}
	snap := waitForState(t, m, b.ID, StateFailed, 5*time.Second)
	if snap.Err == "" {
		t.Error("Snapshot().Err is empty after a port collision, want an explanation")
	}
	if fc.callCount() != 1 {
		t.Errorf("connector called %d times, want 1 (profile b must never reach the connector)", fc.callCount())
	}
}

// TestPortCollisionRejectsSecondProfileOnReconciledImplicitTunnel checks the
// fix for a gap the explicit-Ports-only guard above can't see: neither
// profile here configures an explicit local port at all (both rely purely
// on whatever the server suggests), so reservePorts has nothing to compare
// before authenticating. Once profile a actually connects,
// reconcileAllPortReservations must still record the real address its
// tunnel bound -- for every tunnel, not only ones tracked from an explicit
// Ports entry -- so that profile b's reservePorts check (which runs before
// b's own connector call) can catch the same real address and reject it.
func TestPortCollisionRejectsSecondProfileOnReconciledImplicitTunnel(t *testing.T) {
	fc := &fakeConnector{connectFunc: func(server, keyPath string, opts client.Options) (Handle, error) {
		return &fakeHandle{status: client.WebStatus{
			Connected: true,
			Tunnels:   []client.WebTunnel{{Name: "web", LocalAddress: "127.0.0.1:58080"}},
		}}, nil
	}}
	m, _ := newTestManager(t, fc)
	a, _ := m.AddProfile(config.Profile{Name: "a", Server: "https://a.example:8443"})
	b, _ := m.AddProfile(config.Profile{Name: "b", Server: "https://b.example:8443", Hosts: map[string]string{"web": "127.0.0.1"}, Ports: map[string]int{"web": 58080}})

	if err := m.Connect(a.ID); err != nil {
		t.Fatal(err)
	}
	waitForState(t, m, a.ID, StateConnected, 5*time.Second)

	if err := m.Connect(b.ID); err != nil {
		t.Fatal(err)
	}
	snap := waitForState(t, m, b.ID, StateFailed, 5*time.Second)
	if snap.Err == "" {
		t.Error("Snapshot().Err is empty after a reconciled-address collision, want an explanation")
	}
	if fc.callCount() != 1 {
		t.Errorf("connector called %d times, want 1 (profile b must never reach the connector once a's real address is known)", fc.callCount())
	}
}

func TestDisconnectReleasesPortForAnotherProfile(t *testing.T) {
	fc := &fakeConnector{}
	m, _ := newTestManager(t, fc)
	a, _ := m.AddProfile(config.Profile{Name: "a", Server: "https://a.example:8443", Ports: map[string]int{"web": 8080}})
	b, _ := m.AddProfile(config.Profile{Name: "b", Server: "https://b.example:8443", Ports: map[string]int{"web": 8080}})

	if err := m.Connect(a.ID); err != nil {
		t.Fatal(err)
	}
	waitForState(t, m, a.ID, StateConnected, 5*time.Second)

	if err := m.Disconnect(a.ID); err != nil {
		t.Fatalf("Disconnect() error = %v", err)
	}
	waitForState(t, m, a.ID, StateIdle, 5*time.Second)

	if err := m.Connect(b.ID); err != nil {
		t.Fatal(err)
	}
	waitForState(t, m, b.ID, StateConnected, 5*time.Second)
}

func TestRemoveProfileRefusedWhileConnected(t *testing.T) {
	m, _ := newTestManager(t, &fakeConnector{})
	p, _ := m.AddProfile(config.Profile{Name: "home-lab", Server: "https://home.example:8443"})
	if err := m.Connect(p.ID); err != nil {
		t.Fatal(err)
	}
	waitForState(t, m, p.ID, StateConnected, 5*time.Second)

	if err := m.RemoveProfile(p.ID); err == nil {
		t.Fatal("RemoveProfile() while connected = nil error, want an error")
	}
}

func TestReplacePortCallsHandle(t *testing.T) {
	m, _ := newTestManager(t, &fakeConnector{})
	p, _ := m.AddProfile(config.Profile{Name: "home-lab", Server: "https://home.example:8443"})
	if err := m.Connect(p.ID); err != nil {
		t.Fatal(err)
	}
	waitForState(t, m, p.ID, StateConnected, 5*time.Second)

	addr, err := m.ReplaceListener(p.ID, "web", "", 9090)
	if err != nil {
		t.Fatalf("ReplaceListener() error = %v", err)
	}
	if addr != "127.0.0.1:0" {
		t.Errorf("ReplaceListener() = %q, want the fake handle's fixed address", addr)
	}
}

// TestRemoveProfileWhileAwaitingTrustUnblocksRunConnect checks that removing
// a profile that is parked in StateAwaitingTrust does not leak its
// runConnect goroutine: closing session.cancel must unblock the prompt wait
// so the goroutine exits instead of blocking forever on a reply channel no
// one can ever reach again.
func TestRemoveProfileWhileAwaitingTrustUnblocksRunConnect(t *testing.T) {
	connectStarted := make(chan struct{})
	fc := &fakeConnector{connectFunc: func(server, keyPath string, opts client.Options) (Handle, error) {
		close(connectStarted)
		return nil, &client.UnknownCertificateError{Host: "home.example:8443", Fingerprint: "SHA256:abc"}
	}}
	m, _ := newTestManager(t, fc)
	p, _ := m.AddProfile(config.Profile{Name: "home-lab", Server: "https://home.example:8443", KnownServersFile: filepath.Join(t.TempDir(), "known_servers")})

	if err := m.Connect(p.ID); err != nil {
		t.Fatal(err)
	}
	<-connectStarted
	waitForState(t, m, p.ID, StateAwaitingTrust, 5*time.Second)

	// RemoveProfile must succeed even though a runConnect goroutine is
	// parked awaiting a trust decision for this profile.
	if err := m.RemoveProfile(p.ID); err != nil {
		t.Fatalf("RemoveProfile() while awaiting trust returned an error = %v, want nil", err)
	}
	if _, ok := m.Snapshot(p.ID); ok {
		t.Fatal("Snapshot() still finds the removed profile")
	}

	// AnswerTrust on the now-removed profile must fail cleanly rather than
	// finding a resurrected or dangling session.
	if err := m.AnswerTrust(p.ID, true); err == nil {
		t.Fatal("AnswerTrust() on a removed profile = nil error, want an error")
	}
}

func TestConnectPassphrasePromptTimesOut(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id")
	writeRealEncryptedKey(t, keyPath, "s3cret")

	m, _ := newTestManager(t, &fakeConnector{})
	m.promptTimeout = 50 * time.Millisecond
	p, _ := m.AddProfile(config.Profile{Name: "home-lab", Server: "https://home.example:8443", IdentityFile: keyPath})

	if err := m.Connect(p.ID); err != nil {
		t.Fatal(err)
	}
	waitForState(t, m, p.ID, StateAwaitingPassphrase, 2*time.Second)
	// Deliberately never answer; the prompt should time out on its own.
	snap := waitForState(t, m, p.ID, StateFailed, 2*time.Second)
	if snap.Err == "" {
		t.Error("Snapshot().Err is empty after a prompt timeout, want an explanation")
	}
}

// TestHandleEventAppliesBeforeHandleIsStored guards the window between
// client.ConnectWithOptions returning (which starts the connection's
// background renewal goroutine, and so can start firing OnEvent) and
// runConnect storing the resulting handle on the session: an event that
// arrives there must still be applied, not silently dropped because
// s.handle happens to be nil at that instant.
func TestProbeReturnsTunnelsWithoutConnecting(t *testing.T) {
	var gotQueryOnly bool
	fc := &fakeConnector{authenticateFunc: func(server, keyPath string, opts client.Options) (protocol.AuthResponse, error) {
		gotQueryOnly = opts.QueryOnly
		return protocol.AuthResponse{Tunnels: []protocol.Tunnel{{Name: "web", VirtualPort: 8080}}}, nil
	}}
	m, _ := newTestManager(t, fc)
	p, _ := m.AddProfile(config.Profile{Name: "home-lab", Server: "https://home.example:8443"})

	tunnels, err := m.Probe(p.ID)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if len(tunnels) != 1 || tunnels[0].Name != "web" {
		t.Fatalf("Probe() = %+v, want one tunnel named web", tunnels)
	}
	if !gotQueryOnly {
		t.Error("Probe() did not set Options.QueryOnly -- it would occupy a max_sessions_per_key slot")
	}
	if fc.callCount() != 0 {
		t.Errorf("Probe() called Connect %d times, want 0 (it must use Authenticate, not Connect)", fc.callCount())
	}

	snap, _ := m.Snapshot(p.ID)
	if snap.State != StateIdle {
		t.Errorf("State after Probe() = %q, want %q (probe must not connect)", snap.State, StateIdle)
	}
}

func TestGenerateIdentityWritesKeyAndReturnsFingerprint(t *testing.T) {
	m, _ := newTestManager(t, &fakeConnector{})
	path := filepath.Join(t.TempDir(), "id")

	fingerprint, pub, err := m.GenerateIdentity(path)
	if err != nil {
		t.Fatalf("GenerateIdentity() error = %v", err)
	}
	if fingerprint == "" {
		t.Error("GenerateIdentity() returned an empty fingerprint")
	}
	if !strings.HasPrefix(pub, "ssh-ed25519 ") {
		t.Errorf("GenerateIdentity() public key = %q, want an ssh-ed25519 OpenSSH line", pub)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("private key not written: %v", err)
	}
}

func TestLogoutForUnknownProfileFails(t *testing.T) {
	m, _ := newTestManager(t, &fakeConnector{})
	if err := m.Logout("no-such-id"); err == nil {
		t.Fatal("Logout() on an unknown profile = nil error, want an error")
	}
}

func TestHandleEventAppliesBeforeHandleIsStored(t *testing.T) {
	m, _ := newTestManager(t, &fakeConnector{})
	p, _ := m.AddProfile(config.Profile{Name: "home-lab", Server: "https://home.example:8443"})

	m.mu.Lock()
	s := m.sessions[p.ID]
	s.state = StateConnecting // as it would be mid-runConnect, before s.handle is set
	m.mu.Unlock()

	m.handleEvent(p.ID, client.Event{Kind: client.EventReconnecting, RetryIn: time.Second})

	snap, ok := m.Snapshot(p.ID)
	if !ok {
		t.Fatal("session disappeared")
	}
	if snap.State != StateReconnecting {
		t.Fatalf("State = %q, want %q -- the event was dropped despite s.handle being nil", snap.State, StateReconnecting)
	}
}

func TestHandleEventTransitionsReconnectingAndBack(t *testing.T) {
	m, _ := newTestManager(t, &fakeConnector{})
	p, _ := m.AddProfile(config.Profile{Name: "home-lab", Server: "https://home.example:8443"})
	if err := m.Connect(p.ID); err != nil {
		t.Fatal(err)
	}
	waitForState(t, m, p.ID, StateConnected, 5*time.Second)

	m.handleEvent(p.ID, client.Event{Kind: client.EventReconnecting, RetryIn: time.Second})
	waitForState(t, m, p.ID, StateReconnecting, 2*time.Second)

	m.handleEvent(p.ID, client.Event{Kind: client.EventReconnected})
	waitForState(t, m, p.ID, StateConnected, 2*time.Second)
}

// writeRealEncryptedKey writes a passphrase-protected Ed25519 SSH private
// key to path, the same construction pkg/sshkey's own tests use (see
// pkg/sshkey/sshkey_test.go's TestEncryptedKeyRequiresPassphrase), so
// resolvePassphrase's sshkey.NeedsPassphrase check has a real encrypted key
// to detect.
func writeRealEncryptedKey(t *testing.T, path, passphrase string) {
	t.Helper()
	signer, _, err := sshkey.GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(signer, "", []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
}
