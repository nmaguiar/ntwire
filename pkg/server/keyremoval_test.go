package server

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
)

// TestWatchConfigRevokesOnKeyFileRemoval is the regression test for the watcher
// mask: it listened for Write, Create and Rename but not Remove, so deleting an
// authorized-key file -- the ordinary way to revoke one -- produced no reload
// and the key's live sessions survived to their TTL.
func TestWatchConfigRevokesOnKeyFileRemoval(t *testing.T) {
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		t.Fatal(err)
	}
	_, authLine := genTestKey(t, t.TempDir(), "alice@laptop")
	keyPath := filepath.Join(keysDir, "alice.pub")
	if err := os.WriteFile(keyPath, []byte(authLine+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(dir, "ntwire.yaml")
	yaml := "listen:\n  https: \"127.0.0.1:8443\"\nauth:\n  authorized_keys_dir: " + keysDir +
		"\nnetwork:\n  tunnel_cidr: 100.64.0.0/16\ntunnels:\n  - name: reports\n    target: \"x:1\"\n    virtual_port: 18080\n    allow: [\"*\"]\n"
	if err := os.WriteFile(configPath, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, slog.New(slog.DiscardHandler))

	key, _, err := sshkey.ParsePublicString(authLine)
	if err != nil {
		t.Fatal(err)
	}
	fp := sshkey.Fingerprint(key)
	session := s.sessions.Create(CreateParams{
		Method: "ssh", Identity: fp, Fingerprint: fp,
		Tunnels: []protocol.Tunnel{{Name: "reports", VirtualPort: 18080}}, TTL: time.Hour,
	})

	w, err := WatchConfig(configPath, s, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := s.sessions.Get(session.Token); !ok {
			return // revoked, as it should be
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("removing an authorized-key file did not revoke the key's live session")
}

// TestWatchConfigSurvivesConfigFileRemoval checks the other half of adding
// Remove to the mask: a Remove on the config file itself (some editors' save
// path) must leave the running configuration in force rather than reloading
// from a file that is not there.
func TestWatchConfigSurvivesConfigFileRemoval(t *testing.T) {
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "ntwire.yaml")
	yaml := "listen:\n  https: \"127.0.0.1:8443\"\nauth:\n  authorized_keys_dir: " + keysDir +
		"\nnetwork:\n  tunnel_cidr: 100.64.0.0/16\ntunnels:\n  - name: reports\n    target: \"x:1\"\n    virtual_port: 18080\n    allow: [\"*\"]\n"
	if err := os.WriteFile(configPath, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, slog.New(slog.DiscardHandler))

	w, err := WatchConfig(configPath, s, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)

	if len(s.Config.Tunnels) != 1 || s.Config.Tunnels[0].Name != "reports" {
		t.Fatalf("configuration was clobbered by a removed config file: %+v", s.Config.Tunnels)
	}
}
