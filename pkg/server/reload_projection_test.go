package server

import (
	"fmt"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatchConfigProjectedSymlinkSwap(t *testing.T) {
	dir := t.TempDir()
	volume, keys := filepath.Join(dir, "config"), filepath.Join(dir, "keys")
	for _, p := range []string{keys, filepath.Join(volume, "..v1"), filepath.Join(volume, "..v2")} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for i, desc := range []string{"old", "new"} {
		body := fmt.Sprintf("listen:\n  https: '127.0.0.1:8443'\nauth:\n  authorized_keys_dir: %s\nnetwork:\n  tunnel_cidr: 100.64.0.0/16\ntunnels:\n  - name: reports\n    description: %s\n    target: 'x:1'\n    virtual_port: 18080\n    allow: ['*']\n", keys, desc)
		if err := os.WriteFile(filepath.Join(volume, fmt.Sprintf("..v%d", i+1), "ntwire.yaml"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("..v1", filepath.Join(volume, "..data")); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(volume, "ntwire.yaml")
	if err := os.Symlink("..data/ntwire.yaml", configPath); err != nil {
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
	if err := os.Symlink("..v2", filepath.Join(volume, "..data_tmp")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(volume, "..data_tmp"), filepath.Join(volume, "..data")); err != nil {
		t.Fatal(err)
	}
	current := func() string { s.mu.Lock(); defer s.mu.Unlock(); return s.Config.Tunnels[0].Description }
	deadline := time.Now().Add(time.Second)
	for current() != "new" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	onDisk, err := LoadConfig(configPath)
	if err != nil || onDisk.Tunnels[0].Description != "new" {
		t.Fatalf("fixture did not swap config: %v", err)
	}
	if current() != "new" {
		t.Error("projected symlink switched to valid new config, but running server kept old config")
	}
	// Control: an ordinary authorized-keys event triggers the same reload path.
	if err := os.WriteFile(filepath.Join(keys, "control.pub"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(time.Second)
	for current() != "new" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if current() != "new" {
		t.Fatal("control keys event also failed")
	}
	t.Log("control keys event reloaded successfully")
}

func TestWatchConfigRetainsValidConfigAndMovesKeyWatch(t *testing.T) {
	dir, keysA, keysB := t.TempDir(), t.TempDir(), t.TempDir()
	_, line := genTestKey(t, t.TempDir(), "test")
	for _, keys := range []string{keysA, keysB} {
		if err := os.WriteFile(filepath.Join(keys, "test.pub"), []byte(line), 0600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "config.yaml")
	writeConfig := func(keys string) {
		body := fmt.Sprintf("auth:\n  authorized_keys_dir: %s\ntunnels:\n  - name: reports\n    target: 'x:1'\n    virtual_port: 18080\n    allow: ['*']\n", keys)
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig(keysA)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, slog.New(slog.DiscardHandler))
	watcher, err := WatchConfig(path, s, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Close()
	if err := os.WriteFile(path, []byte("tunnels: [invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	s.mu.Lock()
	kept := len(s.Config.Tunnels) == 1 && s.Config.Auth.AuthorizedKeysDir == keysA
	s.mu.Unlock()
	if !kept {
		t.Fatal("invalid YAML replaced running configuration")
	}
	writeConfig(keysB)
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.mu.Lock()
		changed := s.Config.Auth.AuthorizedKeysDir == keysB
		s.mu.Unlock()
		if changed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("new config was not loaded")
		}
		time.Sleep(10 * time.Millisecond)
	}
	key, _, err := sshkey.ParsePublicString(line)
	if err != nil {
		t.Fatal(err)
	}
	fp := sshkey.Fingerprint(key)
	session := s.sessions.Create(CreateParams{Method: "ssh", Identity: fp, Fingerprint: fp, Tunnels: []protocol.Tunnel{{Name: "reports"}}, TTL: time.Hour})
	if err := os.Remove(filepath.Join(keysB, "test.pub")); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for {
		if _, ok := s.sessions.Get(session.Token); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("key removal from new directory did not revoke session")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
