package client

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultIdentityFileUsesOpenSSHOrder(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"id_ed25519", "id_rsa"} {
		if err := os.WriteFile(filepath.Join(sshDir, name), []byte("key"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := defaultIdentityFile(home), filepath.Join(sshDir, "id_rsa"); got != want {
		t.Fatalf("defaultIdentityFile() = %q, want %q", got, want)
	}
}

func TestDefaultIdentityFileSkipsMissingAndNonRegularFiles(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(filepath.Join(sshDir, "id_rsa"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := defaultIdentityFile(home); got != "" {
		t.Fatalf("defaultIdentityFile() = %q, want empty", got)
	}
}

func TestDefaultIdentityFilePrefersNTWire(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".ntwire", "id_ed25519")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("key"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := defaultIdentityFile(home); got != path {
		t.Fatalf("got %q, want %q", got, path)
	}
}

func TestNormalizeServerURL(t *testing.T) {
	for in, want := range map[string]string{" example.test/ ": "https://example.test", "http://example.test:8080/": "http://example.test:8080"} {
		got, err := NormalizeServerURL(in)
		if err != nil || got != want {
			t.Fatalf("NormalizeServerURL(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := NormalizeServerURL("ssh://example.test"); err == nil {
		t.Fatal("non-HTTP scheme accepted")
	}
}

func TestLoadSettingsReadsHTTPSProxyControls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("https_proxy: http://proxy.example:8080\nno_system_proxy: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.HTTPSProxy != "http://proxy.example:8080" || !got.NoSystemProxy {
		t.Errorf("LoadSettings() = %+v, want HTTPS proxy controls", got)
	}
}
