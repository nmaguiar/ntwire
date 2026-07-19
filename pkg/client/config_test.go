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
