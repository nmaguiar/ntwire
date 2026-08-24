package browseropen

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestChromiumBinaryPrefersFirstExistingAbsoluteCandidate(t *testing.T) {
	dir := t.TempDir()
	second := filepath.Join(dir, "second")
	if err := os.WriteFile(second, []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := chromiumBinary([]string{filepath.Join(dir, "missing"), second})
	if err != nil {
		t.Fatalf("chromiumBinary: %v", err)
	}
	if got != second {
		t.Fatalf("got %q, want %q", got, second)
	}
}

func TestChromiumBinarySkipsDirectory(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := chromiumBinary([]string{sub}); !errors.Is(err, ErrChromiumNotFound) {
		t.Fatalf("err = %v, want ErrChromiumNotFound", err)
	}
}

func TestChromiumBinaryNoneFound(t *testing.T) {
	dir := t.TempDir()
	_, err := chromiumBinary([]string{filepath.Join(dir, "nope"), "ntwire-test-nonexistent-binary-xyz"})
	if !errors.Is(err, ErrChromiumNotFound) {
		t.Fatalf("err = %v, want ErrChromiumNotFound", err)
	}
}

func TestResetSOCKSBrowserProfileRemovesDirAndTolerantOfMissing(t *testing.T) {
	dir := t.TempDir()
	profile := filepath.Join(dir, "profile")
	if err := os.MkdirAll(filepath.Join(profile, "Default"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ResetSOCKSBrowserProfile(profile); err != nil {
		t.Fatalf("ResetSOCKSBrowserProfile: %v", err)
	}
	if _, err := os.Stat(profile); !os.IsNotExist(err) {
		t.Fatalf("profile dir still exists after reset: err=%v", err)
	}
	if err := ResetSOCKSBrowserProfile(profile); err != nil {
		t.Fatalf("ResetSOCKSBrowserProfile on missing dir: %v", err)
	}
}
