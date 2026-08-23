package browseropen

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSanitizeReplacesUnsafeChars(t *testing.T) {
	cases := map[string]string{
		"reports":             "reports",
		"my-profile_1.2":      "my-profile_1.2",
		"profile a/../../etc": "profile_a_.._.._etc",
		"space name":          "space_name",
		"":                    "",
	}
	for in, want := range cases {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProfileDirIsUnderNtwireBrowserProfiles(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory: %v", err)
	}
	dir, err := ProfileDir("my profile/1")
	if err != nil {
		t.Fatalf("ProfileDir() error = %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Join(home, ".ntwire", "browser-profiles", "my_profile_1")) })

	want := filepath.Join(home, ".ntwire", "browser-profiles", "my_profile_1")
	if dir != want {
		t.Errorf("ProfileDir() = %q, want %q", dir, want)
	}
	if _, err := os.Stat(filepath.Dir(dir)); err != nil {
		t.Errorf("parent directory not created: %v", err)
	}
}

func TestCleanProfileOnMissingDirIsNoop(t *testing.T) {
	if err := CleanProfile("does-not-exist-" + t.Name()); err != nil {
		t.Errorf("CleanProfile() on missing dir error = %v, want nil", err)
	}
}

func TestCleanProfileRemovesDirWithoutLock(t *testing.T) {
	key := "cleanup-test-" + t.Name()
	dir, err := ProfileDir(key)
	if err != nil {
		t.Fatalf("ProfileDir() error = %v", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := CleanProfile(key); err != nil {
		t.Fatalf("CleanProfile() error = %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("profile dir still exists after CleanProfile, stat err = %v", err)
	}
}

func TestCleanProfileRefusesWhenLocked(t *testing.T) {
	key := "locked-test-" + t.Name()
	dir, err := ProfileDir(key)
	if err != nil {
		t.Fatalf("ProfileDir() error = %v", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	lock := filepath.Join(dir, "SingletonLock")
	if err := os.Symlink("somewhere", lock); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	if err := CleanProfile(key); err == nil {
		t.Error("CleanProfile() with SingletonLock present, want error, got nil")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("profile dir should still exist, stat err = %v", err)
	}
}
