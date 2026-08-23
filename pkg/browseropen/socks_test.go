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

func TestListProfilesMissingDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)

	profiles, err := ListProfiles()
	if err != nil {
		t.Fatalf("ListProfiles() error = %v", err)
	}
	if profiles != nil {
		t.Errorf("ListProfiles() on missing base dir = %v, want nil", profiles)
	}
}

func TestListProfilesLockedAndUnlocked(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)

	base := filepath.Join(dir, ".ntwire", "browser-profiles")
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	zDir := filepath.Join(base, "z-unlocked")
	if err := os.MkdirAll(zDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	aDir := filepath.Join(base, "a-locked")
	if err := os.MkdirAll(aDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	lock := filepath.Join(aDir, "SingletonLock")
	if err := os.Symlink("somewhere", lock); err != nil {
		if err := os.WriteFile(lock, []byte("123"), 0o600); err != nil {
			t.Fatalf("failed to create lock file: %v", err)
		}
	}

	if err := os.WriteFile(filepath.Join(base, "ignored-file"), []byte("data"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	profiles, err := ListProfiles()
	if err != nil {
		t.Fatalf("ListProfiles() error = %v", err)
	}
	if len(profiles) != 2 {
		t.Fatalf("ListProfiles() returned %d entries, want 2", len(profiles))
	}

	if profiles[0].Key != "a-locked" || !profiles[0].InUse || profiles[0].Path != aDir {
		t.Errorf("profiles[0] = %+v, want Key: a-locked, InUse: true, Path: %s", profiles[0], aDir)
	}
	if profiles[0].ModTime.IsZero() {
		t.Errorf("profiles[0].ModTime is zero")
	}

	if profiles[1].Key != "z-unlocked" || profiles[1].InUse || profiles[1].Path != zDir {
		t.Errorf("profiles[1] = %+v, want Key: z-unlocked, InUse: false, Path: %s", profiles[1], zDir)
	}
	if profiles[1].ModTime.IsZero() {
		t.Errorf("profiles[1].ModTime is zero")
	}
}

func TestCleanProfilesForProfile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)

	base := filepath.Join(dir, ".ntwire", "browser-profiles")
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	// Create directories for profile "p1" (multiple tunnels) and "p2" (different profile)
	p1Socks := filepath.Join(base, "p1-socks")
	p1Web := filepath.Join(base, "p1-web")
	p1Exact := filepath.Join(base, "p1")
	p2Socks := filepath.Join(base, "p2-socks")
	p10Socks := filepath.Join(base, "p10-socks") // p1 prefix should not match p10
	for _, d := range []string{p1Socks, p1Web, p1Exact, p2Socks, p10Socks} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatalf("MkdirAll(%s) error = %v", d, err)
		}
	}

	// Empty profileID does nothing
	if err := CleanProfilesForProfile(""); err != nil {
		t.Errorf("CleanProfilesForProfile(\"\") error = %v", err)
	}

	// Clean p1
	if err := CleanProfilesForProfile("p1"); err != nil {
		t.Fatalf("CleanProfilesForProfile(\"p1\") error = %v", err)
	}

	// Check p1 dirs are gone
	for _, d := range []string{p1Socks, p1Web, p1Exact} {
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Errorf("expected %s to be deleted, stat err = %v", d, err)
		}
	}

	// Check p2 and p10 remain
	for _, d := range []string{p2Socks, p10Socks} {
		if _, err := os.Stat(d); err != nil {
			t.Errorf("expected %s to remain, stat err = %v", d, err)
		}
	}
}
