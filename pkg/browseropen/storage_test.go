package browseropen

import (
	"os"
	"path/filepath"
	"testing"
)

func isolatedProfileHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home
}

func TestCustomProfileReuseAndCleanup(t *testing.T) {
	isolatedProfileHome(t)
	folder := t.TempDir()
	p := SelectProfile(t.TempDir(), ProfileSettings{Folder: folder, Name: "Work"})
	key := "client-reports"
	before, err := ProfilePath(key, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(before); !os.IsNotExist(err) {
		t.Fatalf("preview created %s: %v", before, err)
	}
	dir, err := prepareProfile(key, p)
	if err != nil || dir != before {
		t.Fatalf("launch path %q: %v, want %q", dir, err, before)
	}
	bookmark := filepath.Join(dir, "bookmark-test")
	if err := os.WriteFile(bookmark, []byte("example.org"), 0o600); err != nil {
		t.Fatal(err)
	}
	other, err := prepareProfile("client-admin", p)
	if err != nil || other == dir {
		t.Fatalf("same label must produce separate directories: %q, %v", other, err)
	}
	p.Name = "Renamed"
	if got, err := prepareProfile(key, p); err != nil || got != dir {
		t.Fatalf("rename selected %q: %v", got, err)
	}
	if _, err := os.Stat(bookmark); err != nil {
		t.Fatal(err)
	}
	p.Folder = t.TempDir()
	moved, err := prepareProfile(key, p)
	if err != nil || moved == dir {
		t.Fatalf("folder change selected %q: %v", moved, err)
	}
	unrelated := filepath.Join(filepath.Dir(dir), "unrelated")
	if err := os.Mkdir(unrelated, 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := ListProfiles()
	if err != nil || len(entries) != 3 {
		t.Fatalf("inventory = %+v: %v", entries, err)
	}
	lock := filepath.Join(dir, "SingletonLock")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var previous ProfileEntry
	for _, entry := range entries {
		if entry.Path == dir {
			previous = entry
		}
	}
	if previous.Name != "Renamed" || CleanProfile(previous.Key) == nil {
		t.Fatalf("missing rename or unsafe cleanup: %+v", previous)
	}
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if err := CleanProfile(previous.Key); err != nil {
		t.Fatal(err)
	}
	if err := CleanConfiguredProfile(key, p); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{unrelated, other} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("cleanup touched %s: %v", path, err)
		}
	}
}

func TestCustomProfileRejectsExistingUnownedDirectory(t *testing.T) {
	isolatedProfileHome(t)
	p := ProfileSettings{Folder: t.TempDir()}
	const key = "client-socks"
	path, err := ProfilePath(key, p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareProfile(key, p); err == nil {
		t.Fatal("adopted an unrelated directory")
	}
	if err := CleanConfiguredProfile(key, p); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestCustomProfileCleanupRefusesSymlinkReplacement(t *testing.T) {
	isolatedProfileHome(t)
	p := ProfileSettings{Folder: t.TempDir()}
	dir, err := prepareProfile("client-socks", p)
	if err != nil {
		t.Fatal(err)
	}
	replacement := dir + "-elsewhere"
	if err := os.Rename(dir, replacement); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(replacement, dir); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := CleanConfiguredProfile("client-socks", p); err == nil {
		t.Fatal("cleanup accepted a symlink, even with the original marker")
	}
	if _, err := os.Stat(filepath.Join(replacement, profileMarker)); err != nil {
		t.Fatal(err)
	}
}

func TestConfiguredProfileLaunchArguments(t *testing.T) {
	isolatedProfileHome(t)
	key := "client-reports"
	p := ProfileSettings{Folder: t.TempDir(), Name: "Work"}
	path, err := prepareProfile(key, p)
	if err != nil {
		t.Fatal(err)
	}
	args, err := socksArgs(path, "127.0.0.1:1080", []string{"https://example.org"})
	if err != nil {
		t.Fatal(err)
	}
	if args[0] != "--user-data-dir="+path || args[1] != "--proxy-server=socks5://127.0.0.1:1080" || args[len(args)-1] != "https://example.org" {
		t.Fatalf("unexpected browser arguments: %q", args)
	}
}
