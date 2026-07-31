//go:build darwin

package autostart

import (
	"os"
	"strings"
	"testing"
)

// These exercise enableIn/disableIn/enabledIn -- the real file-I/O logic,
// not a fake -- against t.TempDir() rather than the real
// ~/Library/LaunchAgents, so running this test suite never registers (or
// unregisters) anything in the developer's own login items.

func TestEnableInWritesPlistAndEnabledInSeesIt(t *testing.T) {
	dir := t.TempDir()

	if enabled, err := enabledIn(dir); err != nil || enabled {
		t.Fatalf("enabledIn on an empty dir = (%v, %v), want (false, nil)", enabled, err)
	}

	if err := enableIn(dir, "/usr/local/bin/ntwire-gui", []string{"--autostart"}); err != nil {
		t.Fatalf("enableIn: %v", err)
	}

	enabled, err := enabledIn(dir)
	if err != nil || !enabled {
		t.Fatalf("enabledIn after enableIn = (%v, %v), want (true, nil)", enabled, err)
	}

	b, err := os.ReadFile(plistPath(dir))
	if err != nil {
		t.Fatalf("reading plist: %v", err)
	}
	if !strings.Contains(string(b), "/usr/local/bin/ntwire-gui") {
		t.Errorf("plist does not mention the executable path:\n%s", b)
	}
	if !strings.Contains(string(b), "--autostart") {
		t.Errorf("plist does not mention --autostart:\n%s", b)
	}

	info, err := os.Stat(plistPath(dir))
	if err != nil {
		t.Fatalf("stat plist: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("plist mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestDisableInRemovesThePlist(t *testing.T) {
	dir := t.TempDir()
	if err := enableIn(dir, "/usr/local/bin/ntwire-gui", nil); err != nil {
		t.Fatalf("enableIn: %v", err)
	}
	if err := disableIn(dir); err != nil {
		t.Fatalf("disableIn: %v", err)
	}
	if enabled, err := enabledIn(dir); err != nil || enabled {
		t.Fatalf("enabledIn after disableIn = (%v, %v), want (false, nil)", enabled, err)
	}
}

// TestDisableInOnMissingFileIsNotAnError matters because a user who never
// enabled autostart, or already disabled it, clicking "disable" again (or
// the tray syncing state at startup) must not surface an error.
func TestDisableInOnMissingFileIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	if err := disableIn(dir); err != nil {
		t.Errorf("disableIn on a dir with no plist = %v, want nil", err)
	}
}

func TestEnableInCreatesTheDirectoryIfMissing(t *testing.T) {
	dir := t.TempDir() + "/nested/LaunchAgents"
	if err := enableIn(dir, "/usr/local/bin/ntwire-gui", nil); err != nil {
		t.Fatalf("enableIn into a non-existent directory: %v", err)
	}
	if enabled, err := enabledIn(dir); err != nil || !enabled {
		t.Fatalf("enabledIn = (%v, %v), want (true, nil)", enabled, err)
	}
}
