//go:build darwin

// Package autostart registers (or unregisters) ntwire-gui to launch at
// login. This file writes a LaunchAgent property list under
// ~/Library/LaunchAgents -- chosen over macOS's newer SMAppService
// because that API needs Objective-C interop, breaking the pure-Go
// implementation the rest of this app follows. It only writes the file;
// it deliberately does not invoke `launchctl load`, so a freshly enabled
// autostart entry takes effect at the next login, not immediately.
package autostart

import (
	"os"
	"path/filepath"
)

func launchAgentsDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents"), nil
}

// Enable registers execPath (with args) to launch at login.
func Enable(execPath string, args []string) error {
	dir, err := launchAgentsDir()
	if err != nil {
		return err
	}
	return enableIn(dir, execPath, args)
}

// Disable removes the login item, if any.
func Disable() error {
	dir, err := launchAgentsDir()
	if err != nil {
		return err
	}
	return disableIn(dir)
}

// Enabled reports whether the login item is currently registered.
func Enabled() (bool, error) {
	dir, err := launchAgentsDir()
	if err != nil {
		return false, err
	}
	return enabledIn(dir)
}

func enableIn(dir, execPath string, args []string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return os.WriteFile(plistPath(dir), plistContents(execPath, args), 0600)
}

func disableIn(dir string) error {
	err := os.Remove(plistPath(dir))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func enabledIn(dir string) (bool, error) {
	_, err := os.Stat(plistPath(dir))
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}
