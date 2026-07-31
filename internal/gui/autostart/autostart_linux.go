//go:build linux

// Package autostart registers (or unregisters) ntwire-gui to launch at
// login. This file writes a freedesktop.org autostart .desktop entry
// under $XDG_CONFIG_HOME/autostart (~/.config/autostart), pure Go file
// I/O with no GTK or D-Bus dependency.
package autostart

import (
	"os"
	"path/filepath"
)

func autostartDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "autostart"), nil
}

// Enable registers execPath (with args) to launch at login.
func Enable(execPath string, args []string) error {
	dir, err := autostartDir()
	if err != nil {
		return err
	}
	return enableIn(dir, execPath, args)
}

// Disable removes the login item, if any.
func Disable() error {
	dir, err := autostartDir()
	if err != nil {
		return err
	}
	return disableIn(dir)
}

// Enabled reports whether the login item is currently registered.
func Enabled() (bool, error) {
	dir, err := autostartDir()
	if err != nil {
		return false, err
	}
	return enabledIn(dir)
}

func enableIn(dir, execPath string, args []string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return os.WriteFile(desktopPath(dir), []byte(desktopContents(execPath, args)), 0644)
}

func disableIn(dir string) error {
	err := os.Remove(desktopPath(dir))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func enabledIn(dir string) (bool, error) {
	_, err := os.Stat(desktopPath(dir))
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}
