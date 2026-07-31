// Package singleinstance lets a second ntwire-gui launch detect a live
// instance already running against the same gui.yaml, and raise its
// settings window instead of starting a second connection manager --
// which would otherwise double-connect every profile and fight over
// per-profile status files and explicit local ports.
package singleinstance

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Info is what a running instance records about itself, and what a later
// launch reads back to find it.
type Info struct {
	PID   int    `json:"pid"`
	URL   string `json:"url"` // bare origin, e.g. "http://127.0.0.1:54321"
	Token string `json:"token"`
}

// lockFileName is colocated with gui.yaml rather than at a fixed path, so
// tests (and any future --gui-config override) get isolation for free:
// each gui.yaml directory has its own lock, the same as it has its own
// profile store.
const lockFileName = "gui-instance.json"

// LockPath returns the lock file path for the gui.yaml at guiConfigPath.
// It errors on an empty guiConfigPath rather than silently resolving to
// "." (filepath.Dir("") is "."), matching how config.Save already refuses
// to write to an unresolvable path.
func LockPath(guiConfigPath string) (string, error) {
	if guiConfigPath == "" {
		return "", errors.New("gui/singleinstance: cannot determine a lock path from an empty gui-config path")
	}
	return filepath.Join(filepath.Dir(guiConfigPath), lockFileName), nil
}

// Write persists this instance's Info to path, atomically and at mode
// 0600, mirroring config.Save's temp-file-then-rename pattern.
func Write(path string, info Info) error {
	b, err := json.Marshal(info)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".gui-instance-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(b)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// Remove deletes the lock file. A missing file is not an error.
func Remove(path string) error {
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// Existing reads the lock file at path and returns the recorded Info only
// if a live process actually answers at its URL with its token -- a
// lightweight authenticated GET, chosen over trusting the file's mere
// existence, since a crashed process leaves it behind with nothing
// listening on that port. Any of "no file", "corrupt file", "URL isn't
// loopback" (the file is user-writable; refusing to probe a non-loopback
// host keeps a doctored lock file from making this process send a valid
// token to an arbitrary address) or "nothing answered" is reported as
// (nil, nil) -- not running -- rather than an error, so a caller can
// always fall back to starting its own instance.
func Existing(path string, client *http.Client) (*Info, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var info Info
	if err := json.Unmarshal(b, &info); err != nil {
		return nil, nil
	}
	if !isLoopbackURL(info.URL) {
		return nil, nil
	}
	if !probe(client, info) {
		return nil, nil
	}
	return &info, nil
}

func isLoopbackURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	switch u.Hostname() {
	case "127.0.0.1", "localhost", "::1":
		return true
	default:
		return false
	}
}

func probe(client *http.Client, info Info) bool {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(info.URL, "/")+"/api/settings", nil)
	if err != nil {
		return false
	}
	q := req.URL.Query()
	q.Set("token", info.Token)
	req.URL.RawQuery = q.Encode()
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
