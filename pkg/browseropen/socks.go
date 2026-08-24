package browseropen

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// ErrChromiumNotFound is returned by OpenSOCKSBrowser when no Chromium-family
// browser (Chrome, Chromium, Edge, or Brave) can be located on this host.
// Only that family supports the --proxy-server flag OpenSOCKSBrowser relies
// on; Safari and Firefox have no command-line equivalent.
var ErrChromiumNotFound = errors.New("no Chromium-family browser (Chrome, Chromium, Edge, or Brave) found")

// OpenSOCKSBrowser launches a Chromium-family browser with an isolated
// profile directory and all its traffic sent through the SOCKS5 proxy at
// proxyAddr (host:port). This is the flow documented for `target: socks`
// tunnels in examples/instructions/socks-client.md -- run for the user by
// the client status UI's "Open in browser" button instead of by hand,
// because the OS's default browser has no notion of this tunnel's proxy.
// profileDir is created if it does not already exist, and is never removed
// by this function -- see ResetSOCKSBrowserProfile for that.
func OpenSOCKSBrowser(profileDir, proxyAddr string) error {
	bin, err := chromiumBinary(chromiumCandidates())
	if err != nil {
		return err
	}
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		return fmt.Errorf("create browser profile directory: %w", err)
	}
	args := []string{
		"--user-data-dir=" + profileDir,
		"--proxy-server=socks5://" + proxyAddr,
		"--no-first-run",
	}
	return exec.Command(bin, args...).Start()
}

// ResetSOCKSBrowserProfile deletes an isolated profile directory previously
// used by OpenSOCKSBrowser, so the next "Open in browser" starts clean --
// no cached cookies, site data, or saved credentials from prior sessions.
// It is not an error for profileDir not to exist yet.
func ResetSOCKSBrowserProfile(profileDir string) error {
	return os.RemoveAll(profileDir)
}

// chromiumBinary returns the path to the first candidate that resolves to
// an executable: an absolute path is checked with os.Stat (the common case
// on macOS and Windows, where browsers are not on PATH), anything else is
// looked up on PATH (the common case on Linux).
func chromiumBinary(candidates []string) (string, error) {
	for _, c := range candidates {
		if filepath.IsAbs(c) {
			if info, err := os.Stat(c); err == nil && !info.IsDir() {
				return c, nil
			}
			continue
		}
		if p, err := exec.LookPath(c); err == nil {
			return p, nil
		}
	}
	return "", ErrChromiumNotFound
}

// chromiumCandidates lists this OS's usual Chromium-family install
// locations, most-preferred first (Chrome, then Chromium, then Edge, then
// Brave).
func chromiumCandidates() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
		}
	case "windows":
		var out []string
		for _, base := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("LocalAppData")} {
			if base == "" {
				continue
			}
			out = append(out,
				filepath.Join(base, "Google", "Chrome", "Application", "chrome.exe"),
				filepath.Join(base, "Chromium", "Application", "chrome.exe"),
				filepath.Join(base, "Microsoft", "Edge", "Application", "msedge.exe"),
				filepath.Join(base, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
			)
		}
		return append(out, "chrome.exe", "msedge.exe", "brave.exe")
	default:
		return []string{
			"google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
			"microsoft-edge", "microsoft-edge-stable", "brave-browser",
		}
	}
}
