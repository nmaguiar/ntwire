package browseropen

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// FindChrome locates a Chrome or Chromium binary for this OS. It checks the
// same handful of places the reference newChrome.sh scripts (mac/unix/win)
// rely on, plus -- on Windows -- the common install paths those scripts
// leave to cmd's own "start" (which consults the App Paths registry key
// that exec.Command does not).
func FindChrome() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		candidates := []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				return c, nil
			}
		}
	case "windows":
		if p, err := exec.LookPath("chrome.exe"); err == nil {
			return p, nil
		}
		var candidates []string
		for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "LocalAppData"} {
			if dir := os.Getenv(env); dir != "" {
				candidates = append(candidates,
					filepath.Join(dir, "Google", "Chrome", "Application", "chrome.exe"),
					filepath.Join(dir, "Chromium", "Application", "chrome.exe"),
					filepath.Join(dir, "Microsoft", "Edge", "Application", "msedge.exe"),
				)
			}
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				return c, nil
			}
		}
	default:
		for _, name := range []string{"google-chrome", "chromium-browser", "chromium"} {
			if p, err := exec.LookPath(name); err == nil {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf("no Chrome or Chromium installation found")
}

// sanitize replaces every rune outside [A-Za-z0-9_.-] with "_", so key can
// be used as a single path element.
func sanitize(key string) string {
	var b strings.Builder
	for _, r := range key {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

// ProfileDir returns the persistent, isolated Chrome user-data-dir for key,
// creating its parent directory if needed. Every (caller, target) pair gets
// its own directory under ~/.ntwire/browser-profiles so cookies and logins
// for one SOCKS egress target never leak into another's session.
func ProfileDir(key string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	base := filepath.Join(home, ".ntwire", "browser-profiles")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(base, sanitize(key)), nil
}

// OpenSocks launches Chrome/Chromium against localAddr ("host:port") via
// --proxy-server=socks5://<localAddr>, using the persistent, isolated
// profile directory for key (see ProfileDir). It starts the process and
// returns immediately -- it does not wait for the browser to exit.
func OpenSocks(key, localAddr string) error {
	bin, err := FindChrome()
	if err != nil {
		return err
	}
	dir, err := ProfileDir(key)
	if err != nil {
		return err
	}
	args := []string{
		"--user-data-dir=" + dir,
		"--proxy-server=socks5://" + localAddr,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-sync",
	}
	return exec.Command(bin, args...).Start()
}

// CleanProfile removes the persistent profile directory for key (see
// ProfileDir). It refuses -- returning an error rather than deleting -- if
// the profile's SingletonLock indicates a Chrome instance is still running
// against it, the same check newChrome.sh itself makes before deleting.
func CleanProfile(key string) error {
	dir, err := ProfileDir(key)
	if err != nil {
		return err
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil
	}
	if _, err := os.Lstat(filepath.Join(dir, "SingletonLock")); err == nil {
		return fmt.Errorf("browser profile still in use (close the browser first)")
	}
	return os.RemoveAll(dir)
}
