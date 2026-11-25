package window

import (
	"fmt"
	"html"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

var launchBootstrapFile = func(path string) error {
	var command string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		command, args = "open", []string{path}
	case "windows":
		command, args = "rundll32", []string{"url.dll,FileProtocolHandler", path}
	default:
		command, args = "xdg-open", []string{path}
	}
	return exec.Command(command, args...).Run()
}

// launchPrivateBrowser gives the browser a private local document, never a reusable credential
// in argv. Other OS accounts can see the filename but cannot read the 0700
// directory or 0600 document. Keep it briefly for asynchronous browser startup.
func launchPrivateBrowser(target string) (func(), error) {
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("invalid browser bootstrap URL")
	}
	dir, err := os.MkdirTemp("", "ntwire-browser-")
	if err != nil {
		return nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	path := filepath.Join(dir, "ntwire.html")
	page := fmt.Sprintf(`<!doctype html><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta http-equiv="refresh" content="0;url=%s"><title>Opening ntwire</title>`, html.EscapeString(target))
	if err := os.WriteFile(path, []byte(page), 0600); err != nil {
		cleanup()
		return nil, err
	}
	if err := launchBootstrapFile(path); err != nil {
		cleanup()
		return nil, err
	}
	return cleanup, nil
}

func smartProxyDashboardURL(settingsURL, group string) (string, error) {
	return smartProxyBrowserURL(settingsURL, "/smart-proxy-dashboard.html", url.Values{"group": {group}})
}

func smartProxyBrowserURL(settingsURL, path string, query url.Values) (string, error) {
	target, err := url.Parse(settingsURL)
	if err != nil {
		return "", err
	}
	query.Set("token", target.Query().Get("token"))
	target.Path = path
	target.RawPath = ""
	target.RawQuery = query.Encode()
	target.Fragment = ""
	return target.String(), nil
}

// OpenSmartProxyDashboard opens the selected group in the system browser.
func OpenSmartProxyDashboard(settingsURL, group string) error {
	target, err := smartProxyDashboardURL(settingsURL, group)
	if err != nil {
		return err
	}
	cleanup, err := launchPrivateBrowser(target)
	if err != nil {
		return err
	}
	time.AfterFunc(30*time.Second, cleanup)
	return nil
}
