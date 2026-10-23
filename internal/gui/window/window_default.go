//go:build !gui

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

// Run gives the browser a private local document, never a reusable credential
// in argv. Other OS accounts can see the filename but cannot read the 0700
// directory or 0600 document. Keep it briefly for asynchronous browser startup.
func Run(target string) error {
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return fmt.Errorf("invalid browser bootstrap URL")
	}
	dir, err := os.MkdirTemp("", "ntwire-browser-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "settings.html")
	page := fmt.Sprintf(`<!doctype html><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta http-equiv="refresh" content="0;url=%s"><title>Opening ntwire settings</title>`, html.EscapeString(target))
	if err := os.WriteFile(path, []byte(page), 0600); err != nil {
		return err
	}
	if err := launchBootstrapFile(path); err != nil {
		return err
	}
	time.Sleep(30 * time.Second)
	return nil
}
