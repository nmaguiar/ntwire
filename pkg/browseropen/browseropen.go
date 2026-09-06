// Package browseropen opens a browser for ntwire: either the OS default
// browser at an arbitrary URL (pkg/client's SSO login flow, ntwire-gui's
// tray "Open dashboard…" action, and its settings window's browser fallback
// when no native webview runtime is available), or, via OpenSocks, a
// Chrome/Chromium instance pre-configured to route through a SOCKS egress
// tunnel's local port (cmd/ntwire's "browser" command, ntwire-gui's
// per-tunnel "Open in browser" actions, and the client status UI's "Open in
// browser" button on target: socks tunnels).
package browseropen

import (
	"errors"
	"os/exec"
	"runtime"
	"strings"
)

// ErrUnsafeURL is returned for a URL that must not be handed to an OS handler
// or a browser: anything that is not an absolute http(s) URL, which includes a
// value beginning with "-" that a browser would read as a command-line switch.
var ErrUnsafeURL = errors.New("refusing to open a URL that is not absolute http(s)")

// safeURL reports whether url may be passed to a browser or OS handler. The
// callers' URLs are server-supplied (a portal target's configured URL), and
// "open"/"xdg-open" will happily act on a local path while Chromium reads a
// leading "-" as a switch, so this is checked at the launcher rather than
// trusted from the caller.
func safeURL(url string) bool {
	u := strings.TrimSpace(url)
	if u == "" || strings.HasPrefix(u, "-") || strings.ContainsAny(u, " \t\r\n\"'<>") {
		return false
	}
	l := strings.ToLower(u)
	return strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://")
}

// Open launches the OS's default browser at url.
func Open(url string) error {
	if !safeURL(url) {
		return ErrUnsafeURL
	}
	var command string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		command, args = "open", []string{url}
	case "windows":
		command, args = "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default:
		command, args = "xdg-open", []string{url}
	}
	return exec.Command(command, args...).Start()
}
