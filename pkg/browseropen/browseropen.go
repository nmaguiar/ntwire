// Package browseropen opens a browser for ntwire: either the OS default
// browser at an arbitrary URL (pkg/client's SSO login flow, ntwire-gui's
// tray "Open dashboard…" action, and its settings window's browser fallback
// when no native webview runtime is available), or, via OpenSocks, a
// Chrome/Chromium instance pre-configured to route through a SOCKS egress
// tunnel's local port (cmd/ntwire's "browser" command and ntwire-gui's
// per-tunnel "Open in browser" actions).
package browseropen

import (
	"os/exec"
	"runtime"
)

// Open launches the OS's default browser at url.
func Open(url string) error {
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
