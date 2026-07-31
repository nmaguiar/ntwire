// Package browseropen opens a URL in the user's default browser, the one
// way every ntwire binary that needs it does it: pkg/client's SSO login
// flow, and ntwire-gui's tray "Open dashboard…" action and its settings
// window's browser fallback when no native webview runtime is available.
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
