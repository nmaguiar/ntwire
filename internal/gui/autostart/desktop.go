package autostart

import (
	"path/filepath"
	"strings"
)

const desktopFileName = "ntwire-gui.desktop"

func desktopPath(dir string) string {
	return filepath.Join(dir, desktopFileName)
}

// desktopContents builds a minimal freedesktop.org autostart entry:
// Exec is execPath followed by args, each shell-quoted.
func desktopContents(execPath string, args []string) string {
	exec := quoteShellArg(execPath)
	for _, a := range args {
		exec += " " + quoteShellArg(a)
	}
	var b strings.Builder
	b.WriteString("[Desktop Entry]\n")
	b.WriteString("Type=Application\n")
	b.WriteString("Name=ntwire\n")
	b.WriteString("Exec=" + exec + "\n")
	b.WriteString("X-GNOME-Autostart-enabled=true\n")
	return b.String()
}

// quoteShellArg wraps s in single quotes, escaping any single quote it
// contains -- the standard shell-quoting a .desktop Exec= line needs, and
// the part that matters when execPath contains a space.
func quoteShellArg(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
