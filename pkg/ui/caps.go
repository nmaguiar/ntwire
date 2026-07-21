// Package ui provides terminal capability detection, a brand color palette,
// and small rendering helpers shared by ntwire, ntwire-relay, and
// ntwire-server so their CLI output and -h help degrade gracefully on
// terminals that don't support ANSI colors or UTF-8 symbols.
package ui

import (
	"io"
	"os"
	"runtime"
	"strings"
)

// Capabilities describes what a given output stream supports.
type Capabilities struct {
	Color bool
	UTF8  bool
}

// Detect resolves capabilities for w, honoring (in order): an explicit
// --no-color flag, the NO_COLOR convention (https://no-color.org, any
// value disables color), CLICOLOR_FORCE (forces color even off a TTY),
// and finally whether w is a terminal at all.
func Detect(w io.Writer, noColorFlag bool) Capabilities {
	tty := isTerminal(w)
	color := tty
	if v, forced := os.LookupEnv("CLICOLOR_FORCE"); forced && v != "0" {
		color = true
	}
	if _, set := os.LookupEnv("NO_COLOR"); set {
		color = false
	}
	if noColorFlag {
		color = false
	}
	return Capabilities{
		Color: color,
		UTF8:  tty && localeUTF8(),
	}
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// localeUTF8 reports whether the environment advertises a UTF-8 locale.
// Windows terminals rarely set LANG/LC_*, so Windows Terminal's WT_SESSION
// is used as a UTF-8 signal there instead; other Windows consoles fall
// back to ASCII symbols.
func localeUTF8() bool {
	if runtime.GOOS == "windows" {
		_, wt := os.LookupEnv("WT_SESSION")
		return wt
	}
	for _, env := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if v := os.Getenv(env); v != "" {
			return strings.Contains(strings.ToLower(v), "utf-8") || strings.Contains(strings.ToLower(v), "utf8")
		}
	}
	// No locale vars set at all is common in minimal containers; default to
	// UTF-8 support since it's the near-universal default outside Windows.
	return true
}
