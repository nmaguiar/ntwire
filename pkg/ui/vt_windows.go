//go:build windows

package ui

import (
	"os"

	"golang.org/x/sys/windows"
)

func init() {
	enableVirtualTerminal(os.Stdout)
	enableVirtualTerminal(os.Stderr)
}

// enableVirtualTerminal turns on ANSI escape sequence processing for a
// Windows console handle. It is a no-op (and safe to call) when f isn't a
// console, e.g. when output is redirected to a file or pipe.
func enableVirtualTerminal(f *os.File) {
	handle := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return
	}
	mode |= windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
	_ = windows.SetConsoleMode(handle, mode)
}
