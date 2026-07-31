package tray

import (
	"errors"
	"os/exec"
	"runtime"
)

var errNoClipboardTool = errors.New("gui/tray: no clipboard tool found (tried wl-copy, xclip, xsel)")

// copyToClipboard is a best-effort, dependency-free clipboard write via
// each OS's own built-in copy command -- no cgo, no GTK, matching the
// "100% Go, no bundled runtime" constraint the rest of this app follows.
// macOS and Windows ship pbcopy/clip.exe unconditionally; Linux has no
// single universal equivalent, so this tries the common X11/Wayland tools
// in order and reports whichever, if any, actually ran.
func copyToClipboard(text string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("pbcopy")
	case "windows":
		cmd = exec.Command("clip")
	default:
		for _, name := range []string{"wl-copy", "xclip", "xsel"} {
			if path, err := exec.LookPath(name); err == nil {
				args := []string{}
				if name == "xclip" {
					args = []string{"-selection", "clipboard"}
				} else if name == "xsel" {
					args = []string{"--clipboard", "--input"}
				}
				cmd = exec.Command(path, args...)
				break
			}
		}
	}
	if cmd == nil {
		return errNoClipboardTool
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	_, writeErr := stdin.Write([]byte(text))
	closeErr := stdin.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	return cmd.Wait()
}
