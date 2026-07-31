// Package window manages ntwire-gui's settings window: the core process's
// side spawns it as a child process (Spawner) re-executing the same
// binary with a hidden --window flag; the child process's side (Run, in
// window_gui.go / window_default.go) hosts either a native webview or a
// browser-fallback page at the URL it's given. Splitting core and window
// into separate processes is what lets the tray keep running -- and stay
// responsive -- independent of the settings window's own lifecycle; see
// internal/gui/tray's package doc and this repo's Phase 0 spike notes for
// why a single process can't safely do both.
package window

import (
	"os/exec"
	"sync"
)

// Spawner starts the settings-window child process, refusing to start a
// second one while the current one is still running -- "raise the
// existing window" is left undone (cross-platform window-raising is a
// separate, non-trivial problem), but at minimum a second click on
// "Settings…" must not spawn a second window process.
type Spawner struct {
	mu   sync.Mutex
	done chan struct{} // non-nil and open while a child is running
}

// commandContext lets tests substitute a fake child process; production
// code never overrides it.
var commandContext = exec.Command

// Open starts command with args and extraEnv appended to the current
// process's environment, unless a previously started child is still
// running, in which case it does nothing and returns nil -- from the
// caller's point of view, "a settings window is open" either way.
func (s *Spawner) Open(command string, args []string, extraEnv []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running() {
		return nil
	}

	cmd := commandContext(command, args...)
	cmd.Env = append(cmd.Environ(), extraEnv...)
	if err := cmd.Start(); err != nil {
		return err
	}

	done := make(chan struct{})
	s.done = done
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	return nil
}

// running reports whether the most recently started child is still
// alive. Must be called with mu held.
func (s *Spawner) running() bool {
	if s.done == nil {
		return false
	}
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}

// Running reports whether a settings-window child process is currently
// alive.
func (s *Spawner) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running()
}
