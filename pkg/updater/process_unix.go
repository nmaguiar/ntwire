//go:build !windows

package updater

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"
)

func waitForExit(ctx context.Context, pid int) error {
	if pid <= 1 {
		return errors.New("invalid parent PID")
	}
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		if e := syscall.Kill(pid, 0); e == syscall.ESRCH {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func startElevated(helper, job, expectedHash string) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		command := shellQuote(helper) + " --internal-update " + shellQuote(job) + " >/dev/null 2>&1 &"
		script := `do shell script "` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(command) + `" with administrator privileges`
		cmd = exec.Command("osascript", "-e", script)
	} else {
		cmd = exec.Command("pkexec", helper, "--internal-update", job)
	}
	// macOS returns after authorization and launching the detached helper. pkexec
	// must stay alive while waiting for the parent; run it asynchronously.
	if runtime.GOOS == "darwin" {
		out, e := cmd.CombinedOutput()
		if e != nil {
			return fmt.Errorf("administrator authorization cancelled or failed: %s: %w", out, e)
		}
		return nil
	}
	if e := cmd.Start(); e != nil {
		return e
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(2 * time.Minute)
	defer timer.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case e := <-done:
			if e == nil {
				return errors.New("administrator helper exited before installation")
			}
			return fmt.Errorf("administrator authorization cancelled or failed: %w", e)
		case <-tick.C:
			if _, e := os.Stat(job + ".ready"); e == nil {
				return nil
			}
		case <-timer.C:
			_ = cmd.Process.Kill()
			return errors.New("administrator authorization timed out")
		}
	}
}

func resultOwner(f *os.File, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot determine helper result owner")
	}
	if os.Geteuid() == 0 {
		return f.Chown(int(stat.Uid), int(stat.Gid))
	}
	return nil
}
