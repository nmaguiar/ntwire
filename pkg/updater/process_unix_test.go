//go:build !windows

package updater

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

func TestWaitForExitAndCancellation(t *testing.T) {
	cmd := exec.Command("sleep", "1")
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- waitForExit(context.Background(), cmd.Process.Pid) }()
	select {
	case e := <-done:
		t.Fatalf("returned before parent exited: %v", e)
	case <-time.After(50 * time.Millisecond):
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("did not see exit")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := waitForExit(ctx, 1); e == nil {
		t.Fatal("accepted invalid PID")
	}
	cmd = exec.Command("sleep", "2")
	cmd.Start()
	defer cmd.Wait()
	defer cmd.Process.Kill()
	if e := waitForExit(ctx, cmd.Process.Pid); e == nil {
		t.Fatal("cancellation ignored")
	}
}
