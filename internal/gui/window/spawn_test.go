package window

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestHelperProcess is not a real test: it is re-executed as the "child
// process" by tests below, via the classic os/exec testing idiom (re-run
// the test binary itself with -test.run=TestHelperProcess so no real
// external binary is required, portable across every platform this repo
// targets). GO_WANT_HELPER_PROCESS gates it so a normal `go test` run
// doesn't try to run it as an actual test. Rather than assert on the
// child's stdout (Spawner.Open builds its own *exec.Cmd internally, so a
// test has no handle to redirect it), the marker is written to a file
// whose path is passed alongside it -- a channel entirely under the
// production code path's control.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	if marker := os.Getenv("NTWIRE_TEST_ENV_MARKER"); marker != "" {
		if path := os.Getenv("NTWIRE_TEST_ENV_OUTFILE"); path != "" {
			_ = os.WriteFile(path, []byte(marker), 0600)
		}
	}
	time.Sleep(200 * time.Millisecond)
	os.Exit(0)
}

// helperCommand returns the (path, args) pair Spawner.Open needs to
// re-exec this test binary as TestHelperProcess. Open builds its own
// *exec.Cmd internally from these, so only Path/Args are meaningful here
// -- GO_WANT_HELPER_PROCESS=1 must be supplied by the caller via Open's
// own extraEnv parameter, exercising the real code path rather than a
// pre-built *exec.Cmd's Env field that Open would never look at.
func helperCommand() *exec.Cmd {
	return exec.Command(os.Args[0], "-test.run=TestHelperProcess", "--")
}

func TestOpenStartsAChild(t *testing.T) {
	var s Spawner
	if s.Running() {
		t.Fatal("a freshly constructed Spawner reports Running before Open is ever called")
	}
	cmd := helperCommand()
	if err := s.Open(cmd.Path, cmd.Args[1:], []string{"GO_WANT_HELPER_PROCESS=1"}); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !s.Running() {
		t.Fatal("Running() = false immediately after a successful Open")
	}
}

// TestOpenDoesNotSpawnASecondChildWhileOneIsRunning is the actual
// invariant this type exists for: clicking "Settings…" twice in a row
// must not leave two window processes running.
func TestOpenDoesNotSpawnASecondChildWhileOneIsRunning(t *testing.T) {
	var s Spawner
	env := []string{"GO_WANT_HELPER_PROCESS=1"}
	cmd1 := helperCommand()
	if err := s.Open(cmd1.Path, cmd1.Args[1:], env); err != nil {
		t.Fatalf("first Open: %v", err)
	}

	callCount := 0
	orig := commandContext
	commandContext = func(name string, arg ...string) *exec.Cmd {
		callCount++
		return orig(name, arg...)
	}
	defer func() { commandContext = orig }()

	cmd2 := helperCommand()
	if err := s.Open(cmd2.Path, cmd2.Args[1:], env); err != nil {
		t.Fatalf("second Open: %v", err)
	}
	if callCount != 0 {
		t.Errorf("commandContext was invoked %d times while the first child was still running, want 0", callCount)
	}

	// Let the first child exit, then confirm a later Open is allowed to
	// spawn a fresh one -- Running() must go back to false, not get stuck.
	deadline := time.Now().Add(2 * time.Second)
	for s.Running() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.Running() {
		t.Fatal("first child never reported as exited")
	}

	cmd3 := helperCommand()
	if err := s.Open(cmd3.Path, cmd3.Args[1:], env); err != nil {
		t.Fatalf("third Open (after the first child exited): %v", err)
	}
	if !s.Running() {
		t.Fatal("a new child should be running after Open following the previous one's exit")
	}
}

// TestOpenPassesExtraEnv confirms the token-via-env plumbing actually
// reaches the child -- the whole reason internal/gui/window's contract is
// "token via env, bare origin in argv" rather than embedding the token in
// the --window URL, where it would be visible to any local user via ps or
// /proc/<pid>/cmdline.
func TestOpenPassesExtraEnv(t *testing.T) {
	var s Spawner
	outFile := filepath.Join(t.TempDir(), "marker.txt")
	cmd := helperCommand()
	extraEnv := []string{
		"GO_WANT_HELPER_PROCESS=1",
		"NTWIRE_TEST_ENV_MARKER=hello-from-env",
		"NTWIRE_TEST_ENV_OUTFILE=" + outFile,
	}
	if err := s.Open(cmd.Path, cmd.Args[1:], extraEnv); err != nil {
		t.Fatalf("Open: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(outFile); err == nil {
			if got := string(b); got != "hello-from-env" {
				t.Fatalf("child wrote marker %q, want %q", got, "hello-from-env")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("child never wrote the marker file within the deadline -- extra env did not reach it")
}
