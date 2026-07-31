package tray

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// TestCopyToClipboardRoundTrips actually exercises the OS clipboard on
// platforms with an unconditional, script-friendly readback tool (macOS's
// pbpaste). It is a real, executed verification, not just a compile check
// -- deliberately narrow to darwin because Linux has no single guaranteed
// clipboard tool to read back from in a CI container.
func TestCopyToClipboardRoundTrips(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("clipboard readback is only verified on darwin, where pbpaste is guaranteed present")
	}
	want := "ntwire-gui clipboard test 12345"
	if err := copyToClipboard(want); err != nil {
		t.Fatalf("copyToClipboard: %v", err)
	}
	out, err := exec.Command("pbpaste").Output()
	if err != nil {
		t.Fatalf("pbpaste: %v", err)
	}
	if got := strings.TrimRight(string(out), "\n"); got != want {
		t.Errorf("clipboard contains %q, want %q", got, want)
	}
}
