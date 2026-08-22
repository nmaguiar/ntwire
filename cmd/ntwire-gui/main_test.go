package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nmaguiar/ntwire/pkg/ui"
)

func TestGUICompletion(t *testing.T) {
	for _, sh := range []string{"bash", "zsh", "fish", "powershell"} {
		t.Run(sh, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			u := ui.New(&stdout, &stderr, true)
			runCompletion([]string{sh}, u)
			if stderr.Len() > 0 {
				t.Fatalf("runCompletion(%q) unexpected stderr: %s", sh, stderr.String())
			}
			if !strings.Contains(stdout.String(), "ntwire-gui") {
				t.Errorf("runCompletion(%q) stdout does not contain ntwire-gui", sh)
			}
		})
	}
}
