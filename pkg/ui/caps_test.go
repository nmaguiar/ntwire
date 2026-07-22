package ui

import (
	"bytes"
	"os"
	"testing"
)

func TestDetectNonTerminalWriter(t *testing.T) {
	var buf bytes.Buffer
	caps := Detect(&buf, false)
	if caps.Color {
		t.Errorf("expected color disabled for a non-terminal writer")
	}
}

func TestDetectNoColorFlagWins(t *testing.T) {
	t.Setenv("CLICOLOR_FORCE", "1")
	var buf bytes.Buffer
	caps := Detect(&buf, true)
	if caps.Color {
		t.Errorf("expected --no-color to override CLICOLOR_FORCE")
	}
}

func TestDetectNoColorEnvWins(t *testing.T) {
	t.Setenv("CLICOLOR_FORCE", "1")
	t.Setenv("NO_COLOR", "1")
	var buf bytes.Buffer
	caps := Detect(&buf, false)
	if caps.Color {
		t.Errorf("expected NO_COLOR to override CLICOLOR_FORCE")
	}
}

func TestDetectCLIColorForceEnablesOffTTY(t *testing.T) {
	noColor, wasSet := os.LookupEnv("NO_COLOR")
	if err := os.Unsetenv("NO_COLOR"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if wasSet {
			_ = os.Setenv("NO_COLOR", noColor)
			return
		}
		_ = os.Unsetenv("NO_COLOR")
	})
	t.Setenv("CLICOLOR_FORCE", "1")
	var buf bytes.Buffer
	caps := Detect(&buf, false)
	if !caps.Color {
		t.Errorf("expected CLICOLOR_FORCE to enable color even off a TTY")
	}
}

func TestStyleSprintNoopWhenDisabled(t *testing.T) {
	s := Style{code: "38;5;111", enabled: false}
	if got := s.Sprint("x"); got != "x" {
		t.Errorf("expected disabled style to return plain text, got %q", got)
	}
}

func TestStyleSprintWrapsWhenEnabled(t *testing.T) {
	s := Style{code: "38;5;111", enabled: true}
	got := s.Sprint("x")
	want := "\x1b[38;5;111mx\x1b[0m"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
