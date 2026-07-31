package autostart

import "testing"

func TestCommandLineQuotesPathWithSpaces(t *testing.T) {
	got := commandLine(`C:\Program Files\ntwire\ntwire-gui.exe`, []string{"--autostart"})
	want := `"C:\Program Files\ntwire\ntwire-gui.exe" --autostart`
	if got != want {
		t.Errorf("commandLine = %q, want %q", got, want)
	}
}

func TestCommandLineWithNoArgs(t *testing.T) {
	got := commandLine(`C:\ntwire-gui.exe`, nil)
	want := `"C:\ntwire-gui.exe"`
	if got != want {
		t.Errorf("commandLine = %q, want %q", got, want)
	}
}
