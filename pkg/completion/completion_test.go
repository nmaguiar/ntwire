package completion

import (
	"strings"
	"testing"
)

func TestParseShell(t *testing.T) {
	cases := []struct {
		input   string
		want    Shell
		wantErr bool
	}{
		{"bash", ShellBash, false},
		{"BASH", ShellBash, false},
		{" bash ", ShellBash, false},
		{"--shell=bash", ShellBash, false},
		{"-shell=zsh", ShellZsh, false},
		{"zsh", ShellZsh, false},
		{"fish", ShellFish, false},
		{"powershell", ShellPowerShell, false},
		{"pwsh", ShellPowerShell, false},
		{"ps1", ShellPowerShell, false},
		{"--fish", ShellFish, false},
		{"-zsh", ShellZsh, false},
		{"unknown", "", true},
		{"", "", true},
	}

	for _, c := range cases {
		got, err := ParseShell(c.input)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseShell(%q) expected error, got nil", c.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseShell(%q) unexpected error: %v", c.input, err)
		}
		if got != c.want {
			t.Errorf("ParseShell(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestGenerateAllShellsForAllCommands(t *testing.T) {
	cmds := []Command{
		ClientCommand(),
		ServerCommand(),
		RelayCommand(),
		GUICommand(),
	}

	shells := []Shell{
		ShellBash,
		ShellZsh,
		ShellFish,
		ShellPowerShell,
	}

	for _, cmd := range cmds {
		for _, sh := range shells {
			t.Run(cmd.Name+"_"+string(sh), func(t *testing.T) {
				out, err := GenerateString(sh, cmd)
				if err != nil {
					t.Fatalf("GenerateString(%s, %s) error: %v", sh, cmd.Name, err)
				}
				if len(out) == 0 {
					t.Fatalf("GenerateString(%s, %s) returned empty string", sh, cmd.Name)
				}
				if !strings.Contains(out, cmd.Name) {
					t.Errorf("expected output to contain command name %q", cmd.Name)
				}
			})
		}
	}
}

func TestBashCompletionDetails(t *testing.T) {
	// Test client command bash output
	out, err := GenerateString(ShellBash, ClientCommand())
	if err != nil {
		t.Fatalf("GenerateString error: %v", err)
	}

	for _, subcmd := range []string{"connect", "keygen", "list", "status", "disconnect", "port", "logout", "completion", "version"} {
		if !strings.Contains(out, subcmd) {
			t.Errorf("expected bash script to mention subcommand %q", subcmd)
		}
	}
	if !strings.Contains(out, "complete -o default -F _ntwire ntwire") {
		t.Errorf("expected bash registration line in output")
	}

	// Test server command bash output
	serverOut, err := GenerateString(ShellBash, ServerCommand())
	if err != nil {
		t.Fatalf("GenerateString error: %v", err)
	}
	if !strings.Contains(serverOut, "complete -o default -F _ntwire_server ntwire-server") {
		t.Errorf("expected bash registration line for ntwire-server")
	}
	if !strings.Contains(serverOut, "conf qr all") {
		t.Errorf("expected wireguard-format choices in bash script")
	}
}

func TestZshCompletionDetails(t *testing.T) {
	out, err := GenerateString(ShellZsh, ClientCommand())
	if err != nil {
		t.Fatalf("GenerateString error: %v", err)
	}

	if !strings.Contains(out, "#compdef ntwire") {
		t.Errorf("expected #compdef header")
	}
	if !strings.Contains(out, "compdef _ntwire ntwire") {
		t.Errorf("expected compdef footer")
	}
	if !strings.Contains(out, "connect:connect tunnels") {
		t.Errorf("expected connect subcommand in subcommands list")
	}

	serverOut, err := GenerateString(ShellZsh, ServerCommand())
	if err != nil {
		t.Fatalf("GenerateString error: %v", err)
	}
	if !strings.Contains(serverOut, "#compdef ntwire-server") {
		t.Errorf("expected #compdef ntwire-server")
	}
	if !strings.Contains(serverOut, "compdef _ntwire_server ntwire-server") {
		t.Errorf("expected compdef _ntwire_server ntwire-server")
	}
}

func TestFishCompletionDetails(t *testing.T) {
	out, err := GenerateString(ShellFish, ClientCommand())
	if err != nil {
		t.Fatalf("GenerateString error: %v", err)
	}

	if !strings.Contains(out, "complete -c ntwire -f") {
		t.Errorf("expected complete -c ntwire -f")
	}
	if !strings.Contains(out, "complete -c ntwire -n \"__fish_use_subcommand\" -a \"connect\"") {
		t.Errorf("expected subcommand completion in fish")
	}

	serverOut, err := GenerateString(ShellFish, ServerCommand())
	if err != nil {
		t.Fatalf("GenerateString error: %v", err)
	}
	if !strings.Contains(serverOut, "complete -c ntwire-server -f") {
		t.Errorf("expected complete -c ntwire-server -f")
	}
	if !strings.Contains(serverOut, "-l config") {
		t.Errorf("expected -l config in fish script")
	}
}

func TestPowerShellCompletionDetails(t *testing.T) {
	out, err := GenerateString(ShellPowerShell, ClientCommand())
	if err != nil {
		t.Fatalf("GenerateString error: %v", err)
	}

	if !strings.Contains(out, "Register-ArgumentCompleter -Native -CommandName 'ntwire'") {
		t.Errorf("expected Register-ArgumentCompleter for ntwire")
	}
	if !strings.Contains(out, "[System.Management.Automation.CompletionResult]::new") {
		t.Errorf("expected CompletionResult instantiation in powershell script")
	}

	serverOut, err := GenerateString(ShellPowerShell, ServerCommand())
	if err != nil {
		t.Fatalf("GenerateString error: %v", err)
	}
	if !strings.Contains(serverOut, "Register-ArgumentCompleter -Native -CommandName 'ntwire-server'") {
		t.Errorf("expected Register-ArgumentCompleter for ntwire-server")
	}
}
