package completion

import (
	"bytes"
	"fmt"
	"io"
	"strings"
)

// Shell identifies a supported target shell for completion generation.
type Shell string

const (
	ShellBash       Shell = "bash"
	ShellZsh        Shell = "zsh"
	ShellFish       Shell = "fish"
	ShellPowerShell Shell = "powershell"
)

// SupportedShells lists the canonical names of all supported shells.
var SupportedShells = []string{
	string(ShellBash),
	string(ShellZsh),
	string(ShellFish),
	string(ShellPowerShell),
}

// Flag describes a single command-line flag for completion.
type Flag struct {
	Name       string   // flag name without leading dashes, e.g. "config"
	Usage      string   // description
	TakesValue bool     // false for boolean flags
	IsFilePath bool     // true if value is a filesystem path
	Choices    []string // allowable value choices if enum
}

// Command describes a binary or subcommand hierarchy for completion.
type Command struct {
	Name        string    // binary or subcommand name, e.g. "ntwire", "connect"
	Summary     string    // short description
	Flags       []Flag    // flags supported by this command
	Subcommands []Command // subcommands (if any)
	ArgChoices  []string  // choices for positional argument if any
}

// ParseShell parses a shell name string into a validated Shell enum.
func ParseShell(s string) (Shell, error) {
	clean := strings.TrimSpace(strings.ToLower(s))
	clean = strings.TrimPrefix(clean, "--shell=")
	clean = strings.TrimPrefix(clean, "-shell=")
	clean = strings.TrimPrefix(clean, "--")
	clean = strings.TrimPrefix(clean, "-")
	switch clean {
	case "bash":
		return ShellBash, nil
	case "zsh":
		return ShellZsh, nil
	case "fish":
		return ShellFish, nil
	case "powershell", "pwsh", "ps1":
		return ShellPowerShell, nil
	default:
		return "", fmt.Errorf("unsupported shell %q (supported: %s)", s, strings.Join(SupportedShells, ", "))
	}
}

// Generate writes the completion script for the specified shell and command to w.
func Generate(shell Shell, cmd Command, w io.Writer) error {
	switch shell {
	case ShellBash:
		return Bash(cmd, w)
	case ShellZsh:
		return Zsh(cmd, w)
	case ShellFish:
		return Fish(cmd, w)
	case ShellPowerShell:
		return PowerShell(cmd, w)
	default:
		return fmt.Errorf("unsupported shell %q", shell)
	}
}

// GenerateString returns the completion script as a string.
func GenerateString(shell Shell, cmd Command) (string, error) {
	var buf bytes.Buffer
	if err := Generate(shell, cmd, &buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}
