package browseropen

import (
	"fmt"
	"regexp"
	"strings"
)

// LaunchOptions configures a Chromium SOCKS browser launch.
type LaunchOptions struct {
	Executable string
	ExtraArgs  []string
}

var browserSwitchName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]*$`)

// ValidateExtraArgs validates literal Chromium switches without interpreting a shell.
func ValidateExtraArgs(args []string) error {
	for _, arg := range args {
		if strings.ContainsAny(arg, "\x00\r\n") {
			return fmt.Errorf("invalid browser argument %q: control characters are not allowed", arg)
		}
		if strings.TrimSpace(arg) == "" {
			continue
		}
		name, _, _ := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
		if !strings.HasPrefix(arg, "--") || !browserSwitchName.MatchString(name) || strings.ContainsAny(arg, "\x00\r\n") {
			return fmt.Errorf("invalid browser argument %q: use --flag or --flag=value", arg)
		}
		switch strings.ToLower(name) {
		case "proxy-server", "proxy-pac-url", "proxy-auto-detect", "no-proxy-server", "proxy-bypass-list", "user-data-dir", "profile-directory":
			return fmt.Errorf("browser argument %q conflicts with ntwire managed settings", arg)
		}
	}
	return nil
}

// ResolveExtraArgs combines global and profile arguments using an explicit mode.
func ResolveExtraArgs(global, profile []string, mode string) ([]string, error) {
	var args []string
	switch mode {
	case "", "inherit":
		args = append(args, global...)
	case "append":
		args = append(args, global...)
		args = append(args, profile...)
	case "replace":
		args = append(args, profile...)
	default:
		return nil, fmt.Errorf("invalid browser arguments mode %q", mode)
	}
	if err := ValidateExtraArgs(args); err != nil {
		return nil, err
	}
	return args, nil
}
