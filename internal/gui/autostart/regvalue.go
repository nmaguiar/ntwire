package autostart

import "strings"

// commandLine builds the string ntwire-gui's Windows autostart entry
// stores in HKCU\...\Run: the quoted executable path followed by args, so
// Explorer's shell parses it correctly even when the path contains a
// space (e.g. "C:\Program Files\ntwire\ntwire-gui.exe"). This wraps in
// literal double quotes and escapes only an embedded ", the Windows
// command-line convention -- Go's %q is the wrong tool here, since it
// additionally escapes every backslash into \\, corrupting a Windows path.
func commandLine(execPath string, args []string) string {
	out := `"` + strings.ReplaceAll(execPath, `"`, `\"`) + `"`
	for _, a := range args {
		out += " " + a
	}
	return out
}
