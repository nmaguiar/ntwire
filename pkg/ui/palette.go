package ui

import "fmt"

// Style wraps an SGR escape code. Sprint/Sprintf are no-ops (return plain
// text) when the style is disabled, so callers never need to branch on
// color capability themselves.
type Style struct {
	code    string
	enabled bool
}

func (s Style) Sprint(a ...any) string {
	text := fmt.Sprint(a...)
	if !s.enabled || s.code == "" {
		return text
	}
	return "\x1b[" + s.code + "m" + text + "\x1b[0m"
}

func (s Style) Sprintf(format string, a ...any) string {
	return s.Sprint(fmt.Sprintf(format, a...))
}

// Palette is the terminal translation of docs/UI-THEME.md's dark-mode
// brand tokens: brand blue for informational/highlighted text, accent
// green for success, amber for warnings, a bolder amber for errors
// (the theme has no dedicated red), and muted gray-blue for secondary text.
type Palette struct {
	Info      Style // brand blue, --brand dark: #79a7ff
	Success   Style // accent green, --accent dark: #4ade80
	Warn      Style // amber, --danger dark: #fb923c
	Danger    Style // bold amber, for errors: distinguishes from Warn by weight
	Muted     Style // muted gray-blue, --muted dark: #9fb0ca
	Highlight Style // bold brand blue, for headers and emphasized names
}

// DefaultPalette returns the ntwire brand palette. When color is false,
// every Style is a no-op and Sprint/Sprintf return their input unchanged.
func DefaultPalette(color bool) Palette {
	return Palette{
		Info:      Style{code: "38;5;111", enabled: color},
		Success:   Style{code: "38;5;84", enabled: color},
		Warn:      Style{code: "38;5;215", enabled: color},
		Danger:    Style{code: "1;38;5;208", enabled: color},
		Muted:     Style{code: "38;5;145", enabled: color},
		Highlight: Style{code: "1;38;5;111", enabled: color},
	}
}
