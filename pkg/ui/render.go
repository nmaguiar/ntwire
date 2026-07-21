package ui

import (
	"fmt"
	"io"
)

// UI bundles output/error streams with their independently detected
// capabilities (a script can redirect stdout but leave stderr attached to
// a terminal, or vice versa) and provides small, composable helpers for
// status lines. When color is disabled, every helper falls back to plain
// fmt.Fprintln output byte-identical to an undecorated message, so piped
// output stays stable.
type UI struct {
	Out, Err io.Writer

	OutCaps, ErrCaps Capabilities
	OutPal, ErrPal   Palette
	OutSym, ErrSym   Symbols
}

// New builds a UI bound to out/err, detecting capabilities independently
// for each stream and honoring an explicit --no-color flag for both.
func New(out, err io.Writer, noColorFlag bool) *UI {
	oc := Detect(out, noColorFlag)
	ec := Detect(err, noColorFlag)
	return &UI{
		Out: out, Err: err,
		OutCaps: oc, ErrCaps: ec,
		OutPal: DefaultPalette(oc.Color), ErrPal: DefaultPalette(ec.Color),
		OutSym: SymbolsFor(oc), ErrSym: SymbolsFor(ec),
	}
}

// Success prints a success line to Out, prefixed with a checkmark when
// color is available; otherwise it's a plain message line.
func (u *UI) Success(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	if u.OutCaps.Color {
		fmt.Fprintf(u.Out, "%s %s\n", u.OutPal.Success.Sprint(u.OutSym.OK), msg)
		return
	}
	fmt.Fprintln(u.Out, msg)
}

// Info prints an informational line to Out.
func (u *UI) Info(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	if u.OutCaps.Color {
		fmt.Fprintf(u.Out, "%s %s\n", u.OutPal.Info.Sprint(u.OutSym.Bullet), msg)
		return
	}
	fmt.Fprintln(u.Out, msg)
}

// Warn prints a warning line to Err.
func (u *UI) Warn(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	if u.ErrCaps.Color {
		fmt.Fprintf(u.Err, "%s %s\n", u.ErrPal.Warn.Sprint(u.ErrSym.Warn), msg)
		return
	}
	fmt.Fprintln(u.Err, msg)
}

// WarnOut prints a warning-styled line to Out instead of Err, for
// diagnostics that were historically part of a command's stdout output
// (and may be relied on there) rather than genuine error/warning noise.
func (u *UI) WarnOut(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	if u.OutCaps.Color {
		fmt.Fprintf(u.Out, "%s %s\n", u.OutPal.Warn.Sprint(u.OutSym.Warn), msg)
		return
	}
	fmt.Fprintln(u.Out, msg)
}

// Errorf prints an error line to Err.
func (u *UI) Errorf(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	if u.ErrCaps.Color {
		fmt.Fprintf(u.Err, "%s %s\n", u.ErrPal.Danger.Sprint(u.ErrSym.Fail), msg)
		return
	}
	fmt.Fprintln(u.Err, msg)
}

// Section prints a colorized header line to Out with no plain-mode decoration.
func (u *UI) Section(title string) {
	fmt.Fprintln(u.Out, u.OutPal.Highlight.Sprint(title))
}
