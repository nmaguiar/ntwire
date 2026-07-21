package ui

import (
	"flag"
	"fmt"
	"io"
	"strings"
)

// Command describes one subcommand entry in a Spec's command list.
type Command struct {
	Name    string
	Summary string
}

// Spec is a tool or subcommand's help text, rendered consistently across
// ntwire, ntwire-relay, and ntwire-server. It degrades to clean plain text
// when color/UTF-8 aren't available -- decoration is never the only way
// information is conveyed.
type Spec struct {
	Tool     string
	Tagline  string
	Commands []Command
	Flags    []*flag.Flag
	Examples []string
}

// FlagsOf collects every flag defined on fs, in the order flag.VisitAll
// reports them (lexicographic), for use as a Spec's Flags.
func FlagsOf(fs *flag.FlagSet) []*flag.Flag {
	var out []*flag.Flag
	fs.VisitAll(func(f *flag.Flag) { out = append(out, f) })
	return out
}

// Render renders the Spec using pal/sym directly, decoupled from any
// particular stream. Fprint is the usual entry point; Render is exposed
// for callers that need the string (e.g. tests).
func (s Spec) Render(pal Palette, sym Symbols) string {
	var b strings.Builder
	fmt.Fprintln(&b, pal.Highlight.Sprint(s.Tool))
	if s.Tagline != "" {
		fmt.Fprintln(&b, pal.Muted.Sprint(s.Tagline))
	}
	if len(s.Commands) > 0 {
		width := 0
		for _, c := range s.Commands {
			if len(c.Name) > width {
				width = len(c.Name)
			}
		}
		fmt.Fprintf(&b, "\n%s\n", pal.Info.Sprint("COMMANDS"))
		for _, c := range s.Commands {
			fmt.Fprintf(&b, "  %s  %s\n", pal.Highlight.Sprint(pad(c.Name, width, "left")), c.Summary)
		}
	}
	if len(s.Flags) > 0 {
		width := 0
		for _, f := range s.Flags {
			if n := len(flagLabel(f)); n > width {
				width = n
			}
		}
		fmt.Fprintf(&b, "\n%s\n", pal.Info.Sprint("FLAGS"))
		for _, f := range s.Flags {
			label := pad(flagLabel(f), width, "left")
			usage := f.Usage
			if def := defaultSuffix(f); def != "" {
				usage += def
			}
			fmt.Fprintf(&b, "  %s  %s\n", pal.Highlight.Sprint(label), usage)
		}
	}
	if len(s.Examples) > 0 {
		fmt.Fprintf(&b, "\n%s\n", pal.Info.Sprint("EXAMPLES"))
		for _, e := range s.Examples {
			fmt.Fprintf(&b, "  %s %s\n", sym.Arrow, e)
		}
	}
	return b.String()
}

// Fprint renders the Spec and writes it to w, coloring/symbolizing it
// according to whichever of u's streams w actually is (help conventionally
// goes to Err, but this makes `ntwire -h 2>file` -- capturing just Err on a
// color-capable stdout -- behave correctly rather than leaking ANSI into a
// file because color was decided from the wrong stream).
func (s Spec) Fprint(w io.Writer, u *UI) {
	pal, sym := u.OutPal, u.OutSym
	if w == u.Err {
		pal, sym = u.ErrPal, u.ErrSym
	}
	fmt.Fprint(w, s.Render(pal, sym))
}

func flagLabel(f *flag.Flag) string {
	return "-" + f.Name
}

func defaultSuffix(f *flag.Flag) string {
	if f.DefValue == "" || f.DefValue == "false" {
		return ""
	}
	return fmt.Sprintf(" (default %q)", f.DefValue)
}
