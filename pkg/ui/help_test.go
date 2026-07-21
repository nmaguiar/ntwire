package ui

import (
	"bytes"
	"strings"
	"testing"
)

// fakeTTY implements the same shape isTerminal checks for (*os.File), but
// since isTerminal only recognizes *os.File, a bytes.Buffer standing in
// for a "color-capable" stream can't fool Detect -- so this test instead
// constructs a UI directly with mismatched Out/Err capabilities to prove
// Fprint picks color based on the stream it actually writes to, not
// whichever stream was used to build the palette.
func TestSpecFprintColorsByTargetStream(t *testing.T) {
	var out, errOut bytes.Buffer
	u := &UI{
		Out: &out, Err: &errOut,
		OutCaps: Capabilities{Color: true, UTF8: true},
		ErrCaps: Capabilities{Color: false},
		OutPal:  DefaultPalette(true), ErrPal: DefaultPalette(false),
		OutSym: SymbolsFor(Capabilities{UTF8: true}), ErrSym: SymbolsFor(Capabilities{UTF8: false}),
	}
	spec := Spec{Tool: "ntwire-server", Tagline: "test"}

	// Help conventionally writes to Err; Err has color disabled here even
	// though Out (a different, color-capable stream) does not.
	spec.Fprint(u.Err, u)
	if strings.Contains(errOut.String(), "\x1b[") {
		t.Errorf("Fprint(u.Err, ...) leaked ANSI escapes from Out's capabilities: %q", errOut.String())
	}

	spec.Fprint(u.Out, u)
	if !strings.Contains(out.String(), "\x1b[") {
		t.Errorf("Fprint(u.Out, ...) should use Out's color-enabled palette: %q", out.String())
	}
}
