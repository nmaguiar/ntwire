package ui

import (
	"fmt"
	"strings"
)

// KV renders aligned "key value" pairs to Out: keys are left-padded to the
// widest key in the set and bold-highlighted, mirroring the COMMANDS/FLAGS
// alignment help.go already uses for -h output. A Value of "" omits the
// row entirely, so callers can build the full set of possible rows and let
// KV skip the ones that don't apply (e.g. no local status UI configured).
type KV struct {
	Rows [][2]string
}

// Add appends a row, keeping key/value construction close to the call site.
func (kv *KV) Add(key, value string) {
	if value == "" {
		return
	}
	kv.Rows = append(kv.Rows, [2]string{key, value})
}

func (kv KV) Render(u *UI) string {
	width := 0
	for _, r := range kv.Rows {
		if n := len(r[0]) + 1; n > width { // +1 accounts for the trailing colon
			width = n
		}
	}
	var b strings.Builder
	for _, r := range kv.Rows {
		key := pad(r[0]+":", width, "left")
		fmt.Fprintf(&b, "%s %s\n", u.OutPal.Highlight.Sprint(key), r[1])
	}
	return b.String()
}
