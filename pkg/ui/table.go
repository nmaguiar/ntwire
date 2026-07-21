package ui

import (
	"fmt"
	"strings"
)

// Column describes one column of a Table. Width is a fixed padding width
// (0 means "no padding," i.e. the last/free-form column); Align is "left"
// (default) or "right". Sep is the literal separator printed immediately
// before this column (ignored for the first column; defaults to a single
// space).
type Column struct {
	Header string
	Width  int
	Align  string
	Sep    string
}

// Table renders aligned rows, with an optional colorized header and a
// highlighted first column shown only when the UI's Out stream has color
// enabled. In plain mode it prints only the padded/separated rows with no
// header, so callers can reuse exact legacy column widths/separators to
// keep piped output byte-stable across this change.
type Table struct {
	Columns []Column
	Rows    [][]string
}

func (t Table) Render(u *UI) string {
	var b strings.Builder
	color := u.OutCaps.Color
	if color && anyHeader(t.Columns) {
		b.WriteString(u.OutPal.Muted.Sprint(t.formatRow(u, headers(t.Columns), false)))
		b.WriteString("\n")
	}
	for _, row := range t.Rows {
		b.WriteString(t.formatRow(u, row, color))
		b.WriteString("\n")
	}
	return b.String()
}

func (t Table) formatRow(u *UI, row []string, highlightFirst bool) string {
	var b strings.Builder
	for i, col := range t.Columns {
		if i > 0 {
			sep := col.Sep
			if sep == "" {
				sep = " "
			}
			b.WriteString(sep)
		}
		v := ""
		if i < len(row) {
			v = row[i]
		}
		v = pad(v, col.Width, col.Align)
		if highlightFirst && i == 0 {
			v = u.OutPal.Highlight.Sprint(v)
		}
		b.WriteString(v)
	}
	return b.String()
}

func pad(s string, width int, align string) string {
	if width <= 0 {
		return s
	}
	if align == "right" {
		return fmt.Sprintf("%*s", width, s)
	}
	return fmt.Sprintf("%-*s", width, s)
}

func headers(cols []Column) []string {
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = c.Header
	}
	return out
}

func anyHeader(cols []Column) bool {
	for _, c := range cols {
		if c.Header != "" {
			return true
		}
	}
	return false
}
