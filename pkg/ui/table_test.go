package ui

import (
	"bytes"
	"fmt"
	"testing"
)

// TestTableListShapeByteStable locks the `ntwire list` non-color rendering
// to the exact "%-20s %5d  %s\n" shape the plain fmt.Printf loop produced
// before this package existed, so piped/NO_COLOR output doesn't reshape.
func TestTableListShapeByteStable(t *testing.T) {
	rows := [][]string{
		{"reports", "18080", "Reporting service"},
		{"a-very-long-tunnel-name", "9", "x"},
	}
	tbl := Table{
		Columns: []Column{
			{Header: "NAME", Width: 20, Align: "left"},
			{Header: "PORT", Width: 5, Align: "right"},
			{Header: "DESCRIPTION", Sep: "  "},
		},
		Rows: rows,
	}

	var out bytes.Buffer
	u := New(&out, &out, true) // --no-color: no TTY caps.Color regardless

	got := tbl.Render(u)

	var want bytes.Buffer
	for _, r := range rows {
		var port int
		fmt.Sscanf(r[1], "%d", &port)
		fmt.Fprintf(&want, "%-20s %5d  %s\n", r[0], port, r[2])
	}

	if got != want.String() {
		t.Errorf("Render() =\n%q\nwant\n%q", got, want.String())
	}
}
