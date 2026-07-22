package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nmaguiar/ntwire/pkg/client"
	"github.com/nmaguiar/ntwire/pkg/ui"
)

func TestFormatBytes(t *testing.T) {
	cases := []struct {
		n    uint64
		want string
	}{
		{0, "0 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{1153433, "1.1 MiB"},
		{1 << 40, "1.0 TiB"},
	}
	for _, c := range cases {
		if got := formatBytes(c.n); got != c.want {
			t.Errorf("formatBytes(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

func TestConnsAndTrafficSummary(t *testing.T) {
	s := client.TunnelStats{Active: 3, Connections: 12, BytesFromTunnel: 1153433, BytesToTunnel: 4404019}
	if got, want := connsSummary(s), "3/12"; got != want {
		t.Errorf("connsSummary() = %q, want %q", got, want)
	}
	if got, want := trafficSummary(s), "1.1 MiB in / 4.2 MiB out"; got != want {
		t.Errorf("trafficSummary() = %q, want %q", got, want)
	}
}

// TestListColumnsFitLiveStats renders list()'s table with realistic and
// near-worst-case live stats and checks that DESCRIPTION starts at the
// same column offset on every row -- the failure mode a too-narrow STATS
// column previously produced (a long CONNS/TRAFFIC value overflowed its
// padded width and pushed DESCRIPTION out of alignment on that row only).
func TestListColumnsFitLiveStats(t *testing.T) {
	rows := [][]string{
		{"reports", "51001", "8080", "connected", connsSummary(client.TunnelStats{Active: 3, Connections: 12}),
			trafficSummary(client.TunnelStats{BytesFromTunnel: 1153433, BytesToTunnel: 4404019}), "Reporting DB"},
		{"admin", "51002", "8081", "-", "-", "-", "Admin panel"},
		{"huge-tunnel", "9", "-", "connected", connsSummary(client.TunnelStats{Active: 999, Connections: 99999}),
			trafficSummary(client.TunnelStats{BytesFromTunnel: (1 << 40) * 999, BytesToTunnel: (1 << 40) * 999}), "Worst case"},
	}
	tbl := ui.Table{Columns: listColumns(), Rows: rows}

	var out bytes.Buffer
	u := ui.New(&out, &out, true) // --no-color
	got := tbl.Render(u)

	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) != len(rows) {
		t.Fatalf("Render() produced %d lines, want %d:\n%s", len(lines), len(rows), got)
	}
	var descOffset = -1
	for i, line := range lines {
		want := rows[i][len(rows[i])-1] // DESCRIPTION is the last field
		idx := strings.Index(line, want)
		if idx < 0 {
			t.Fatalf("line %d %q does not contain description %q", i, line, want)
		}
		if descOffset == -1 {
			descOffset = idx
		} else if idx != descOffset {
			t.Errorf("line %d: DESCRIPTION starts at column %d, want %d (misaligned):\n%s", i, idx, descOffset, got)
		}
	}
}
