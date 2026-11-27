package main

import (
	"slices"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/internal/benchmark"
)

func TestRealUDPRelayCarriesBenchmarkTraffic(t *testing.T) {
	report, err := benchmark.ExecuteLab(t.Context(), []benchmark.Options{{
		Transport: "udp-relay", Workload: "udp", Connections: 1,
		Duration: 3 * time.Second, MaxBytes: 1 << 20,
	}}, startRelay)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Runs) != 1 {
		t.Fatalf("unexpected run count %d", len(report.Runs))
	}
	run := report.Runs[0]
	if !slices.Equal(run.SelectedPaths, []string{"udp-relay"}) || run.Iterations == 0 {
		t.Fatalf("expected delivered echo traffic over the real relay, got %+v", run)
	}
	if traffic := run.RelayTraffic; traffic == nil || traffic.PacketsSent == 0 || traffic.PacketsReceived == 0 {
		t.Fatalf("expected measured WireGuard datagrams in both directions, got %+v", traffic)
	}
}
