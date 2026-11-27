package benchmark

import (
	"testing"
	"time"
)

func TestHostCPUIncludesKernelAndSoftIRQ(t *testing.T) {
	now := time.Now()
	start := parseHostCPU("cpu 10 2 4 100 6 3 8 1 9 1\ncpu0 0", now)
	end := parseHostCPU("cpu 12 2 11 140 9 4 20 4 10 1\n", now.Add(time.Second))
	idle := HostCPU{IdleBusyTicks: 1, IdleElapsedUS: 500000}
	got := idle.measured(start, end)
	if got == nil || got.BusyTicks != 22 || got.SoftIRQTicks != 12 || got.ElapsedUS != 1000000 ||
		got.IdleBusyTicks != 1 || got.IdleElapsedUS != 500000 {
		t.Fatalf("wrong host CPU delta: %+v", got)
	}
	for _, raw := range []string{"cpu 1", "cpu0 1 2 3 4 5 6 7 8", "cpu 1 2 3 4 5 x 7 8"} {
		if got := idle.measured(start, parseHostCPU(raw, end.at)); got != nil {
			t.Fatalf("invalid input %q produced host CPU data", raw)
		}
	}
	if idle.measured(end, start) != nil {
		t.Fatal("nonmonotonic counters produced host CPU data")
	}
}
