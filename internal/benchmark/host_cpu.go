package benchmark

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"
)

// HostCPU measures the entire Linux worker, including the client, server,
// kernel and other processes. Use a dedicated worker for backend comparisons.
type HostCPU struct {
	BusyTicks     uint64 `json:"busy_ticks"`
	SoftIRQTicks  uint64 `json:"softirq_ticks"`
	ElapsedUS     int64  `json:"elapsed_us"`
	IdleBusyTicks uint64 `json:"idle_baseline_busy_ticks"`
	IdleElapsedUS int64  `json:"idle_baseline_elapsed_us"`
}

type hostCPUSnapshot struct {
	at            time.Time
	busy, softIRQ uint64
}

func readHostCPU() hostCPUSnapshot {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return hostCPUSnapshot{}
	}
	return parseHostCPU(string(raw), time.Now())
}

func parseHostCPU(raw string, at time.Time) hostCPUSnapshot {
	line, _, _ := strings.Cut(raw, "\n")
	fields := strings.Fields(line)
	if len(fields) < 9 || fields[0] != "cpu" {
		return hostCPUSnapshot{}
	}
	sample := hostCPUSnapshot{at: at}
	// User and nice already include guest time. Idle, I/O wait and
	// hypervisor steal are time without CPU work in this worker.
	for _, i := range []int{1, 2, 3, 6, 7} {
		value, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			return hostCPUSnapshot{}
		}
		sample.busy += value
		if i == 7 {
			sample.softIRQ = value
		}
	}
	return sample
}

func sampleIdleHostCPU(ctx context.Context) HostCPU {
	start := readHostCPU()
	if start.at.IsZero() {
		return HostCPU{}
	}
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return HostCPU{}
	case <-timer.C:
	}
	end := readHostCPU()
	if !end.at.After(start.at) || end.busy < start.busy {
		return HostCPU{}
	}
	return HostCPU{IdleBusyTicks: end.busy - start.busy, IdleElapsedUS: end.at.Sub(start.at).Microseconds()}
}

func (idle HostCPU) measured(start, end hostCPUSnapshot) *HostCPU {
	if idle.IdleElapsedUS <= 0 || start.at.IsZero() || !end.at.After(start.at) ||
		end.busy < start.busy || end.softIRQ < start.softIRQ {
		return nil
	}
	idle.BusyTicks = end.busy - start.busy
	idle.SoftIRQTicks = end.softIRQ - start.softIRQ
	idle.ElapsedUS = end.at.Sub(start.at).Microseconds()
	return &idle
}
