package benchmark

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"runtime/pprof"
)

type Resources struct {
	CPUSeconds     float64 `json:"process_cpu_seconds,omitempty"`
	AllocatedBytes uint64  `json:"allocated_bytes"`
	HeapPeakBytes  uint64  `json:"sampled_heap_peak_bytes"`
	GoroutinePeak  int     `json:"sampled_goroutine_peak"`
	RSSPeakBytes   uint64  `json:"process_lifetime_peak_rss_bytes,omitempty"`
	FDPeak         int     `json:"sampled_open_fd_peak,omitempty"`
	FDLimit        uint64  `json:"open_fd_soft_limit,omitempty"`
}

type counters struct {
	cpu             float64
	heap, allocated uint64
	rssPeak         uint64
	goroutines      int
}

func processCounters() counters {
	samples := []metrics.Sample{
		{Name: "/memory/classes/heap/objects:bytes"},
		{Name: "/gc/heap/allocs:bytes"},
	}
	metrics.Read(samples)
	cpu, rssPeak := processUsage()
	return counters{cpu: cpu, rssPeak: rssPeak, heap: samples[0].Value.Uint64(),
		allocated: samples[1].Value.Uint64(), goroutines: runtime.NumGoroutine()}
}

func (r *Resources) delta(first, last counters) {
	r.CPUSeconds = max(0, last.cpu-first.cpu)
	r.AllocatedBytes = last.allocated - first.allocated
	r.RSSPeakBytes = last.rssPeak
}

type profiles struct {
	dir string
	cpu *os.File
}

func startProfiles(dir string) (profiles, error) {
	if dir == "" {
		return profiles{}, nil
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return profiles{}, err
	}
	output, err := os.OpenFile(filepath.Join(dir, "cpu.pprof"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return profiles{}, err
	}
	if err = pprof.StartCPUProfile(output); err != nil {
		_ = output.Close()
		return profiles{}, err
	}
	return profiles{dir: dir, cpu: output}, nil
}

func (p profiles) finish() ([]string, error) {
	if p.cpu == nil {
		return nil, nil
	}
	pprof.StopCPUProfile()
	if err := p.cpu.Close(); err != nil {
		return nil, err
	}
	names := []string{"cpu.pprof"}
	for _, name := range []string{"heap", "allocs", "goroutine"} {
		file := name + ".pprof"
		output, err := os.OpenFile(filepath.Join(p.dir, file), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, err
		}
		err = pprof.Lookup(name).WriteTo(output, 0)
		closeErr := output.Close()
		if err != nil {
			return nil, fmt.Errorf("write %s: %w", file, err)
		}
		if closeErr != nil {
			return nil, closeErr
		}
		names = append(names, file)
	}
	return names, nil
}
