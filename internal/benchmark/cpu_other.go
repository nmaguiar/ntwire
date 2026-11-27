//go:build !darwin && !linux && !windows

package benchmark

func processUsage() (cpuSeconds float64, rssPeakBytes uint64) { return 0, 0 }
