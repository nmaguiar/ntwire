//go:build darwin || linux

package benchmark

import (
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

func processUsage() (cpuSeconds float64, rssPeakBytes uint64) {
	var usage unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err != nil {
		return 0, 0
	}
	rssPeakBytes = uint64(max(usage.Maxrss, 0))
	if runtime.GOOS == "linux" {
		rssPeakBytes *= 1024 // Linux reports KiB. Darwin reports bytes.
	}
	return time.Duration(usage.Utime.Nano() + usage.Stime.Nano()).Seconds(), rssPeakBytes
}
