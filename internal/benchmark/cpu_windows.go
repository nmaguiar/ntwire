package benchmark

import "golang.org/x/sys/windows"

func processUsage() (cpuSeconds float64, rssPeakBytes uint64) {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &creation, &exit, &kernel, &user); err != nil {
		return 0, 0
	}
	k := uint64(kernel.HighDateTime)<<32 | uint64(kernel.LowDateTime)
	u := uint64(user.HighDateTime)<<32 | uint64(user.LowDateTime)
	return float64(k+u) / 1e7, 0 // FILETIME durations are in 100 ns ticks.
}
