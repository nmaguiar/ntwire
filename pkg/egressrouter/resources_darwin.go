package egressrouter

import "golang.org/x/sys/unix"

func hostHeadroom() (int64, int64) {
	fds := descriptorHeadroom("/dev/fd")
	pressure, err := unix.SysctlUint32("kern.memorystatus_vm_pressure_level")
	if err == nil && pressure >= 2 {
		return 0, fds
	}
	total, err := unix.SysctlUint64("hw.memsize")
	if err != nil {
		return -1, fds
	}
	// Bound new allocations conservatively on macOS, which reports pressure
	// independently of reclaimable cache and compressed memory.
	return int64(total / 8), fds
}
