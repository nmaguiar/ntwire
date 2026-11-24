package egressrouter

import "runtime/metrics"

// Budget at most a quarter of available memory for new sockets, assuming
// 256 KiB each for userspace buffers and kernel/transport overhead.
func machineBudget(active int) (int, string) {
	ceiling, reason := MaxConnections, "Shared process connection ceiling"
	constrain := func(n int64, why string) {
		if n < int64(ceiling) {
			ceiling = int(max(int64(0), n))
			reason = why
		}
	}
	mem, additionalFD := hostHeadroom()
	if mem == 0 {
		constrain(int64(active/2), "Memory pressure")
	} else if mem > 0 {
		constrain(int64(active)+mem/(4*256<<10), "Available memory")
	}
	if additionalFD >= 0 {
		constrain(int64(active)+additionalFD, "Available file descriptors")
	}
	samples := []metrics.Sample{{Name: "/gc/gomemlimit:bytes"}, {Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"}}
	metrics.Read(samples)
	used := samples[1].Value.Uint64() - samples[2].Value.Uint64()
	remaining := int64(samples[0].Value.Uint64()) - int64(used)
	constrain(int64(active)+max(int64(0), remaining)/(4*256<<10), "Go memory limit")
	return ceiling, reason
}
