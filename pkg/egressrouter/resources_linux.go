package egressrouter

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func hostHeadroom() (int64, int64) {
	available := int64(-1)
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		for line := range strings.SplitSeq(string(data), "\n") {
			var kb int64
			if _, err := fmt.Sscanf(line, "MemAvailable: %d kB", &kb); err == nil {
				available = kb * 1024
				break
			}
		}
	}
	// Walk cgroup v2 ancestors because a parent can impose a tighter limit.
	root := "/sys/fs/cgroup"
	if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		for line := range strings.SplitSeq(string(data), "\n") {
			name, ok := strings.CutPrefix(line, "0::/")
			if !ok {
				continue
			}
			for dir := filepath.Join(root, filepath.Clean("/"+name)); ; dir = filepath.Dir(dir) {
				limit, hasLimit := readCgroupBytes(dir, "memory.max")
				if hasLimit {
					if used, ok := readCgroupBytes(dir, "memory.current"); ok {
						remaining := max(0, limit-used)
						if available < 0 || remaining < available {
							available = remaining
						}
					}
				}
				if dir == root {
					break
				}
			}
		}
	}
	return available, descriptorHeadroom("/proc/self/fd")
}

func readCgroupBytes(dir, key string) (int64, bool) {
	data, err := os.ReadFile(filepath.Join(dir, key))
	if err != nil {
		return 0, false
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	return value, err == nil && value >= 0
}
