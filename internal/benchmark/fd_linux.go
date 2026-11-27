package benchmark

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func openFDs() int {
	dir, err := os.Open("/proc/self/fd")
	if err != nil {
		return 0
	}
	defer dir.Close()
	count := 0
	for {
		names, err := dir.Readdirnames(128)
		count += len(names)
		if err == io.EOF {
			return max(0, count-1) // Exclude the enumeration handle itself.
		}
		if err != nil {
			return 0
		}
	}
}

func openFDLimit() uint64 {
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		return 0
	}
	return limit.Cur
}
