//go:build linux || darwin

package egressrouter

import (
	"os"

	"golang.org/x/sys/unix"
)

func descriptorHeadroom(dir string) int64 {
	var limit unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_NOFILE, &limit) != nil {
		return -1
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return -1
	}
	// Reserve 32 descriptors for control traffic and two for each proxy flow.
	return max(0, (int64(min(limit.Cur, uint64(1<<40)))-int64(len(entries))-32)/2)
}
