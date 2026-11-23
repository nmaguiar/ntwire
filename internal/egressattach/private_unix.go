//go:build darwin || linux

package egressattach

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func restrict(path string, directory bool) error {
	if err := verifyPrivate(path, directory); err != nil {
		return err
	}
	return nil
}
func verifyPrivate(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() || info.Mode().Perm()&0077 != 0 ||
		directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
		return errors.New("egress attachment path must be private and owned by the current user")
	}
	return nil
}
func lockFile(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) }
