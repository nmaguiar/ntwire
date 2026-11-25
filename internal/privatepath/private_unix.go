//go:build darwin || linux

package privatepath

import (
	"errors"
	"os"
	"syscall"
)

func Restrict(path string, directory bool) error {
	if err := Verify(path, directory); err != nil {
		return err
	}
	return nil
}
func Verify(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() || info.Mode().Perm()&0077 != 0 ||
		directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
		return errors.New("path must be private and owned by the current user")
	}
	return nil
}
