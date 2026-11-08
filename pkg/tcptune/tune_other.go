//go:build !linux

package tcptune

import "errors"

func apply(uintptr, Options) error {
	return errors.New("TCP tuning is supported only on Linux")
}
