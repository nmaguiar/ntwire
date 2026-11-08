//go:build linux

package tcptune

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// apply sets each requested option independently, so one rejected value
// (for example an unloaded congestion module) does not suppress the other.
func apply(fd uintptr, o Options) error {
	var errs []error
	if o.Congestion != "" {
		if err := unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, o.Congestion); err != nil {
			errs = append(errs, fmt.Errorf("TCP_CONGESTION %q: %w", o.Congestion, err))
		}
	}
	if o.NotSentLowat > 0 {
		if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, o.NotSentLowat); err != nil {
			errs = append(errs, fmt.Errorf("TCP_NOTSENT_LOWAT %d: %w", o.NotSentLowat, err))
		}
	}
	return errors.Join(errs...)
}
