//go:build !linux && !darwin && !windows

package wstransport

import "errors"

func setUDPDontFragment(_ uintptr, _ bool) error {
	return errors.New("adaptive UDP fragmentation control is unavailable")
}
