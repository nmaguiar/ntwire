//go:build !linux

package benchmark

import "errors"

func (*fixture) startKernelClient(fixtureState) error {
	return errors.New("kernel WireGuard requires Linux")
}
