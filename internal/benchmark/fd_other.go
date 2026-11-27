//go:build !linux

package benchmark

func openFDs() int        { return 0 }
func openFDLimit() uint64 { return 0 }
