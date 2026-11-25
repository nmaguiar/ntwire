//go:build !linux && !darwin && !windows

package egressrouter

func hostHeadroom() (int64, int64) { return -1, -1 }
