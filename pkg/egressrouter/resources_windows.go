package egressrouter

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var globalMemoryStatus = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")

func hostHeadroom() (int64, int64) {
	var status struct {
		Length, Load     uint32
		Total, Available uint64
		Other            [5]uint64
	}
	status.Length = uint32(unsafe.Sizeof(status))
	ok, _, _ := globalMemoryStatus.Call(uintptr(unsafe.Pointer(&status)))
	if ok == 0 {
		return -1, -1
	}
	return int64(status.Available), -1
}
