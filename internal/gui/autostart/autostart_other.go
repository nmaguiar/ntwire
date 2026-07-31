//go:build !darwin && !linux && !windows

package autostart

import "errors"

var errUnsupported = errors.New("gui/autostart: unsupported platform")

// Enable, Disable and Enabled are unimplemented on platforms other than
// darwin, linux and windows.
func Enable(execPath string, args []string) error { return errUnsupported }
func Disable() error                              { return errUnsupported }
func Enabled() (bool, error)                      { return false, errUnsupported }
