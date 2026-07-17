// Package wstransport defines framing for a future WebSocket fallback.
package wstransport

import "errors"

var ErrUnavailable = errors.New("WireGuard-over-WebSocket transport is not linked in this build")

func ValidDatagram(b []byte) bool { return len(b) >= 16 && len(b) <= 65535 }
