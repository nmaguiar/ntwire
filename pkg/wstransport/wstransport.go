// Package wstransport defines validation and framing for the WebSocket
// WireGuard fallback. Each binary WebSocket message is exactly one datagram.
package wstransport

const maxDatagramSize = 65535

func ValidDatagram(b []byte) bool { return len(b) >= 16 && len(b) <= maxDatagramSize }

// Accept rejects control/oversized frames before they are passed to WireGuard.
func Accept(b []byte) ([]byte, bool) {
	if !ValidDatagram(b) {
		return nil, false
	}
	return b, true
}
