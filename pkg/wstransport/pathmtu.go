package wstransport

import "encoding/binary"

// PathMTUProbe is an authenticated, bounded candidate-path probe. Target is
// the UDP payload size, including the five-byte ntwire control header.
type PathMTUProbe struct {
	Nonce  [pathProbeSize]byte
	Target uint16
}

const minPathMTUProbe uint16 = 1200

func nextPathMTUProbe(current uint16) uint16 {
	switch current {
	case 1200:
		return 1400
	case 1400:
		return MaxRelayDatagram
	default:
		return 0
	}
}

// EncodePathMTUProbe pads the control payload to Target. The echoed ack is
// deliberately small, so the request is never an amplification primitive.
func EncodePathMTUProbe(nonce [pathProbeSize]byte, target uint16) []byte {
	if target < minPathMTUProbe || target > MaxRelayDatagram {
		return nil
	}
	b := make([]byte, int(target)-controlHeaderLen)
	copy(b, nonce[:])
	binary.LittleEndian.PutUint16(b[pathProbeSize:], target)
	return b
}
func DecodePathMTUProbe(b []byte) (PathMTUProbe, bool) {
	if len(b) < pathProbeSize+2 {
		return PathMTUProbe{}, false
	}
	var p PathMTUProbe
	copy(p.Nonce[:], b)
	p.Target = binary.LittleEndian.Uint16(b[pathProbeSize:])
	return p, p.Target >= minPathMTUProbe && p.Target <= MaxRelayDatagram && len(b) == int(p.Target)-controlHeaderLen
}
func EncodePathMTUAck(nonce [pathProbeSize]byte, target uint16) []byte {
	b := make([]byte, pathProbeSize+2)
	copy(b, nonce[:])
	binary.LittleEndian.PutUint16(b[pathProbeSize:], target)
	return b
}
func DecodePathMTUAck(b []byte) (PathMTUProbe, bool) {
	if len(b) != pathProbeSize+2 {
		return PathMTUProbe{}, false
	}
	var p PathMTUProbe
	copy(p.Nonce[:], b)
	p.Target = binary.LittleEndian.Uint16(b[pathProbeSize:])
	return p, p.Target >= minPathMTUProbe && p.Target <= MaxRelayDatagram
}
