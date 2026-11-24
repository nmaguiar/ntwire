package socks

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
)

// ClientRequest is a validated local SOCKS CONNECT or UDP ASSOCIATE request.
type ClientRequest struct {
	Destination Destination
	UDP         bool
	Source      netip.AddrPort
}

// Associate requests an upstream UDP relay. The TCP connection remains open
// for the association lifetime.
func Associate(ctx context.Context, conn net.Conn) (netip.AddrPort, error) {
	_, ip, port, err := exchange(ctx, conn, []byte{5, socks5CmdUDP, 0, 1, 0, 0, 0, 0, 0, 0})
	if err != nil {
		return netip.AddrPort{}, err
	}
	if !ip.IsValid() || port == 0 {
		return netip.AddrPort{}, errors.New("invalid SOCKS UDP relay endpoint")
	}
	return netip.AddrPortFrom(ip.Unmap(), port), nil
}

// ReplyBound announces a bound SOCKS UDP relay endpoint.
func ReplyBound(w net.Conn, addr netip.AddrPort) {
	writeSocks5Reply(w, socks5RepSucceeded, addr.Addr(), addr.Port())
}

// DatagramDestination validates a SOCKS UDP envelope without DNS resolution.
// The returned offset identifies the first payload byte.
func DatagramDestination(packet []byte) (Destination, int, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return Destination{}, 0, errors.New("invalid or fragmented SOCKS datagram")
	}
	offset, size := 4, 0
	switch packet[3] {
	case socks5AtypIPv4:
		size = 4
	case socks5AtypIPv6:
		size = 16
	case socks5AtypDomain:
		if len(packet) <= offset {
			return Destination{}, 0, io.ErrUnexpectedEOF
		}
		size = int(packet[offset])
		offset++
	default:
		return Destination{}, 0, errAddressType
	}
	end := offset + size
	if len(packet) < end+2 {
		return Destination{}, 0, io.ErrUnexpectedEOF
	}
	var host string
	var ip netip.Addr
	if packet[3] == socks5AtypDomain {
		host = string(packet[offset:end])
	} else {
		ip, _ = netip.AddrFromSlice(packet[offset:end])
	}
	port := binary.BigEndian.Uint16(packet[end:])
	dst, err := wireDestination(host, ip, port)
	return dst, end + 2, err
}

// DatagramFrame encodes a numeric SOCKS5 UDP source address and payload.
func DatagramFrame(address netip.AddrPort, payload []byte) []byte {
	ip := address.Addr().Unmap()
	atyp, size := byte(socks5AtypIPv6), 16
	if ip.Is4() {
		atyp, size = socks5AtypIPv4, 4
	}
	frame := make([]byte, 6+size+len(payload))
	frame[3] = atyp
	copy(frame[4:], ip.AsSlice())
	binary.BigEndian.PutUint16(frame[4+size:], address.Port())
	copy(frame[6+size:], payload)
	return frame
}
