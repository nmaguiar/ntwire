package socks

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
)

// ClientRequest is a validated local SOCKS CONNECT or UDP ASSOCIATE request.
type ClientRequest struct {
	Address string
	UDP     bool
	Source  netip.AddrPort
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
func DatagramDestination(packet []byte) (string, uint16, int, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return "", 0, 0, errors.New("invalid or fragmented SOCKS datagram")
	}
	r := bytes.NewReader(packet[4:])
	host, ip, port, err := readAddress(r, packet[3])
	if err != nil {
		return "", 0, 0, err
	}
	if ip.IsValid() {
		host = ip.String()
	} else if _, err := netip.ParseAddr(host); err == nil {
		return "", 0, 0, errors.New("numeric address requires a numeric SOCKS address type")
	}
	if _, err := Address(host, port); err != nil {
		return "", 0, 0, err
	}
	return host, port, len(packet) - r.Len(), nil
}
