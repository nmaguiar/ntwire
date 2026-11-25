package socks

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"slices"
	"time"
)

const (
	destinationOfferCommand = 0x80
	MaxDestinationOffers    = 8
)

func readOfferReply(r io.Reader) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return &ConnectError{Submitted: true, Err: err}
	}
	if header[0] != 5 || header[2] != 0 {
		return &ConnectError{Submitted: true}
	}
	_, _, _, err := readAddress(r, header[3])
	if err != nil || header[1] != 0 {
		return &ConnectError{Submitted: true, Code: header[1], Err: err}
	}
	return nil
}

// OfferDestination asks a capable native SOCKS tunnel to authorize a hostname
// and offer exact connection addresses on this same stream.
func OfferDestination(ctx context.Context, conn net.Conn, dst Destination) ([]netip.Addr, error) {
	if ip, err := dst.validate(); err != nil || ip.IsValid() {
		return nil, ErrInvalidDestination
	}
	if err := Negotiate(ctx, conn); err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	request := append([]byte{5, destinationOfferCommand, 0, socks5AtypDomain, byte(len(dst.Host))}, dst.Host...)
	request = binary.BigEndian.AppendUint16(request, dst.Port)
	if _, err := conn.Write(request); err != nil {
		return nil, &ConnectError{Submitted: true, Err: err}
	}
	if err := readOfferReply(conn); err != nil {
		return nil, err
	}
	var count [1]byte
	if _, err := io.ReadFull(conn, count[:]); err != nil || count[0] == 0 || count[0] > MaxDestinationOffers {
		return nil, &ConnectError{Submitted: true, Err: err}
	}
	addresses := make([]netip.Addr, 0, count[0])
	for range count[0] {
		var raw [16]byte
		if _, err := io.ReadFull(conn, raw[:]); err != nil {
			return nil, &ConnectError{Submitted: true, Err: err}
		}
		ip := netip.AddrFrom16(raw).Unmap()
		if ip.IsUnspecified() || slices.Contains(addresses, ip) {
			return nil, &ConnectError{Submitted: true}
		}
		addresses = append(addresses, ip)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return addresses, nil
}

// SelectDestination commits the offer once. The index refers to the ordered
// address list returned on this stream by OfferDestination.
func SelectDestination(ctx context.Context, conn net.Conn, index int) error {
	if index < 0 || index >= MaxDestinationOffers {
		return ErrInvalidDestination
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{byte(index)}); err != nil {
		return &ConnectError{Submitted: true, Err: err}
	}
	if err := readOfferReply(conn); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return conn.SetDeadline(time.Time{})
}

func (s *Server) serveDestinationOffer(ctx context.Context, in net.Conn, br *bufio.Reader, host string, ip netip.Addr, port uint16) {
	if s.allowDestinationBinding == nil {
		Reply(in, socks5RepCmdNotSupported)
		return
	}
	if !s.allowDestinationBinding(ctx) {
		Reply(in, socks5RepNotAllowed)
		return
	}
	if dst, err := wireDestination(host, ip, port); err != nil || dst.IP().IsValid() {
		Reply(in, socks5RepAtypNotSupported)
		return
	}
	setup, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	deadline, _ := setup.Deadline()
	_ = in.SetDeadline(deadline)
	dns, done := context.WithTimeout(setup, s.dnsTimeout)
	addresses, err := s.resolver.LookupNetIP(dns, "ip", host)
	done()
	if err != nil || len(addresses) == 0 {
		Reply(in, socks5RepHostUnreachable)
		return
	}
	if len(addresses) > 32 {
		Reply(in, socks5RepGeneralFailure)
		return
	}
	var offered [MaxDestinationOffers]netip.Addr
	n := 0
	for i, ip := range addresses {
		ip = ip.Unmap()
		_, result := s.filterDestinationProtocol(setup, host, "", ip, port, "tcp")
		if result != outcomeGranted || ip.Zone() != "" || ip.IsUnspecified() {
			// Preserve the ordinary SOCKS first-answer authorization gate.
			if i == 0 {
				Reply(in, socks5RepNotAllowed)
				return
			}
			continue
		}
		if !slices.Contains(offered[:n], ip) {
			if n == len(offered) {
				Reply(in, socks5RepGeneralFailure)
				return
			}
			offered[n] = ip
			n++
		}
	}
	if setup.Err() != nil || !s.allowDestinationBinding(ctx) {
		Reply(in, socks5RepNotAllowed)
		return
	}
	var frame [1 + MaxDestinationOffers*16]byte
	frame[0] = byte(n)
	for i, ip := range offered[:n] {
		raw := ip.As16()
		copy(frame[1+i*16:], raw[:])
	}
	Reply(in, socks5RepSucceeded)
	if _, err := in.Write(frame[:1+n*16]); err != nil {
		return
	}
	index, err := br.ReadByte()
	if err != nil {
		return
	}
	if int(index) >= n || setup.Err() != nil || !s.allowDestinationBinding(ctx) {
		Reply(in, socks5RepNotAllowed)
		return
	}
	out, result := s.connectDestination(setup, host, "", offered[index], port)
	if result != outcomeGranted {
		Reply(in, socks5ReplyCode(result))
		return
	}
	defer out.Close()
	if setup.Err() != nil || !s.allowDestinationBinding(ctx) {
		Reply(in, socks5RepNotAllowed)
		return
	}
	if _, result := s.filterDestinationProtocol(setup, host, "", offered[index], port, "tcp"); result != outcomeGranted {
		Reply(in, socks5ReplyCode(result))
		return
	}
	Reply(in, socks5RepSucceeded)
	_ = in.SetDeadline(time.Time{})
	s.relay(in, br, out)
}
