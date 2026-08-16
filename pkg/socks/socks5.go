package socks

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
)

const (
	socks5Version = 0x05

	socks5NoAuth              = 0x00
	socks5NoAcceptableMethods = 0xFF

	socks5CmdConnect = 0x01
	socks5CmdBind    = 0x02
	socks5CmdUDP     = 0x03

	socks5AtypIPv4   = 0x01
	socks5AtypDomain = 0x03
	socks5AtypIPv6   = 0x04

	socks5RepSucceeded        = 0x00
	socks5RepGeneralFailure   = 0x01
	socks5RepNotAllowed       = 0x02
	socks5RepHostUnreachable  = 0x04
	socks5RepConnRefused      = 0x05
	socks5RepTTLExpired       = 0x06
	socks5RepCmdNotSupported  = 0x07
	socks5RepAtypNotSupported = 0x08
)

// serveSocks5 implements the SOCKS5 handshake and CONNECT command
// (upstream java-socks-proxy-server's Socks5Impl): NO_AUTH-only method
// negotiation (refuses any request that doesn't offer it -- there is no
// username/password support upstream either, matching that the ntwire
// session is already authenticated before this tunnel is reached), and
// IPv4/IPv6/domain address types. Version byte 0x05 was already consumed by
// ServeConn.
func (s *Server) serveSocks5(ctx context.Context, conn net.Conn, br *bufio.Reader) {
	nmethods, err := br.ReadByte()
	if err != nil {
		return
	}
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	noAuth := false
	for _, m := range methods {
		if m == socks5NoAuth {
			noAuth = true
			break
		}
	}
	if !noAuth {
		_, _ = conn.Write([]byte{socks5Version, socks5NoAcceptableMethods})
		return
	}
	if _, err := conn.Write([]byte{socks5Version, socks5NoAuth}); err != nil {
		return
	}

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return
	}
	ver, cmd, atyp := hdr[0], hdr[1], hdr[3]
	if ver != socks5Version {
		return
	}

	var hostname string
	var ip netip.Addr
	switch atyp {
	case socks5AtypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(br, b[:]); err != nil {
			return
		}
		ip = netip.AddrFrom4(b)
	case socks5AtypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(br, b[:]); err != nil {
			return
		}
		ip = netip.AddrFrom16(b)
	case socks5AtypDomain:
		l, err := br.ReadByte()
		if err != nil {
			return
		}
		buf := make([]byte, l)
		if _, err := io.ReadFull(br, buf); err != nil {
			return
		}
		hostname = string(buf)
	default:
		writeSocks5Reply(conn, socks5RepAtypNotSupported, netip.IPv4Unspecified(), 0)
		return
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(br, portBuf[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf[:])

	switch cmd {
	case socks5CmdConnect:
		out, o := s.connect(ctx, hostname, ip, port)
		if o != outcomeGranted {
			writeSocks5Reply(conn, socks5ReplyCode(o), netip.IPv4Unspecified(), 0)
			return
		}
		bindAddr, bindPort := localAddrParts(out)
		writeSocks5Reply(conn, socks5RepSucceeded, bindAddr, bindPort)
		s.relay(conn, br, out)
	case socks5CmdBind:
		if !s.allowBind {
			s.log.Warn("socks5 BIND denied by policy")
			writeSocks5Reply(conn, socks5RepCmdNotSupported, netip.IPv4Unspecified(), 0)
			return
		}
		s.doSocks5Bind(ctx, conn, br, hostname, ip, port)
	default:
		s.log.Debug("socks5: unsupported command", "command", cmd)
		writeSocks5Reply(conn, socks5RepCmdNotSupported, netip.IPv4Unspecified(), 0)
	}
}

// doSocks5Bind implements SOCKS5's BIND command. SOCKS5 has no dedicated
// bind() override upstream -- Socks5Impl inherits Socks4Impl.bind() verbatim
// and only overrides reply framing (bindReply) -- so this mirrors
// doSocks4Bind's two-reply flow with SOCKS5 addressing.
func (s *Server) doSocks5Bind(ctx context.Context, conn net.Conn, br *bufio.Reader, hostname string, dstIP netip.Addr, dstPort uint16) {
	if _, o := s.filterDestination(ctx, hostname, dstIP, dstPort); o != outcomeGranted {
		writeSocks5Reply(conn, socks5ReplyCode(o), netip.IPv4Unspecified(), 0)
		return
	}
	bl, o := s.startBind()
	if o != outcomeGranted {
		writeSocks5Reply(conn, socks5ReplyCode(o), netip.IPv4Unspecified(), 0)
		return
	}
	writeSocks5Reply(conn, socks5RepSucceeded, bl.addr, bl.port)

	peer, o := s.acceptBind(bl)
	if o != outcomeGranted {
		writeSocks5Reply(conn, socks5ReplyCode(o), netip.IPv4Unspecified(), 0)
		return
	}
	peerAddr, peerPort := remoteAddrParts(peer)
	writeSocks5Reply(conn, socks5RepSucceeded, peerAddr, peerPort)
	s.relay(conn, br, peer)
}

func socks5ReplyCode(o outcome) byte {
	switch o {
	case outcomeNotAllowed:
		return socks5RepNotAllowed
	case outcomeHostUnreachable:
		return socks5RepHostUnreachable
	case outcomeConnRefused:
		return socks5RepConnRefused
	case outcomeTTLExpired:
		return socks5RepTTLExpired
	case outcomeCommandNotSupported:
		return socks5RepCmdNotSupported
	case outcomeAddressTypeNotSupported:
		return socks5RepAtypNotSupported
	default:
		return socks5RepGeneralFailure
	}
}

func localAddrParts(c net.Conn) (netip.Addr, uint16) {
	if a, ok := c.LocalAddr().(*net.TCPAddr); ok {
		if ip, ok := netip.AddrFromSlice(a.IP); ok {
			return ip.Unmap(), uint16(a.Port)
		}
	}
	return netip.IPv4Unspecified(), 0
}

func writeSocks5Reply(w io.Writer, rep byte, addr netip.Addr, port uint16) {
	var buf []byte
	if addr.Is6() {
		buf = make([]byte, 4+16+2)
		buf[3] = socks5AtypIPv6
		a := addr.As16()
		copy(buf[4:20], a[:])
		binary.BigEndian.PutUint16(buf[20:22], port)
	} else {
		buf = make([]byte, 4+4+2)
		buf[3] = socks5AtypIPv4
		a := addr.As4()
		copy(buf[4:8], a[:])
		binary.BigEndian.PutUint16(buf[8:10], port)
	}
	buf[0] = socks5Version
	buf[1] = rep
	buf[2] = 0x00
	_, _ = w.Write(buf)
}
