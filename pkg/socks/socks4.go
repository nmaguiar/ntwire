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
	socks4Version = 0x04

	socks4CmdConnect = 0x01
	socks4CmdBind    = 0x02

	socks4Granted  = 0x5A
	socks4Rejected = 0x5B
)

// serveSocks4 implements the SOCKS4 handshake (upstream java-socks-proxy-server's
// Socks4Impl): no SOCKS4a domain-name extension, no authentication, a
// null-terminated userid field that is read and discarded. Version byte 0x04
// was already consumed by ServeConn.
func (s *Server) serveSocks4(ctx context.Context, conn net.Conn, br *bufio.Reader) {
	cmd, err := br.ReadByte()
	if err != nil {
		return
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(br, portBuf[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf[:])
	var ipBuf [4]byte
	if _, err := io.ReadFull(br, ipBuf[:]); err != nil {
		return
	}
	if err := skipCString(br); err != nil { // userid
		return
	}

	ip := netip.AddrFrom4(ipBuf)
	switch cmd {
	case socks4CmdConnect:
		out, o := s.connect(ctx, "", ip, port)
		if o != outcomeGranted {
			writeSocks4Reply(conn, socks4Rejected, port, ipBuf)
			return
		}
		writeSocks4Reply(conn, socks4Granted, port, ipBuf)
		s.relay(conn, br, out)
	case socks4CmdBind:
		s.doSocks4Bind(ctx, conn, br, ip, port, ipBuf)
	default:
		s.log.Debug("socks4: unsupported command", "command", cmd)
		writeSocks4Reply(conn, socks4Rejected, port, ipBuf)
	}
}

// doSocks4Bind implements SOCKS4's BIND command (upstream Socks4Impl.bind(),
// reused as-is by SOCKS5): a two-reply handshake around a single accepted
// peer. The first reply announces the ephemeral listener's port; the second,
// sent once a peer connects, announces that peer's address.
func (s *Server) doSocks4Bind(ctx context.Context, conn net.Conn, br *bufio.Reader, dstIP netip.Addr, dstPort uint16, reqIP [4]byte) {
	if _, o := s.filterDestination(ctx, "", dstIP, dstPort); o != outcomeGranted {
		writeSocks4Reply(conn, socks4Rejected, dstPort, reqIP)
		return
	}
	bl, o := s.startBind()
	if o != outcomeGranted {
		writeSocks4Reply(conn, socks4Rejected, dstPort, reqIP)
		return
	}
	var localIP [4]byte
	if bl.addr.Is4() {
		localIP = bl.addr.As4()
	}
	writeSocks4Reply(conn, socks4Granted, bl.port, localIP)

	peer, o := s.acceptBind(bl)
	if o != outcomeGranted {
		writeSocks4Reply(conn, socks4Rejected, dstPort, reqIP)
		return
	}
	peerAddr, peerPort := remoteAddrParts(peer)
	var peerIP [4]byte
	if peerAddr.Is4() {
		peerIP = peerAddr.As4()
	}
	writeSocks4Reply(conn, socks4Granted, peerPort, peerIP)
	s.relay(conn, br, peer)
}

func writeSocks4Reply(w io.Writer, code byte, port uint16, ip [4]byte) {
	reply := [8]byte{0, code, byte(port >> 8), byte(port), ip[0], ip[1], ip[2], ip[3]}
	_, _ = w.Write(reply[:])
}

func skipCString(br *bufio.Reader) error {
	for {
		b, err := br.ReadByte()
		if err != nil {
			return err
		}
		if b == 0 {
			return nil
		}
	}
}
