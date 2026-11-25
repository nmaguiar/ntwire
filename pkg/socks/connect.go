package socks

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"
)

var errAddressType = errors.New("unsupported SOCKS address type")

// Address validates a TCP destination without resolving it.
func Address(host string, port uint16) (string, error) {
	if port == 0 || len(host) == 0 || len(host) > 255 {
		return "", errors.New("invalid destination")
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.Zone() == "" {
		return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), nil
	}
	for _, c := range host {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return "", errors.New("invalid destination hostname")
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func readAddress(r io.Reader, atyp byte) (string, netip.Addr, uint16, error) {
	var buf [255]byte
	var host string
	var ip netip.Addr
	switch atyp {
	case socks5AtypIPv4:
		if _, err := io.ReadFull(r, buf[:4]); err != nil {
			return "", ip, 0, err
		}
		ip = netip.AddrFrom4([4]byte(buf[:4]))
	case socks5AtypIPv6:
		if _, err := io.ReadFull(r, buf[:16]); err != nil {
			return "", ip, 0, err
		}
		ip = netip.AddrFrom16([16]byte(buf[:16]))
	case socks5AtypDomain:
		if _, err := io.ReadFull(r, buf[:1]); err != nil {
			return "", ip, 0, err
		}
		n := int(buf[0])
		if _, err := io.ReadFull(r, buf[:n]); err != nil {
			return "", ip, 0, err
		}
		host = string(buf[:n])
	default:
		return "", ip, 0, errAddressType
	}
	_, err := io.ReadFull(r, buf[:2])
	return host, ip, binary.BigEndian.Uint16(buf[:2]), err
}

// readRequest runs after the version byte has been consumed.
func readRequest(w io.Writer, r io.Reader, strict bool) (byte, string, netip.Addr, uint16, error) {
	var buf [255]byte
	var ip netip.Addr
	if _, err := io.ReadFull(r, buf[:1]); err != nil {
		return 0, "", ip, 0, err
	}
	methods := buf[:int(buf[0])]
	if _, err := io.ReadFull(r, methods); err != nil {
		return 0, "", ip, 0, err
	}
	method := byte(socks5NoAcceptableMethods)
	for _, offered := range methods {
		if offered == socks5NoAuth {
			method = socks5NoAuth
			break
		}
	}
	if _, err := w.Write([]byte{socks5Version, method}); err != nil {
		return 0, "", ip, 0, err
	}
	if method != socks5NoAuth {
		return 0, "", ip, 0, errors.New("no acceptable SOCKS authentication method")
	}
	if _, err := io.ReadFull(r, buf[:4]); err != nil {
		return 0, "", ip, 0, err
	}
	if buf[0] != socks5Version || (strict || buf[1] == destinationOfferCommand) && buf[2] != 0 {
		return 0, "", ip, 0, errors.New("invalid SOCKS request")
	}
	host, ip, port, err := readAddress(r, buf[3])
	if errors.Is(err, errAddressType) {
		Reply(w, socks5RepAtypNotSupported)
	}
	return buf[1], host, ip, port, err
}

// ReadConnect negotiates only SOCKS5 CONNECT. The caller owns buffering and deadlines.
func ReadConnect(w io.Writer, r io.Reader) (string, error) {
	req, err := ReadClientRequest(w, r, false)
	if err != nil {
		return "", err
	}
	if req.Destination.NumericDomain() {
		// A string-only caller cannot preserve the requested address type.
		Reply(w, socks5RepAtypNotSupported)
		return "", errAddressType
	}
	return net.JoinHostPort(req.Destination.Host, strconv.Itoa(int(req.Destination.Port))), nil
}

// ReadClientRequest accepts UDP ASSOCIATE only when explicitly enabled.
func ReadClientRequest(w io.Writer, r io.Reader, allowUDP bool) (ClientRequest, error) {
	var version [1]byte
	if _, err := io.ReadFull(r, version[:]); err != nil {
		return ClientRequest{}, err
	}
	if version[0] == socks4Version {
		// Consume the bounded SOCKS4 header and user ID before rejecting it,
		// so TCP does not reset the connection with unread request bytes.
		var header [7]byte
		if _, err := io.ReadFull(r, header[:]); err == nil {
			for range 256 {
				if _, err = io.ReadFull(r, version[:]); err != nil || version[0] == 0 {
					break
				}
			}
			writeSocks4Reply(w, socks4Rejected, 0, [4]byte{})
		}
		return ClientRequest{}, errors.New("SOCKS4 unsupported")
	}
	if version[0] != socks5Version {
		return ClientRequest{}, errors.New("SOCKS5 required")
	}
	cmd, host, ip, port, err := readRequest(w, r, true)
	if err != nil {
		return ClientRequest{}, err
	}
	if cmd == socks5CmdUDP && allowUDP {
		if !ip.IsValid() {
			Reply(w, socks5RepAtypNotSupported)
			return ClientRequest{}, errors.New("UDP source must be a numeric address")
		}
		return ClientRequest{UDP: true, Source: netip.AddrPortFrom(ip.Unmap(), port)}, nil
	}
	if cmd != socks5CmdConnect {
		Reply(w, socks5RepCmdNotSupported)
		return ClientRequest{}, errors.New("SOCKS command unsupported")
	}
	dst, err := wireDestination(host, ip, port)
	if err != nil {
		Reply(w, socks5RepGeneralFailure)
	}
	return ClientRequest{Destination: dst}, err
}

// Reply writes a SOCKS5 reply with an unspecified bound address.
func Reply(w io.Writer, code byte) {
	writeSocks5Reply(w, code, netip.IPv4Unspecified(), 0)
}

// ConnectError describes an upstream SOCKS exchange without leaking the destination.
type ConnectError struct {
	Code      byte
	Submitted bool
	Auth      bool
	Retryable bool // positively identified I/O failure during method negotiation
	Err       error
}

func (e *ConnectError) Error() string { return "upstream SOCKS5 setup failed" }
func (e *ConnectError) Unwrap() error { return e.Err }

// Connect performs a no-auth SOCKS5 CONNECT over an already-open stream.
// The caller keeps ownership of conn and its lifetime after the handshake.
func Connect(ctx context.Context, conn net.Conn, address string) error {
	dst, err := ParseDestination(address)
	if err != nil {
		return err
	}
	return ConnectDestination(ctx, conn, dst)
}

// ConnectDestination preserves the wire encoding. Callers must establish
// upstream support before forwarding a domain-form numeric destination.
func ConnectDestination(ctx context.Context, conn net.Conn, dst Destination) error {
	ip, err := dst.validate()
	if err != nil {
		return ErrInvalidDestination
	}
	var request []byte
	if ip.IsValid() && dst.AddressType != socks5AtypDomain {
		atyp := byte(socks5AtypIPv6)
		if ip.Is4() {
			atyp = socks5AtypIPv4
		}
		request = make([]byte, 0, 4+ip.BitLen()/8+2)
		request = append(request, socks5Version, socks5CmdConnect, 0, atyp)
		request = append(request, ip.AsSlice()...)
	} else {
		request = make([]byte, 0, 5+len(dst.Host)+2)
		request = append(request, socks5Version, socks5CmdConnect, 0, socks5AtypDomain, byte(len(dst.Host)))
		request = append(request, dst.Host...)
	}
	request = binary.BigEndian.AppendUint16(request, dst.Port)
	_, _, _, err = exchange(ctx, conn, request)
	return err
}

func exchange(ctx context.Context, conn net.Conn, request []byte) (string, netip.Addr, uint16, error) {
	if err := Negotiate(ctx, conn); err != nil {
		return "", netip.Addr{}, 0, err
	}
	return command(ctx, conn, request)
}

// Negotiate selects no-authentication without sending a destination.
func Negotiate(ctx context.Context, conn net.Conn) error {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	var reply [2]byte
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return &ConnectError{Err: err}
	}
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		// An unclassified close can be a denied virtual tunnel grant.
		var ne net.Error
		return &ConnectError{Err: err, Retryable: errors.As(err, &ne) && ne.Timeout()}
	}
	if reply[0] != 5 {
		return &ConnectError{}
	}
	if reply[1] != 0 {
		return &ConnectError{Auth: true}
	}
	return conn.SetDeadline(time.Time{})
}

func command(ctx context.Context, conn net.Conn, request []byte) (string, netip.Addr, uint16, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	var reply [4]byte
	if err := ctx.Err(); err != nil {
		return "", netip.Addr{}, 0, &ConnectError{Err: err, Retryable: true}
	}
	if _, err := conn.Write(request); err != nil {
		return "", netip.Addr{}, 0, &ConnectError{Submitted: true, Err: err}
	}
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return "", netip.Addr{}, 0, &ConnectError{Submitted: true, Err: err}
	}
	if reply[0] != 5 || reply[2] != 0 {
		return "", netip.Addr{}, 0, &ConnectError{Submitted: true}
	}
	host, ip, port, err := readAddress(conn, reply[3])
	if err != nil || reply[1] != 0 {
		return "", netip.Addr{}, 0, &ConnectError{Submitted: true, Code: reply[1], Err: err}
	}
	if err := ctx.Err(); err != nil {
		return "", netip.Addr{}, 0, &ConnectError{Submitted: true, Err: err}
	}
	return host, ip, port, conn.SetDeadline(time.Time{})
}
