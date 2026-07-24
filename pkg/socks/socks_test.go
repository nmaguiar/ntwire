package socks

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

// stubUpstream is a fake "target" listener the test dialer connects to,
// standing in for the real destination that a CONNECT/relay would reach.
func stubUpstream(t *testing.T) (addr netip.AddrPort, close func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c) // echo
			}()
		}
	}()
	a := netip.MustParseAddrPort(l.Addr().String())
	return a, func() { l.Close() }
}

func testServer(t *testing.T, filter FilterConfig) *Server {
	t.Helper()
	s, err := New(Config{
		Filter: filter,
		Logger: slog.New(slog.DiscardHandler),
		Dial:   (&net.Dialer{}).DialContext,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSocks5ConnectAllowed(t *testing.T) {
	upstream, closeUpstream := stubUpstream(t)
	defer closeUpstream()

	s := testServer(t, FilterConfig{AllowAll: true})
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		s.ServeConn(context.Background(), server)
		close(done)
	}()

	// greeting: version 5, 1 method, NO_AUTH
	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	readN(t, client, 2, func(b []byte) {
		if b[0] != 0x05 || b[1] != 0x00 {
			t.Fatalf("unexpected method selection reply: %v", b)
		}
	})

	// CONNECT request to upstream's IPv4 addr
	req := []byte{0x05, socks5CmdConnect, 0x00, socks5AtypIPv4}
	ip4 := upstream.Addr().As4()
	req = append(req, ip4[:]...)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], upstream.Port())
	req = append(req, portBuf[:]...)
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}

	readN(t, client, 10, func(b []byte) {
		if b[1] != socks5RepSucceeded {
			t.Fatalf("expected success reply, got rep=%d", b[1])
		}
	})

	// relay works: write and read back the echo
	msg := []byte("hello")
	if _, err := client.Write(msg); err != nil {
		t.Fatal(err)
	}
	readN(t, client, len(msg), func(b []byte) {
		if string(b) != "hello" {
			t.Fatalf("echo mismatch: %q", b)
		}
	})

	client.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ServeConn did not return after client close")
	}
}

func TestSocks5ConnectDenied(t *testing.T) {
	upstream, closeUpstream := stubUpstream(t)
	defer closeUpstream()

	s := testServer(t, FilterConfig{}) // no filters => deny by default
	client, server := net.Pipe()
	go s.ServeConn(context.Background(), server)

	client.Write([]byte{0x05, 0x01, 0x00})
	readN(t, client, 2, nil)

	req := []byte{0x05, socks5CmdConnect, 0x00, socks5AtypIPv4}
	ip4 := upstream.Addr().As4()
	req = append(req, ip4[:]...)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], upstream.Port())
	req = append(req, portBuf[:]...)
	client.Write(req)

	readN(t, client, 10, func(b []byte) {
		if b[1] != socks5RepNotAllowed {
			t.Fatalf("expected not-allowed reply (0x02), got rep=%d", b[1])
		}
	})
}

func TestSocks5NoAuthRequired(t *testing.T) {
	s := testServer(t, FilterConfig{AllowAll: true})
	client, server := net.Pipe()
	go s.ServeConn(context.Background(), server)

	// offer only a bogus method (0x02 = username/password), never NO_AUTH
	client.Write([]byte{0x05, 0x01, 0x02})
	readN(t, client, 2, func(b []byte) {
		if b[0] != 0x05 || b[1] != socks5NoAcceptableMethods {
			t.Fatalf("expected refusal, got %v", b)
		}
	})
}

func TestSocks4Connect(t *testing.T) {
	upstream, closeUpstream := stubUpstream(t)
	defer closeUpstream()

	s := testServer(t, FilterConfig{AllowAll: true})
	client, server := net.Pipe()
	go s.ServeConn(context.Background(), server)

	req := []byte{0x04, socks4CmdConnect}
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], upstream.Port())
	req = append(req, portBuf[:]...)
	ip4 := upstream.Addr().As4()
	req = append(req, ip4[:]...)
	req = append(req, 0x00) // empty userid, null-terminated
	client.Write(req)

	readN(t, client, 8, func(b []byte) {
		if b[1] != socks4Granted {
			t.Fatalf("expected granted (0x5A), got 0x%02x", b[1])
		}
	})
}

func TestSocks4Denied(t *testing.T) {
	upstream, closeUpstream := stubUpstream(t)
	defer closeUpstream()

	s := testServer(t, FilterConfig{}) // deny by default
	client, server := net.Pipe()
	go s.ServeConn(context.Background(), server)

	req := []byte{0x04, socks4CmdConnect}
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], upstream.Port())
	req = append(req, portBuf[:]...)
	ip4 := upstream.Addr().As4()
	req = append(req, ip4[:]...)
	req = append(req, 0x00)
	client.Write(req)

	readN(t, client, 8, func(b []byte) {
		if b[1] != socks4Rejected {
			t.Fatalf("expected rejected (0x5B), got 0x%02x", b[1])
		}
	})
}

func TestSocks5UnsupportedCommandRejected(t *testing.T) {
	s := testServer(t, FilterConfig{AllowAll: true})
	client, server := net.Pipe()
	go s.ServeConn(context.Background(), server)

	client.Write([]byte{0x05, 0x01, 0x00})
	readN(t, client, 2, nil)

	// UDP ASSOCIATE (Stage 3, cross-cutting client/wgnet work; not
	// implemented by this package) must be cleanly rejected, not hang.
	req := []byte{0x05, socks5CmdUDP, 0x00, socks5AtypIPv4, 127, 0, 0, 1, 0, 0}
	client.Write(req)
	readN(t, client, 10, func(b []byte) {
		if b[1] != socks5RepCmdNotSupported {
			t.Fatalf("expected command-not-supported (0x07), got rep=%d", b[1])
		}
	})
}

// readSocks5Reply reads a full VER/REP/RSV/ATYP/ADDR/PORT reply, sizing the
// address field from ATYP (4 bytes for IPv4, 16 for IPv6) rather than
// assuming a fixed 10-byte frame -- net.Listen("tcp", ":0") is dual-stack on
// many systems, so a BIND listener's reported address is not guaranteed to
// be IPv4.
func readSocks5Reply(t *testing.T, r io.Reader) (rep byte, port uint16) {
	t.Helper()
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		t.Fatalf("read reply header: %v", err)
	}
	addrLen := 4
	if hdr[3] == socks5AtypIPv6 {
		addrLen = 16
	}
	rest := make([]byte, addrLen+2)
	if _, err := io.ReadFull(r, rest); err != nil {
		t.Fatalf("read reply address/port: %v", err)
	}
	return hdr[1], binary.BigEndian.Uint16(rest[addrLen:])
}

func TestSocks5Bind(t *testing.T) {
	s := testServer(t, FilterConfig{AllowAll: true})
	client, server := net.Pipe()
	go s.ServeConn(context.Background(), server)

	client.Write([]byte{0x05, 0x01, 0x00})
	readN(t, client, 2, nil)

	// BIND request naming a (filter-wise irrelevant, since AllowAll) DST.
	req := []byte{0x05, socks5CmdBind, 0x00, socks5AtypIPv4, 127, 0, 0, 1, 0, 0}
	client.Write(req)

	rep, boundPort := readSocks5Reply(t, client)
	if rep != socks5RepSucceeded {
		t.Fatalf("expected first BIND reply to succeed, got rep=%d", rep)
	}
	if boundPort == 0 {
		t.Fatal("expected a nonzero bound port in the first BIND reply")
	}

	peer, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(boundPort))))
	if err != nil {
		t.Fatalf("dialing the BIND listener: %v", err)
	}
	defer peer.Close()

	rep, _ = readSocks5Reply(t, client)
	if rep != socks5RepSucceeded {
		t.Fatalf("expected second BIND reply to succeed, got rep=%d", rep)
	}

	// Relay now runs between client and peer.
	msg := []byte("bind relay works")
	if _, err := peer.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatalf("relay = %q, want %q", got, msg)
	}
}

func TestSocks5BindDeniedByFilter(t *testing.T) {
	s := testServer(t, FilterConfig{}) // deny by default
	client, server := net.Pipe()
	go s.ServeConn(context.Background(), server)

	client.Write([]byte{0x05, 0x01, 0x00})
	readN(t, client, 2, nil)

	req := []byte{0x05, socks5CmdBind, 0x00, socks5AtypIPv4, 127, 0, 0, 1, 0, 0}
	client.Write(req)

	readN(t, client, 10, func(b []byte) {
		if b[1] != socks5RepNotAllowed {
			t.Fatalf("expected BIND to be denied by the filter (rep=0x02), got rep=%d", b[1])
		}
	})
}

func TestSocks4Bind(t *testing.T) {
	s := testServer(t, FilterConfig{AllowAll: true})
	client, server := net.Pipe()
	go s.ServeConn(context.Background(), server)

	req := []byte{0x04, socks4CmdBind, 0, 0, 127, 0, 0, 1, 0x00}
	client.Write(req)

	first := make([]byte, 8)
	if _, err := io.ReadFull(client, first); err != nil {
		t.Fatalf("first bind reply: %v", err)
	}
	if first[1] != socks4Granted {
		t.Fatalf("expected first BIND reply granted (0x5A), got 0x%02x", first[1])
	}
	boundPort := binary.BigEndian.Uint16(first[2:4])
	if boundPort == 0 {
		t.Fatal("expected a nonzero bound port in the first BIND reply")
	}

	peer, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(boundPort))))
	if err != nil {
		t.Fatalf("dialing the BIND listener: %v", err)
	}
	defer peer.Close()

	second := make([]byte, 8)
	if _, err := io.ReadFull(client, second); err != nil {
		t.Fatalf("second bind reply: %v", err)
	}
	if second[1] != socks4Granted {
		t.Fatalf("expected second BIND reply granted (0x5A), got 0x%02x", second[1])
	}
}

func readN(t *testing.T, r io.Reader, n int, check func([]byte)) {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	if check != nil {
		check(buf)
	}
}
