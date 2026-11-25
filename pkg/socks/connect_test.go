package socks

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func clientRequestBytes(kind byte, address string, port uint16) []byte {
	b := []byte{5, 1, 0, 5, 1, 0, kind}
	if kind == socks5AtypDomain {
		b = append(b, byte(len(address)))
		b = append(b, address...)
	} else {
		b = append(b, netip.MustParseAddr(address).AsSlice()...)
	}
	return binary.BigEndian.AppendUint16(b, port)
}

func TestReadClientRequestDestination(t *testing.T) {
	for _, tc := range []struct {
		name, host, canonical string
		kind                  byte
		numericDomain         bool
	}{
		{"binary IPv4", "192.0.2.7", "192.0.2.7", 1, false},
		{"Chromium IPv4", "192.0.2.7", "192.0.2.7", 3, true},
		{"binary IPv6", "2001:db8::7", "2001:db8::7", 4, false},
		{"Chromium IPv6", "2001:DB8:0:0::7", "2001:db8::7", 3, true},
		{"binary mapped IPv6", "::ffff:192.0.2.7", "192.0.2.7", 4, false},
		{"domain mapped IPv6", "::FFFF:C000:0207", "192.0.2.7", 3, true},
		{"hostname", "Example.test.", "Example.test.", 3, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reply bytes.Buffer
			req, err := ReadClientRequest(&reply, bytes.NewReader(clientRequestBytes(tc.kind, tc.host, 443)), false)
			dst := req.Destination
			if err != nil || dst.CanonicalHost() != tc.canonical || dst.Port != 443 || dst.AddressType != tc.kind || dst.NumericDomain() != tc.numericDomain {
				t.Fatalf("request %+v, error %v", req, err)
			}
			if tc.kind == socks5AtypDomain && dst.Host != tc.host {
				t.Fatalf("original domain field changed to %q", dst.Host)
			}
		})
	}
	for _, tc := range []struct {
		host string
		port uint16
	}{
		{"127.0.00.1", 443}, {"127.1", 443}, {"2130706433", 443}, {"0x7f.0.0.1", 443},
		{"127.0.0.1.", 443}, {"300.1.1.1", 443}, {"2001:::1", 443}, {"fe80::1%en0", 443},
		{"[2001:db8::1]", 443}, {"name..test", 443}, {"a\x00.test", 443},
		{"", 443}, {"valid.test", 0}, {strings.Repeat("a", 255), 443},
	} {
		var reply bytes.Buffer
		if _, err := ReadClientRequest(&reply, bytes.NewReader(clientRequestBytes(3, tc.host, tc.port)), false); err == nil {
			t.Errorf("accepted invalid SOCKS destination %q:%d", tc.host, tc.port)
		}
	}
	for _, addr := range []string{"192.0.2.7:0", "192.0.2.7:65536", "[::1%en0]:443", "[valid.test]:443", "127.1:443", strings.Repeat("a", 256) + ":443"} {
		if _, err := ParseDestination(addr); err == nil {
			t.Errorf("accepted invalid HTTP destination %q", addr)
		}
	}
}

func TestSOCKS5UDPAssociateKeepsSourceValidation(t *testing.T) {
	for _, tc := range []struct {
		kind byte
		host string
		ok   bool
	}{
		{1, "0.0.0.0", true}, {4, "::", true}, {3, "127.0.0.1", false}, {3, "host.test", false},
	} {
		wire := clientRequestBytes(tc.kind, tc.host, 0)
		wire[4] = socks5CmdUDP
		var reply bytes.Buffer
		req, err := ReadClientRequest(&reply, bytes.NewReader(wire), true)
		if tc.ok != (err == nil && req.UDP && req.Source.Port() == 0) {
			t.Fatalf("source %q type %d: request %+v, error %v", tc.host, tc.kind, req, err)
		}
	}
}

func TestSOCKS5UDPRelayTerminationClosesControl(t *testing.T) {
	lifetime, endRelay := context.WithCancel(t.Context())
	defer endRelay()
	s, err := New(Config{UDPAssociate: func(context.Context, string, netip.Addr, uint16) (*UDPAssociation, bool) {
		return &UDPAssociation{Addr: netip.IPv4Unspecified(), Port: 1080, Lifetime: lifetime}, true
	}})
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	go s.ServeConn(t.Context(), server)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, err := Associate(ctx, client); err != nil {
		t.Fatal(err)
	}
	endRelay()
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	var reply [1]byte
	if _, err := client.Read(reply[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("control connection read after relay termination = %v, want EOF", err)
	}
}

func TestConnectPreservesAddressAndPolicyReply(t *testing.T) {
	for _, tc := range []struct {
		address string
		kind    byte
		want    string
	}{
		{"remote.invalid:443", 3, "remote.invalid"},
		{"[2001:db8::7]:443", 4, "2001:db8::7"},
		{"192.0.2.7:443", 1, "192.0.2.7"},
	} {
		t.Run(tc.address, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				var greeting [3]byte
				_, err := io.ReadFull(b, greeting[:])
				if err != nil {
					done <- err
					return
				}
				_, err = b.Write([]byte{5, 0})
				if err != nil {
					done <- err
					return
				}
				var header [4]byte
				_, err = io.ReadFull(b, header[:])
				if err != nil {
					done <- err
					return
				}
				host, ip, port, err := readAddress(b, header[3])
				if ip.IsValid() {
					host = ip.String()
				}
				if header[3] != tc.kind || host != tc.want || port != 443 {
					t.Errorf("forwarded type=%d host=%s port=%d", header[3], host, port)
				}
				if err != nil {
					done <- err
					return
				}
				// A compliant upstream may answer with a domain-form bound address.
				_, err = b.Write([]byte{5, 2, 0, 3, 3, 'a', 'b', 'c', 0, 0})
				done <- err
			}()
			var failure *ConnectError
			if err := Connect(ctx, a, tc.address); !errors.As(err, &failure) || failure.Code != 2 || !failure.Submitted {
				t.Fatalf("policy reply %v", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReadConnectRejectsUnsupportedCommands(t *testing.T) {
	for _, cmd := range []byte{2, 3} {
		client, server := net.Pipe()
		_ = client.SetDeadline(time.Now().Add(time.Second))
		_ = server.SetDeadline(time.Now().Add(time.Second))
		done := make(chan error, 1)
		go func() { defer server.Close(); _, err := ReadConnect(server, server); done <- err }()
		if _, err := client.Write([]byte{5, 1, 0}); err != nil {
			t.Fatal(err)
		}
		var accept [2]byte
		if _, err := io.ReadFull(client, accept[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write([]byte{5, cmd, 0, 1, 127, 0, 0, 1, 0, 80}); err != nil {
			t.Fatal(err)
		}
		var reply [10]byte
		if _, err := io.ReadFull(client, reply[:]); err != nil || reply[1] != 7 {
			t.Fatalf("command=%d reply=%v err=%v", cmd, reply, err)
		}
		client.Close()
		if err := <-done; err == nil {
			t.Fatal("unsupported command accepted")
		}
	}
}
