package socks

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

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
