package socks

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"testing"
	"time"
)

// fuzzConn is a finite in-memory net.Conn. It prevents fuzz inputs from
// reaching the host network while still exercising the exact ServeConn parser
// entry point.
type fuzzConn struct{ *bytes.Reader }

func (c fuzzConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c fuzzConn) Close() error                     { return nil }
func (c fuzzConn) LocalAddr() net.Addr              { return fuzzAddr("local") }
func (c fuzzConn) RemoteAddr() net.Addr             { return fuzzAddr("remote") }
func (c fuzzConn) SetDeadline(time.Time) error      { return nil }
func (c fuzzConn) SetReadDeadline(time.Time) error  { return nil }
func (c fuzzConn) SetWriteDeadline(time.Time) error { return nil }
func (c fuzzConn) Read(p []byte) (int, error)       { return c.Reader.Read(p) }

type fuzzAddr string

func (a fuzzAddr) Network() string { return "fuzz" }
func (a fuzzAddr) String() string  { return string(a) }

func FuzzServeConn(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x05, 0x01, 0x00})
	f.Add([]byte{0x04, 0x01, 0, 80, 127, 0, 0, 1, 0})
	f.Fuzz(func(t *testing.T, input []byte) {
		s, err := New(Config{
			Filter: FilterConfig{},
			Logger: slog.New(slog.DiscardHandler),
			Resolver: &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("network disabled during fuzzing")
			}},
			Dial: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("network disabled during fuzzing")
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		// The finite reader guarantees EOF for partial frames; no fuzz case can
		// wait for peer input indefinitely.
		s.ServeConn(context.Background(), fuzzConn{bytes.NewReader(input)})
	})
}
