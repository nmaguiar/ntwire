package wstransport

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

type udpReadTestError struct {
	temporary bool
	timeout   bool
}

func (e udpReadTestError) Error() string   { return "UDP read test error" }
func (e udpReadTestError) Temporary() bool { return e.temporary }
func (e udpReadTestError) Timeout() bool   { return e.timeout }

func TestUDPReceive_RecoversAfterRepeatedNetworkErrors(t *testing.T) {
	receiver := NewUDPBind(0, nil)
	defer receiver.Close()
	fns, port, err := receiver.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	sender := NewUDPBind(0, nil)
	defer sender.Close()
	if _, _, err := sender.Open(0); err != nil {
		t.Fatal(err)
	}
	ep, err := sender.ParseEndpoint("127.0.0.1:" + strconv.Itoa(int(port)))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("UDP still receiving")
	if err := sender.Send([][]byte{want}, ep); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	attempts := 0
	receive := resilientUDPReceive(func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		attempts++
		if attempts <= 12 { // Exceeds wireguard-go's consecutive-error limit.
			return 0, &net.OpError{Op: "read", Net: "udp", Err: syscall.ECONNREFUSED}
		}
		return fns[0](bufs, sizes, eps)
	}, receiver.receiveStop, log, "ipv4")
	// Bound the real socket read if retrying or delivery regresses.
	if err := receiver.ipv4.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	timeout := time.AfterFunc(15*time.Second, func() { receiver.Close() })
	defer timeout.Stop()
	bufs := [][]byte{make([]byte, 128)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	n, err := receive(bufs, sizes, eps)
	if err != nil || n != 1 || !bytes.Equal(bufs[0][:sizes[0]], want) || eps[0] == nil {
		t.Fatalf("receive after errors: n=%d err=%v sizes=%v endpoints=%v", n, err, sizes, eps)
	}
	if attempts != 13 {
		t.Fatalf("attempts = %d, want 13", attempts)
	}
	if strings.Count(logs.String(), "receive failed; retrying") != 1 || !strings.Contains(logs.String(), "receive recovered") {
		t.Fatalf("expected rate-limited failure and recovery logs: %s", &logs)
	}
}

func TestUDPReceive_CloseInterruptsRetryAndReopenKeepsOldReceiverClosed(t *testing.T) {
	b := NewUDPBind(0, nil)
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	failed := make(chan struct{})
	receive := resilientUDPReceive(func([][]byte, []int, []conn.Endpoint) (int, error) {
		select {
		case <-failed:
		default:
			close(failed)
		}
		return 0, syscall.ENOBUFS
	}, b.receiveStop, nil, "ipv4")
	done := make(chan error, 1)
	go func() { _, err := receive(nil, nil, nil); done <- err }()
	<-failed
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("close error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt retry")
	}
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	if _, err := receive(nil, nil, nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("old receiver revived after reopen: %v", err)
	}
}

func TestUDPReceive_TerminalErrorIsLoggedAndReturned(t *testing.T) {
	var logs bytes.Buffer
	want := &net.OpError{Op: "read", Net: "udp", Err: syscall.EBADF}
	attempts := 0
	receive := resilientUDPReceive(func([][]byte, []int, []conn.Endpoint) (int, error) {
		attempts++
		return 0, want
	}, make(chan struct{}), slog.New(slog.NewTextHandler(&logs, nil)), "ipv4")
	if _, err := receive(nil, nil, nil); err != want || attempts != 1 {
		t.Fatalf("terminal error = %v, attempts = %d", err, attempts)
	}
	if !strings.Contains(logs.String(), "WireGuard UDP receiver stopped") {
		t.Fatalf("missing terminal diagnostic: %s", &logs)
	}
}

func TestRecoverableUDPReadError(t *testing.T) {
	for _, err := range []error{udpReadTestError{temporary: true}, udpReadTestError{timeout: true}} {
		if !recoverableUDPReadError(fmt.Errorf("wrapped: %w", err)) {
			t.Errorf("temporary/timeout error classified as terminal: %v", err)
		}
	}
	for _, errno := range []syscall.Errno{syscall.EINTR, syscall.EAGAIN, syscall.ENOBUFS, syscall.ENOMEM, syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.ENETDOWN} {
		t.Run(errno.Error(), func(t *testing.T) {
			if !recoverableUDPReadError(fmt.Errorf("wrapped: %w", &net.OpError{Op: "read", Net: "udp", Err: errno})) {
				t.Fatal("network/resource error classified as terminal")
			}
		})
	}
	for _, err := range []error{net.ErrClosed, syscall.EBADF, errors.New("invalid receive batch")} {
		if recoverableUDPReadError(err) {
			t.Errorf("terminal error classified as recoverable: %v", err)
		}
	}
}
