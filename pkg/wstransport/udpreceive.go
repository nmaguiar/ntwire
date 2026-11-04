package wstransport

import (
	"errors"
	"log/slog"
	"net"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// UDP network errors can describe a previous datagram (for example an ICMP
// port-unreachable response), rather than a broken local socket. Keep them
// inside the bind: wireguard-go otherwise stops the receiver on non-temporary
// net.Errors, or after eleven consecutive temporary errors.
func recoverableUDPReadError(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && (ne.Timeout() || ne.Temporary()) {
		return true
	}
	for _, errno := range []syscall.Errno{
		syscall.EINTR, syscall.EAGAIN, syscall.ENOBUFS, syscall.ENOMEM,
		syscall.ECONNREFUSED, syscall.ECONNRESET,
		syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.ENETDOWN,
	} {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}

func resilientUDPReceive(receive conn.ReceiveFunc, stop <-chan struct{}, log *slog.Logger, socket string) conn.ReceiveFunc {
	if log == nil {
		log = slog.Default()
	}
	// ReceiveFuncs are called serially by their wireguard-go receive loop.
	// Keep log throttling across successful calls as well as within an outage.
	var lastLog time.Time
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		delay := 10 * time.Millisecond
		failures := 0
		loggedFailure := false
		for {
			select {
			case <-stop:
				return 0, net.ErrClosed
			default:
			}
			n, err := receive(bufs, sizes, eps)
			if err == nil {
				if loggedFailure {
					log.Info("WireGuard UDP receive recovered", "socket", socket, "failures", failures)
				}
				return n, nil
			}
			if errors.Is(err, net.ErrClosed) {
				return n, err
			}
			if !recoverableUDPReadError(err) {
				log.Error("WireGuard UDP receiver stopped", "socket", socket, "error", err)
				return n, err
			}
			failures++
			if lastLog.IsZero() || time.Since(lastLog) >= 30*time.Second {
				log.Warn("WireGuard UDP receive failed; retrying", "socket", socket, "error", err, "failures", failures)
				lastLog = time.Now()
				loggedFailure = true
			}
			timer := time.NewTimer(delay)
			select {
			case <-stop:
				timer.Stop()
				return 0, net.ErrClosed
			case <-timer.C:
			}
			delay = min(delay*2, time.Second)
		}
	}
}
