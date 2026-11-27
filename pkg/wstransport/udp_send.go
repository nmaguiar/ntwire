package wstransport

import (
	"io"
	"net"
	"net/netip"

	"golang.org/x/net/ipv6"
)

type udpBatchWriter interface {
	WriteBatch([]ipv6.Message, int) (int, error)
}

func sendUDPBatch(socket *net.UDPConn, bufs [][]byte, dst netip.AddrPort) error {
	addr := net.UDPAddrFromAddrPort(dst)
	msgs := make([]ipv6.Message, len(bufs))
	for i, buf := range bufs {
		msgs[i] = ipv6.Message{Addr: addr, Buffers: net.Buffers{buf}}
	}
	_, err := writeUDPBatch(ipv6.NewPacketConn(socket), msgs)
	return err
}

func writeUDPBatch(writer udpBatchWriter, msgs []ipv6.Message) (sent int, err error) {
	for sent < len(msgs) {
		n, err := writer.WriteBatch(msgs[sent:], 0)
		// Linux sendmmsg returns -1 on syscall failure. A positive count,
		// including one returned with an error, is an accepted prefix.
		sent += max(n, 0)
		if err != nil {
			return sent, err
		}
		if n <= 0 {
			return sent, io.ErrNoProgress
		}
	}
	return sent, nil
}
