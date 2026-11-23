package egressattach

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
)

const maxPacket = 65507

// framedPackets preserves datagram boundaries over the pinned TLS channel.
type framedPackets struct {
	net.Conn
	writeMu sync.Mutex
	frame   []byte
}

func (c *framedPackets) Read(p []byte) (int, error) {
	var header [2]byte
	if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
		return 0, err
	}
	size := int(binary.BigEndian.Uint16(header[:]))
	if size == 0 || size > maxPacket {
		return 0, errors.New("invalid attachment datagram length")
	}
	if size > len(p) {
		return 0, io.ErrShortBuffer
	}
	return io.ReadFull(c.Conn, p[:size])
}
func (c *framedPackets) Write(p []byte) (int, error) {
	if len(p) == 0 || len(p) > maxPacket {
		return 0, errors.New("invalid attachment datagram length")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.frame = binary.BigEndian.AppendUint16(c.frame[:0], uint16(len(p)))
	c.frame = append(c.frame, p...)
	n, err := c.Conn.Write(c.frame)
	if err == nil && n != len(c.frame) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return max(0, n-2), err
	}
	return len(p), nil
}
func relayPackets(a, b net.Conn) {
	run := func(dst, src net.Conn) {
		defer dst.Close()
		defer src.Close()
		buf := make([]byte, maxPacket+1)
		for {
			n, err := src.Read(buf)
			if err != nil {
				return
			}
			if n > maxPacket || n == 0 {
				continue
			}
			if _, err = dst.Write(buf[:n]); err != nil {
				return
			}
		}
	}
	var wg sync.WaitGroup
	wg.Go(func() { run(a, b) })
	run(b, a)
	wg.Wait()
}
