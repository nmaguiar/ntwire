package wstransport

import (
	"context"
	"encoding/binary"
	"io"
	"sync"
)

// FramedLink carries one datagram per two-byte length-prefixed record. Its
// transport writer is responsible for bounded I/O and flushing.
type FramedLink struct {
	ctx    context.Context
	cancel context.CancelFunc
	reader io.ReadCloser
	writer io.WriteCloser
	ready  chan struct{}
	close  sync.Once
	max    int
	send   []byte // only the bind's writer goroutine uses this
}

func NewFramedLink(ctx context.Context, reader io.ReadCloser, writer io.WriteCloser, max int) *FramedLink {
	ctx, cancel := context.WithCancel(ctx)
	return &FramedLink{ctx: ctx, cancel: cancel, reader: reader, writer: writer, ready: make(chan struct{}), max: max, send: make([]byte, max+2)}
}

func (l *FramedLink) Ready()                   { close(l.ready) }
func (l *FramedLink) Context() context.Context { return l.ctx }
func (l *FramedLink) Close() error {
	l.close.Do(func() {
		l.cancel()
		_ = l.reader.Close()
		_ = l.writer.Close()
	})
	return nil
}

func (l *FramedLink) SendDatagram(data []byte) error {
	if len(data) == 0 || len(data) > l.max {
		return ErrCarrierDatagram
	}
	select {
	case <-l.ready:
	case <-l.ctx.Done():
		return l.ctx.Err()
	}
	binary.BigEndian.PutUint16(l.send, uint16(len(data)))
	copy(l.send[2:], data)
	n, err := l.writer.Write(l.send[:2+len(data)])
	if err == nil && n != 2+len(data) {
		return io.ErrShortWrite
	}
	return err
}

func (l *FramedLink) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-l.ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return readCarrierFrame(l.reader, l.max)
}

func readCarrierFrame(r io.Reader, max int) ([]byte, error) {
	var length [2]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(length[:]))
	if n == 0 || n > max {
		return nil, ErrCarrierDatagram
	}
	data := make([]byte, n)
	_, err := io.ReadFull(r, data)
	return data, err
}
