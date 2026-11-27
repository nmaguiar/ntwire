package localproxy

import (
	"io"
	"net"
	"sync/atomic"
)

const streamBufferSize = 32 << 10

// Cache at most 2 MiB across counted streams. Outstanding copies own their
// buffers and never wait for a cache slot.
var streamBuffers = make(chan *[streamBufferSize]byte, 64)

// CopyCounted forwards a stream and counts successful writes as they happen.
// Without a counter, use io.Copy so socket-to-socket fast paths stay available.
func CopyCounted(dst io.Writer, src io.Reader, count *atomic.Uint64) (int64, error) {
	if count == nil {
		return io.Copy(dst, src)
	}
	writer := countingWriter{Writer: dst, bytes: count}
	if tcp, ok := src.(*net.TCPConn); ok {
		// TCPConn.WriteTo cannot splice into a counting writer and would
		// allocate its own copy buffer. Use the same Read/Write path here.
		src = struct{ io.Reader }{tcp}
	} else if from, ok := src.(io.WriterTo); ok {
		return from.WriteTo(writer)
	}
	var buf *[streamBufferSize]byte
	select {
	case buf = <-streamBuffers:
	default:
		buf = new([streamBufferSize]byte)
	}
	n, err := io.CopyBuffer(writer, src, buf[:])
	// A later copy can serve a different connection or principal.
	clear(buf[:])
	select {
	case streamBuffers <- buf:
	default:
	}
	return n, err
}

type countingWriter struct {
	io.Writer
	bytes *atomic.Uint64
}

func (w countingWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if n > 0 {
		w.bytes.Add(uint64(n))
	}
	return n, err
}
