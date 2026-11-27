package localproxy

import (
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCopyCounted_RecordsWritesBeforeCopyCompletes(t *testing.T) {
	var count atomic.Uint64
	src := &streamTestReader{Reader: strings.NewReader("abcdef"), beforeRead: func() {
		if got := count.Load(); got != 3 {
			t.Fatalf("live byte count = %d, want 3", got)
		}
	}}
	n, err := CopyCounted(io.Discard, src, &count)
	if err != nil || n != 6 || count.Load() != 6 {
		t.Fatalf("copy = (%d, %v), counter = %d", n, err, count.Load())
	}
}

func TestCopyCounted_RecordsPartialWritesOnError(t *testing.T) {
	var count atomic.Uint64
	writeErr := errors.New("destination stopped accepting writes")
	src := struct{ io.Reader }{strings.NewReader("abcdef")}
	n, err := CopyCounted(streamTestWriter{writeErr}, src, &count)
	if !errors.Is(err, writeErr) || n != 2 || count.Load() != 2 {
		t.Fatalf("copy = (%d, %v), counter = %d", n, err, count.Load())
	}
}

type streamTestReader struct {
	io.Reader
	beforeRead func()
	reads      int
}

func (r *streamTestReader) Read(p []byte) (int, error) {
	if r.reads == 1 {
		r.beforeRead()
	}
	r.reads++
	return r.Reader.Read(p[:3])
}

type streamTestWriter struct{ err error }

func (w streamTestWriter) Write([]byte) (int, error) { return 2, w.err }
