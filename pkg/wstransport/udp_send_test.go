package wstransport

import (
	"errors"
	"golang.org/x/net/ipv6"
	"io"
	"testing"
)

func TestUDPWriteBatch_ZeroProgressTerminates(t *testing.T) {
	writer := udpWriteBatchFunc(func([]ipv6.Message, int) (int, error) { return 0, nil })
	if n, err := writeUDPBatch(writer, []ipv6.Message{{}}); n != 0 || !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("writeUDPBatch returned (%d, %v)", n, err)
	}
}

type udpWriteBatchFunc func([]ipv6.Message, int) (int, error)

func (f udpWriteBatchFunc) WriteBatch(msgs []ipv6.Message, flags int) (int, error) {
	return f(msgs, flags)
}
