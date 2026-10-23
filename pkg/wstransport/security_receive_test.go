package wstransport

import (
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/conn"
	"net"
	"testing"
)

type emptyThenPacketBatch struct{ calls int }

func (b *emptyThenPacketBatch) ReadBatch(msgs []ipv6.Message, _ int) (int, error) {
	b.calls++
	msgs[0].Addr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	msgs[0].N = 0
	if b.calls > 1 {
		copy(msgs[0].Buffers[0], []byte{1, 2, 3, 4})
		msgs[0].N = 4
	}
	return 1, nil
}
func TestEmptyUDPBatchHasEndpointAndMultipathDropsIt(t *testing.T) {
	batch := &emptyThenPacketBatch{}
	receive := makeUDPBatchReceive(batch)
	bufs := [][]byte{make([]byte, 128)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	if n, err := receive(bufs, sizes, eps); err != nil || n != 1 || sizes[0] != 0 || eps[0] == nil {
		t.Fatalf("empty batch: %d %v %v", n, err, eps)
	}
	batch.calls = 0
	eps[0] = nil
	m := NewServerMultipathBind(nil, MultipathOptions{})
	if n, err := m.wrap(receive)(bufs, sizes, eps); err != nil || n != 1 || sizes[0] != 4 || eps[0] == nil {
		t.Fatalf("multipath: %d %v %v", n, err, eps)
	}
}
