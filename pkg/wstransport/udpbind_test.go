package wstransport

import (
	"bytes"
	"strconv"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
)

func TestUDPBindTunesSocketsAndRetainsBatchedIPv4IO(t *testing.T) {
	receiver := NewUDPBind(64<<10, nil)
	defer receiver.Close()
	receiveFns, port, err := receiver.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	var v4 UDPBufferStatus
	for _, status := range receiver.BufferStatus() {
		if status.Socket == "ipv4" {
			v4 = status
			break
		}
	}
	if v4.Requested != 64<<10 {
		t.Fatalf("IPv4 requested buffer = %d, want %d", v4.Requested, 64<<10)
	}
	if v4.Err != nil || v4.Read <= 0 || v4.Write <= 0 {
		t.Fatalf("IPv4 effective buffers = %+v, want positive accepted values", v4)
	}
	if receiver.BatchSize() != conn.IdealBatchSize && receiver.BatchSize() != 1 {
		t.Fatalf("unexpected batch size %d", receiver.BatchSize())
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
	want := []byte("tuned UDP bind")
	if err := sender.Send([][]byte{want}, ep); err != nil {
		t.Fatal(err)
	}
	bufs := make([][]byte, receiver.BatchSize())
	for i := range bufs {
		bufs[i] = make([]byte, 128)
	}
	sizes := make([]int, len(bufs))
	eps := make([]conn.Endpoint, len(bufs))
	n, err := receiveFns[0](bufs, sizes, eps)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || !bytes.Equal(bufs[0][:sizes[0]], want) || !eps[0].DstIP().Is4() {
		t.Fatalf("receive = n=%d payload=%q endpoint=%v; want one IPv4 %q packet", n, bufs[0][:sizes[0]], eps[0], want)
	}
}
