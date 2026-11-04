package wstransport

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

func TestReceiveCompactionPreservesWireGuardBuffers(t *testing.T) {
	for _, mode := range []string{"control", "duplicate"} {
		for _, wrapper := range []string{"filter", "client", "server", "filter-server"} {
			if wrapper == "filter" && mode == "duplicate" {
				continue
			}
			t.Run(wrapper+"/"+mode, func(t *testing.T) {
				cache := NewDuplicateCache(4096, time.Minute)
				wrap := func(fn conn.ReceiveFunc) conn.ReceiveFunc { return fn }
				if wrapper == "client" {
					m := &MultipathBind{cache: cache}
					wrap = m.wrapReceive
				} else if wrapper == "server" || wrapper == "filter-server" {
					m := &ServerMultipathBind{cache: cache}
					wrap = m.wrap
				}
				filter := NewFilterBind(nil)
				first := EncodeControlFrame(FramePrime, nil)
				packet := func(index uint32) []byte {
					b := make([]byte, 32)
					binary.LittleEndian.PutUint32(b, 4)
					binary.LittleEndian.PutUint32(b[4:], index)
					return b
				}
				if mode == "duplicate" {
					first = packet(99)
					cache.Seen(first, time.Now())
				}
				var expected [][]byte
				peers := []conn.Endpoint{fakeEndpoint{id: "control"}, fakeEndpoint{id: "native-wg"}, fakeEndpoint{id: "ntwire"}}
				call := uint32(0)
				source := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
					call++
					// Simultaneous native-WG and ntwire peers behind the same UDP socket.
					expected = [][]byte{packet(call * 2), packet(call*2 + 1)}
					for i, data := range [][]byte{first, expected[0], expected[1]} {
						sizes[i] = copy(bufs[i], data)
						eps[i] = peers[i]
					}
					return 3, nil
				}
				var receive conn.ReceiveFunc = source
				if wrapper == "filter" || wrapper == "filter-server" {
					receive = filter.wrapReceive(receive)
				}
				receive = wrap(receive)
				bufs, sizes, eps := receiveBatch(3)
				// wireguard-go retains these array pointers independently of bufs.
				owned := append([][]byte(nil), bufs...)
				for batch := 0; batch < 3; batch++ {
					n, err := receive(bufs, sizes, eps)
					if err != nil || n != 2 {
						t.Fatalf("receive = %d, %v", n, err)
					}
					for i := range owned {
						if &bufs[i][0] != &owned[i][0] {
							t.Fatalf("receive replaced WireGuard-owned buffer %d", i)
						}
						if i < n && !bytes.Equal(owned[i][:sizes[i]], expected[i]) {
							t.Fatalf("WireGuard-owned slot %d contains the wrong packet", i)
						}
						if i < n && wrapper != "client" && eps[i] != peers[i+1] {
							t.Fatalf("slot %d contains the wrong peer endpoint", i)
						}
					}
					// WireGuard hands accepted arrays to workers and replaces only
					// the delivered slots. Undelivered slots remain for the next read.
					for i := 0; i < n; i++ {
						owned[i] = make([]byte, 128)
						bufs[i] = owned[i]
					}
				}
			})
		}
	}
}
