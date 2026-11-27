package wstransport

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestCarrierFrame_LengthAndTruncation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		record []byte
		want   error
	}{
		{name: "exact bound", record: []byte{0, 3, 1, 2, 3}},
		{name: "empty", record: []byte{0, 0}, want: ErrCarrierDatagram},
		{name: "oversized", record: []byte{0, 4}, want: ErrCarrierDatagram},
		{name: "truncated length", record: []byte{0}, want: io.ErrUnexpectedEOF},
		{name: "truncated data", record: []byte{0, 3, 1}, want: io.ErrUnexpectedEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := readCarrierFrame(bytes.NewReader(tc.record), 3)
			if !errors.Is(err, tc.want) || (err == nil && !bytes.Equal(p, tc.record[2:])) {
				t.Fatalf("packet = %x, error = %v, want %v", p, err, tc.want)
			}
		})
	}
}

func FuzzCarrierFrame(f *testing.F) {
	f.Add([]byte{0, 1, 4})
	f.Add([]byte{0xff, 0xff})
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		p, err := readCarrierFrame(r, 1500)
		if len(p) > 1500 || (err == nil && (len(p) == 0 || len(data)-r.Len() != len(p)+2 || !bytes.Equal(p, data[2:2+len(p)]))) {
			t.Fatalf("invalid decoded record size %d", len(p))
		}
	})
}

func FuzzHTTP3CarrierDatagram(f *testing.F) {
	f.Add([]byte{0, 1})
	f.Add([]byte{0x40, 0, 1})
	f.Add([]byte{0x40})
	f.Add([]byte{1, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := parseHTTP3Datagram(data)
		if err == nil && (len(p) == 0 || len(p) >= len(data) || !bytes.HasSuffix(data, p)) {
			t.Fatalf("invalid decoded datagram size %d", len(p))
		}
	})
}
