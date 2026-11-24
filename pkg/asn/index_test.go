package asn

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/netip"
	"testing"
)

func gzipDataset(t *testing.T, value string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := io.WriteString(w, value); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestIndexValidation(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		ok          bool
		size        int
	}{
		{"ordered on load", `[{"a":9,"s":256,"e":511},{"a":1,"s":0,"e":255}]`, true, 2},
		{"common ASN overlaps merge", `[{"a":1,"s":0,"e":255},{"a":1,"s":32,"e":511}]`, true, 1},
		{"multiple origins are rejected", `[{"a":1,"s":0,"e":255},{"a":2,"s":100,"e":511}]`, false, 0},
		{"backwards range", `[{"a":1,"s":255,"e":0}]`, false, 0},
		{"missing endpoints", `[{"a":1,"e":255}]`, false, 0},
		{"trailing JSON", `[{"a":1,"s":0,"e":255}] []`, false, 0},
		{"empty dataset", `[]`, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			index, err := Decode(bytes.NewReader(gzipDataset(t, tc.value)), true)
			if (err == nil) != tc.ok {
				t.Fatalf("Decode: %v", err)
			}
			if err == nil && index.Len() != tc.size {
				t.Fatalf("got %d indexed ranges", index.Len())
			}
		})
	}
}

func FuzzIndexDecode(f *testing.F) {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = io.WriteString(w, `[{"a":13335,"s":16843008,"e":16843263}]`)
	_ = w.Close()
	f.Add(b.Bytes())
	f.Add([]byte("invalid gzip"))
	f.Fuzz(func(t *testing.T, data []byte) {
		index, err := Decode(bytes.NewReader(data), true)
		if err == nil {
			_, _ = index.Lookup(netip.MustParseAddr("1.1.1.1"))
		}
	})
}
