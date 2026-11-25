package socks

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func gzipJSON(t *testing.T, v any) []byte {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type asnIndexEntry struct {
	ASN   uint32 `json:"a"`
	Start uint32 `json:"s"`
	End   uint32 `json:"e"`
}

func TestASNIndexUpdateAndLookup(t *testing.T) {
	entries := []asnIndexEntry{
		{ASN: 15169, Start: ipToUint32(t, "8.8.8.0"), End: ipToUint32(t, "8.8.8.255")},
		{ASN: 13335, Start: ipToUint32(t, "1.1.1.0"), End: ipToUint32(t, "1.1.1.255")},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(gzipJSON(t, entries))
	}))
	defer srv.Close()

	idx := NewASNIndex()
	if err := idx.Update(context.Background(), srv.URL); err != nil {
		t.Fatalf("Update: %v", err)
	}
	loaded, when := idx.Loaded()
	if !loaded || when.IsZero() {
		t.Fatalf("expected index to be loaded")
	}

	tests := []struct {
		ip      string
		wantASN uint32
		wantOK  bool
	}{
		{"8.8.8.8", 15169, true},
		{"2001:db8::1", 0, false},
		{"::ffff:8.8.8.8", 15169, true},
		{"8.8.8.0", 15169, true},   // range start (inclusive)
		{"8.8.8.255", 15169, true}, // range end (inclusive)
		{"1.1.1.1", 13335, true},
		{"9.9.9.9", 0, false}, // outside all ranges
		{"8.8.7.255", 0, false},
	}
	for _, tt := range tests {
		asn, ok := idx.Lookup(netip.MustParseAddr(tt.ip))
		if ok != tt.wantOK || (ok && asn != tt.wantASN) {
			t.Errorf("Lookup(%s) = (%d, %v), want (%d, %v)", tt.ip, asn, ok, tt.wantASN, tt.wantOK)
		}
	}
}

func ipToUint32(t *testing.T, s string) uint32 {
	t.Helper()
	a := netip.MustParseAddr(s)
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
