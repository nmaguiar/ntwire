// Package asn reads the IPv4 range index used by ntwire's destination filters.
package asn

import (
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"slices"
	"sort"
	"time"
)

const (
	DefaultURL     = "https://openaf.io/asnidx.json.gz"
	DefaultRefresh = 72 * time.Minute
	MaxCompressed  = 16 << 20
	maxExpanded    = 128 << 20
	maxRanges      = 2_000_000
)

type entry struct {
	ASN   uint32 `json:"a"`
	Start uint32 `json:"s"`
	End   uint32 `json:"e"`
}

// Index is immutable and safe for concurrent use.
type Index struct{ entries []entry }

func (i *Index) Len() int { return len(i.entries) }

func (i *Index) Lookup(ip netip.Addr) (uint32, bool) {
	ip = ip.Unmap()
	if !ip.Is4() || i == nil {
		return 0, false
	}
	b := ip.As4()
	n := binary.BigEndian.Uint32(b[:])
	pos := sort.Search(len(i.entries), func(pos int) bool { return i.entries[pos].Start > n })
	if pos == 0 || i.entries[pos-1].End < n {
		return 0, false
	}
	return i.entries[pos-1].ASN, true
}

// Decode bounds the input and validates the full gzip stream. Strict mode
// rejects overlapping ranges with different ASNs for routing decisions.
func Decode(input io.Reader, strict bool) (*Index, error) {
	compressed := &io.LimitedReader{R: input, N: MaxCompressed + 1}
	gz, err := gzip.NewReader(compressed)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	expanded := &io.LimitedReader{R: gz, N: maxExpanded + 1}
	dec := json.NewDecoder(expanded)
	if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
		return nil, errors.New("invalid ASN index array")
	}
	var rows []entry
	for dec.More() {
		if len(rows) >= maxRanges {
			return nil, errors.New("too many ASN ranges")
		}
		var row entry
		if strict {
			var fields struct {
				ASN   *uint32 `json:"a"`
				Start *uint32 `json:"s"`
				End   *uint32 `json:"e"`
			}
			if err := dec.Decode(&fields); err != nil || fields.ASN == nil || fields.Start == nil || fields.End == nil || *fields.Start > *fields.End {
				return nil, errors.New("invalid ASN range")
			}
			row = entry{ASN: *fields.ASN, Start: *fields.Start, End: *fields.End}
		} else if err := dec.Decode(&row); err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF || compressed.N == 0 || expanded.N == 0 {
		return nil, errors.New("invalid or oversized ASN index")
	}
	if strict && len(rows) == 0 {
		return nil, errors.New("empty ASN index")
	}
	sort.Slice(rows, func(a, b int) bool { return rows[a].Start < rows[b].Start })
	if strict {
		merged := rows[:0]
		for _, row := range rows {
			if n := len(merged); n > 0 && row.Start <= merged[n-1].End {
				prev := &merged[n-1]
				if prev.ASN != row.ASN {
					return nil, errors.New("conflicting ASN ranges")
				}
				prev.End = max(prev.End, row.End)
				continue
			}
			merged = append(merged, row)
		}
		rows = slices.Clip(merged)
	}
	return &Index{entries: rows}, nil
}
