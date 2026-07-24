package socks

import (
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// defaultASNURL matches socksd's ASNURL default.
const defaultASNURL = "https://openaf.io/asnidx.json.gz"

// defaultASNRefreshInterval matches socksd's periodic ASN index update job
// (main.yaml: "Periodic ASNs update", scheduled every 4,320,000ms).
const defaultASNRefreshInterval = 72 * time.Minute

// asnIndexEntry is one row of the downloaded index: an IPv4 range (as
// big-endian uint32 bounds, inclusive) announced by ASN a. The wire format
// is a gzip-compressed JSON array of {i,a,s,e} objects; i (the original
// cache index) is accepted but unused here.
type asnIndexEntry struct {
	ASN   uint32 `json:"a"`
	Start uint32 `json:"s"`
	End   uint32 `json:"e"`
}

// ASNIndex is an IPv4-only IP-to-ASN lookup table, matching socksd's index
// (which is built from 32-bit integer ranges; IPv6 destinations never match
// an ASN filter, in socksd or here). It is safe for concurrent use and can
// be refreshed in the background via Refresh.
type ASNIndex struct {
	mu       sync.RWMutex
	entries  []asnIndexEntry // sorted by Start
	loadedAt time.Time
}

// NewASNIndex returns an empty index; Lookup returns ok=false until Update
// or Refresh populates it.
func NewASNIndex() *ASNIndex {
	return &ASNIndex{}
}

// Lookup implements ASNLookup.
func (a *ASNIndex) Lookup(ip netip.Addr) (uint32, bool) {
	ip = ip.Unmap()
	if !ip.Is4() {
		return 0, false
	}
	b := ip.As4()
	n := binary.BigEndian.Uint32(b[:])

	a.mu.RLock()
	defer a.mu.RUnlock()
	entries := a.entries
	i := sort.Search(len(entries), func(i int) bool { return entries[i].Start > n })
	if i == 0 {
		return 0, false
	}
	e := entries[i-1]
	if n >= e.Start && n <= e.End {
		return e.ASN, true
	}
	return 0, false
}

// Loaded reports whether the index has ever been successfully populated,
// and when.
func (a *ASNIndex) Loaded() (bool, time.Time) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.entries) > 0, a.loadedAt
}

// Update downloads and replaces the index from url (defaulting to
// defaultASNURL), matching socksd's updateASNIdx().
func (a *ASNIndex) Update(ctx context.Context, url string) error {
	if url == "" {
		url = defaultASNURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("socks: asn index download failed: %s", resp.Status)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	defer gz.Close()

	var raw []asnIndexEntry
	if err := json.NewDecoder(gz).Decode(&raw); err != nil {
		return err
	}
	sort.Slice(raw, func(i, j int) bool { return raw[i].Start < raw[j].Start })

	a.mu.Lock()
	a.entries = raw
	a.loadedAt = time.Now()
	a.mu.Unlock()
	return nil
}

// Refresh loads the index immediately and then re-downloads it every
// interval (defaulting to defaultASNRefreshInterval) until stop is closed.
// Download failures are logged and otherwise ignored; the previously loaded
// index (if any) keeps serving lookups.
func (a *ASNIndex) Refresh(url string, interval time.Duration, log *slog.Logger, stop <-chan struct{}) {
	if interval <= 0 {
		interval = defaultASNRefreshInterval
	}
	load := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := a.Update(ctx, url); err != nil {
			log.Warn("socks asn index update failed", "url", url, "error", err)
			return
		}
		_, t := a.Loaded()
		log.Debug("socks asn index updated", "url", url, "loaded_at", t)
	}
	load()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			load()
		case <-stop:
			return
		}
	}
}
