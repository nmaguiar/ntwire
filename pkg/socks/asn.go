package socks

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/nmaguiar/ntwire/pkg/asn"
)

const defaultASNURL = asn.DefaultURL
const defaultASNRefreshInterval = asn.DefaultRefresh

type asnSnapshot struct {
	index    *asn.Index
	loadedAt time.Time
}

// ASNIndex provides the legacy server-side view of the shared IPv4 index.
type ASNIndex struct {
	data atomic.Pointer[asnSnapshot]
}

// NewASNIndex returns an empty index; Lookup returns ok=false until Update
// or Refresh populates it.
func NewASNIndex() *ASNIndex {
	return &ASNIndex{}
}

// Lookup implements ASNLookup.
func (a *ASNIndex) Lookup(ip netip.Addr) (uint32, bool) {
	if snapshot := a.data.Load(); snapshot != nil {
		return snapshot.index.Lookup(ip)
	}
	return 0, false
}

// Loaded reports whether the index has data, and when it was last updated.
func (a *ASNIndex) Loaded() (bool, time.Time) {
	if snapshot := a.data.Load(); snapshot != nil {
		return snapshot.index.Len() > 0, snapshot.loadedAt
	}
	return false, time.Time{}
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
	index, err := asn.Decode(resp.Body, false)
	if err != nil {
		return err
	}
	a.data.Store(&asnSnapshot{index: index, loadedAt: time.Now()})
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
