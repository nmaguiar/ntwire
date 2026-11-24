package egressrouter

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSplitASNRefreshRetainsSnapshot(t *testing.T) {
	var healthy atomic.Bool
	healthy.Store(true)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !healthy.Load() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, _ = io.WriteString(gz, `[{"i":1,"a":13335,"s":16843008,"e":16843263}]`)
		_ = gz.Close()
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()
	db := &asnDatabase{config: ASNDatabaseConfig{Source: srv.URL, MaxAge: time.Hour}}
	cache := filepath.Join(t.TempDir(), "private", "asn.json.gz")
	if err := db.refresh(t.Context(), srv.Client(), cache); err != nil {
		t.Fatal(err)
	}
	initial := db.data.Load()
	ip := netip.MustParseAddr("1.1.1.1")
	var readers sync.WaitGroup
	for range 4 {
		readers.Go(func() {
			for range 3000 {
				if got, ok := db.data.Load().index.Lookup(ip); !ok || got != 13335 {
					t.Errorf("lookup %d %t", got, ok)
					return
				}
			}
		})
	}
	if err := db.refresh(t.Context(), srv.Client(), cache); err != nil {
		readers.Wait()
		t.Fatal(err)
	}
	readers.Wait()
	current := db.data.Load()
	if current == initial {
		t.Fatal("refresh did not publish a new snapshot")
	}
	healthy.Store(false)
	if err := db.refresh(t.Context(), srv.Client(), cache); err == nil || db.data.Load() != current {
		t.Fatalf("refresh failure lost snapshot: %v", err)
	}
	if status := db.status(current.updated.Add(2 * time.Hour)); !status.Loaded || !status.Stale || status.IPv6 || status.Ranges != 1 {
		t.Fatalf("status %+v", status)
	}
	reloaded := &asnDatabase{config: db.config}
	reloaded.loadCache(cache)
	if index := reloaded.data.Load(); index == nil || index.index.Len() != 1 {
		t.Fatal("validated cache unavailable after restart")
	}
}

func FuzzSplitRoutingNumericEquivalence(f *testing.F) {
	f.Add(uint32(16843009), uint16(443))
	f.Add(uint32(0), uint16(0))
	f.Fuzz(func(t *testing.T, raw uint32, port uint16) {
		if port == 0 {
			return
		}
		ip := netip.AddrFrom4([4]byte{byte(raw >> 24), byte(raw >> 16), byte(raw >> 8), byte(raw)})
		str := netip.AddrPortFrom(ip, port).String()
		number := func(netip.Addr) (uint32, string) { return 42, "" }
		routing := Routing{Rules: []Rule{{ASNs: []uint32{42}, Ports: []uint16{443}, Action: Direct}}, Unmatched: "deny"}
		binary, err := destination(str)
		if err != nil {
			t.Fatal(err)
		}
		domain := binary
		domain.AddressType = 3
		mapped, err := destination(fmt.Sprintf("[::ffff:%s]:%d", ip, port))
		if err != nil {
			t.Fatal(err)
		}
		a, b, c := routing.decide(binary, binary.IP(), number), routing.decide(domain, domain.IP(), number), routing.decide(mapped, mapped.IP(), number)
		if a.Action != b.Action || b.Action != c.Action {
			t.Fatalf("actions %s %s %s", a.Action, b.Action, c.Action)
		}
	})
}

func BenchmarkSplitASNRefreshWithReaders(b *testing.B) {
	original, next := sampleASN(b), sampleASN(b)
	var db asnDatabase
	db.data.Store(original)
	b.ReportAllocs()
	var count atomic.Uint64
	ip := netip.MustParseAddr("1.1.1.1")
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			n := count.Add(1)
			if n%1024 == 0 {
				if n%2048 == 0 {
					db.data.Store(original)
				} else {
					db.data.Store(next)
				}
			}
			_, _ = db.data.Load().index.Lookup(ip)
		}
	})
}
