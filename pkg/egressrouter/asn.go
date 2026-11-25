package egressrouter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/nmaguiar/ntwire/internal/privatepath"
	"github.com/nmaguiar/ntwire/pkg/asn"
)

type ASNDatabaseConfig struct {
	Source          string        `yaml:"source,omitempty" json:"source,omitempty"`
	RefreshInterval time.Duration `yaml:"refresh_interval,omitempty" json:"refresh_interval,omitempty"`
	MaxAge          time.Duration `yaml:"max_age,omitempty" json:"max_age,omitempty"`
	CacheDir        string        `yaml:"cache_dir,omitempty" json:"cache_dir,omitempty"`
}

type ASNPolicy struct {
	Enabled            *bool     `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	HostnameResolution string    `yaml:"hostname_resolution,omitempty" json:"hostname_resolution,omitempty"`
	OnUnknown          string    `yaml:"on_unknown,omitempty" json:"on_unknown,omitempty"`
	Hosts              []string  `yaml:"hosts,omitempty" json:"hosts,omitempty"`
	Suffixes           []string  `yaml:"suffixes,omitempty" json:"suffixes,omitempty"`
	ResolverMember     *MemberID `yaml:"resolver_member,omitempty" json:"resolver_member,omitempty"`
}

type ASNStatus struct {
	Loaded     bool       `json:"loaded"`
	IPv4       bool       `json:"ipv4"`
	IPv6       bool       `json:"ipv6"`
	Stale      bool       `json:"stale"`
	Ranges     int        `json:"ranges"`
	LastUpdate *time.Time `json:"last_update,omitempty"`
	AgeSeconds int64      `json:"age_seconds"`
	LastError  string     `json:"last_error,omitempty"`
}

func (c ASNDatabaseConfig) normalized() (ASNDatabaseConfig, error) {
	if c.Source == "" {
		c.Source = asn.DefaultURL
	}
	u, err := url.Parse(c.Source)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return c, errors.New("ASN database source must be an HTTPS URL without credentials or fragment")
	}
	if c.RefreshInterval == 0 {
		c.RefreshInterval = asn.DefaultRefresh
	}
	if c.MaxAge == 0 {
		c.MaxAge = 24 * time.Hour
	}
	if c.RefreshInterval < time.Minute || c.RefreshInterval > 30*24*time.Hour || c.MaxAge < c.RefreshInterval || c.MaxAge > 90*24*time.Hour {
		return c, errors.New("invalid ASN refresh interval or maximum age")
	}
	if c.CacheDir != "" && !filepath.IsAbs(c.CacheDir) {
		return c, errors.New("ASN database cache directory must be absolute")
	}
	return c, nil
}

type asnData struct {
	index   *asn.Index
	updated time.Time
}

type asnDatabase struct {
	config  ASNDatabaseConfig
	data    atomic.Pointer[asnData]
	failure atomic.Pointer[string]
	cancel  context.CancelFunc
}

func (d *asnDatabase) expired(data *asnData, now time.Time) bool {
	return now.Sub(data.updated) >= d.config.MaxAge
}

func (d *asnDatabase) status(now time.Time) *ASNStatus {
	if d == nil {
		return nil
	}
	s := &ASNStatus{}
	if data := d.data.Load(); data != nil {
		s.Loaded, s.IPv4, s.Stale, s.Ranges = true, true, d.expired(data, now), data.index.Len()
		s.LastUpdate = &data.updated
		s.AgeSeconds = max(0, int64(now.Sub(data.updated)/time.Second))
	}
	if err := d.failure.Load(); err != nil {
		s.LastError = *err
	}
	return s
}

func useASNDatabase(current *asnDatabase, cfg *ASNDatabaseConfig, used bool) *asnDatabase {
	if !used {
		if current != nil {
			current.cancel()
		}
		return nil
	}
	config := ASNDatabaseConfig{}
	if cfg != nil {
		config = *cfg
	}
	config, _ = config.normalized()
	if current != nil && current.config == config {
		return current
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &asnDatabase{config: config, cancel: cancel}
	if current != nil {
		current.cancel()
		if current.config.Source == config.Source {
			d.data.Store(current.data.Load())
		}
	}
	go d.run(ctx)
	return d
}

func (d *asnDatabase) run(ctx context.Context) {
	cache := ""
	if d.config.CacheDir != "" {
		cache = filepath.Join(d.config.CacheDir, fmt.Sprintf("asn-%x.json.gz", sha256.Sum256([]byte(d.config.Source))))
		d.loadCache(cache)
	}
	transport := &http.Transport{DisableCompression: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	ticker := time.NewTicker(d.config.RefreshInterval)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		if err := d.refresh(ctx, client, cache); err != nil {
			message := err.Error()
			d.failure.Store(&message)
		} else {
			d.failure.Store(nil)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (d *asnDatabase) refresh(ctx context.Context, client *http.Client, cache string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.config.Source, nil)
	if err != nil {
		return errors.New("invalid ASN source request")
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("ASN source request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ASN source returned HTTP %d", resp.StatusCode)
	}
	var compressed bytes.Buffer
	var input io.Reader = resp.Body
	if cache != "" {
		input = io.TeeReader(input, &compressed)
	}
	index, err := asn.Decode(input, true)
	if err != nil {
		return errors.New("ASN source returned an invalid index")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	now := time.Now()
	d.data.Store(&asnData{index: index, updated: now})
	if cache != "" && writeASNCache(cache, compressed.Bytes()) != nil {
		return errors.New("ASN cache write failed")
	}
	return nil
}

func (d *asnDatabase) loadCache(path string) {
	if privatepath.Verify(filepath.Dir(path), true) != nil || privatepath.Verify(path, false) != nil {
		return
	}
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.ModTime().After(time.Now()) {
		return
	}
	if index, err := asn.Decode(file, true); err == nil {
		current := d.data.Load()
		if current == nil || info.ModTime().After(current.updated) {
			d.data.Store(&asnData{index: index, updated: info.ModTime()})
		}
	}
}

func writeASNCache(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(filepath.Dir(dir), 0700); err != nil {
		return err
	}
	switch err := os.Mkdir(dir, 0700); {
	case err == nil:
		if err := privatepath.Restrict(dir, true); err != nil {
			return err
		}
	case !os.IsExist(err):
		return err
	}
	if err := privatepath.Verify(dir, true); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".asn-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := privatepath.Restrict(file.Name(), false); err != nil {
		_ = file.Close()
		return err
	}
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
