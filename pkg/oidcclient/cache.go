package oidcclient

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CacheEntry is one cached principal: a long-lived refresh token plus the
// most recently minted ID token, so reconnect() can survive ID-token expiry
// without reopening the browser.
type CacheEntry struct {
	RefreshToken string    `json:"refresh_token,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
}

// Cache is the on-disk token store at ~/.ntwire/tokens.json (0600), keyed by
// server_url+issuer_name so the same IdP account can be cached independently
// per ntwire server.
type Cache struct {
	path    string
	mu      sync.Mutex
	entries map[string]CacheEntry
}

func DefaultCacheFile() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(h, ".ntwire", "tokens.json")
}

// OpenCache loads the cache at path (DefaultCacheFile when empty). A missing
// file is treated as an empty cache.
func OpenCache(path string) (*Cache, error) {
	if path == "" {
		path = DefaultCacheFile()
	}
	c := &Cache{path: path, entries: map[string]CacheEntry{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &c.entries); err != nil {
		return nil, err
	}
	return c, nil
}

func cacheKey(serverURL, issuerName string) string { return serverURL + "|" + issuerName }

func (c *Cache) Get(serverURL, issuerName string) (CacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[cacheKey(serverURL, issuerName)]
	return e, ok
}

func (c *Cache) Put(serverURL, issuerName string, e CacheEntry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[cacheKey(serverURL, issuerName)] = e
	return c.save()
}

// DeleteServer removes every cached entry for a server, regardless of
// issuer. It backs `ntwire logout`, which does not know which issuer was
// used to connect.
func (c *Cache) DeleteServer(serverURL string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	prefix := serverURL + "|"
	for k := range c.entries {
		if strings.HasPrefix(k, prefix) {
			delete(c.entries, k)
		}
	}
	return c.save()
}

func (c *Cache) save() error {
	b, err := json.MarshalIndent(c.entries, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0700); err != nil {
		return err
	}
	return os.WriteFile(c.path, b, 0600)
}
