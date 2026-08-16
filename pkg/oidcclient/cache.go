package oidcclient

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/zalando/go-keyring"
)

// CacheEntry is one cached principal: a long-lived refresh token plus the
// most recently minted ID token, so reconnect() can survive ID-token expiry
// without reopening the browser.
type CacheEntry struct {
	RefreshToken string    `json:"refresh_token,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
}

// Cache keeps token metadata in ~/.ntwire/tokens.json (0600), keyed by
// server_url+issuer_name so the same IdP account can be cached independently
// per ntwire server. On supported desktop systems, reusable credentials live
// in the OS credential store; the file intentionally keeps only an index and
// is the explicit fallback when that store is unavailable.
type Cache struct {
	path    string
	mu      sync.Mutex
	entries map[string]CacheEntry
	store   credentialStore
}

// credentialStore is deliberately small so the OIDC flow does not depend on
// an operating system. Values are serialized CacheEntry values, never logged.
type credentialStore interface {
	Get(string) (string, error)
	Set(string, string) error
	Delete(string) error
}

var errCredentialNotFound = errors.New("credential not found")

const credentialService = "ntwire-oidc"

type nativeCredentialStore struct{}

func (nativeCredentialStore) Get(key string) (string, error) {
	v, err := keyring.Get(credentialService, credentialKey(key))
	if errors.Is(err, keyring.ErrNotFound) {
		return "", errCredentialNotFound
	}
	return v, err
}

func (nativeCredentialStore) Set(key, value string) error {
	return keyring.Set(credentialService, credentialKey(key), value)
}

func (nativeCredentialStore) Delete(key string) error {
	err := keyring.Delete(credentialService, credentialKey(key))
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}

// credentialKey avoids putting a server URL or issuer name in an OS
// credential-store account label, where it may be visible in a desktop UI.
func credentialKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x", sum[:])
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
	return openCache(path, nativeCredentialStore{})
}

// openCache accepts a store for deterministic unit tests. Production callers
// use OpenCache, which selects the OS keychain adapter above.
func openCache(path string, store credentialStore) (*Cache, error) {
	if path == "" {
		path = DefaultCacheFile()
	}
	c := &Cache{path: path, entries: map[string]CacheEntry{}, store: store}
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
	key := cacheKey(serverURL, issuerName)
	if c.store != nil {
		v, err := c.store.Get(key)
		if err == nil {
			var e CacheEntry
			if json.Unmarshal([]byte(v), &e) == nil && e.RefreshToken != "" {
				return e, true
			}
			return CacheEntry{}, false
		}
		if !errors.Is(err, errCredentialNotFound) {
			// The documented 0600-file fallback is intentionally used only
			// when a native store cannot be used. Never log the returned error:
			// credential backends can include account details in their text.
			return c.legacyGet(key)
		}
	}
	if e, ok := c.legacyGet(key); ok && c.store != nil {
		// Safe one-way migration: write, read back, then scrub the legacy
		// secret. A failed native write leaves the old file untouched.
		if c.putNative(key, e) == nil {
			c.entries[key] = CacheEntry{}
			_ = c.save()
		}
		return e, true
	}
	return c.legacyGet(key)
}

func (c *Cache) Put(serverURL, issuerName string, e CacheEntry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := cacheKey(serverURL, issuerName)
	if c.store != nil && c.putNative(key, e) == nil {
		// Retain only the non-secret index so Logout can remove native entries.
		c.entries[key] = CacheEntry{}
		return c.save()
	}
	c.entries[key] = e
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
			if c.store != nil {
				if err := c.store.Delete(k); err != nil {
					// A native store may be absent in a headless environment;
					// remove the file fallback regardless, but return the error
					// so callers do not report logout as complete incorrectly.
					delete(c.entries, k)
					_ = c.save()
					return err
				}
			}
			delete(c.entries, k)
		}
	}
	return c.save()
}

func (c *Cache) legacyGet(key string) (CacheEntry, bool) {
	e, ok := c.entries[key]
	return e, ok && e.RefreshToken != ""
}

func (c *Cache) putNative(key string, e CacheEntry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if err = c.store.Set(key, string(b)); err != nil {
		return err
	}
	// Verification before deleting a legacy copy is required for migration.
	got, err := c.store.Get(key)
	if err != nil || got != string(b) {
		if err != nil {
			return err
		}
		return errors.New("credential store verification failed")
	}
	return nil
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
