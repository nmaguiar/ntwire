// Package updater discovers and verifies independently installable client releases.
package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// PublicKey is a base64 Ed25519 public key, provisioned at release build time.
// Empty keys fail closed; no network response can supply a trust anchor.
var PublicKey string

const Repository = "nmaguiar/ntwire"
const maxMetadata = 2 << 20
const maxArchive = 512 << 20

type Asset struct {
	Product string `json:"product"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
}
type Manifest struct {
	Version string  `json:"version"`
	Assets  []Asset `json:"assets"`
}
type Release struct {
	Manifest  Manifest `json:"manifest"`
	Asset     Asset    `json:"asset"`
	Notes     string   `json:"notes"`
	URL       string   `json:"url"`
	Raw       []byte   `json:"raw"`
	Signature []byte   `json:"signature"`
}
type Client struct {
	HTTP *http.Client
	API  string
	Key  ed25519.PublicKey
}

func NewClient() *Client {
	key, _ := base64.StdEncoding.DecodeString(PublicKey)
	return &Client{HTTP: &http.Client{Timeout: 10 * time.Minute}, API: "https://api.github.com/repos/" + Repository, Key: key}
}

var stableVersion = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

func version(s string) ([3]uint64, error) {
	var v [3]uint64
	if !stableVersion.MatchString(s) {
		return v, fmt.Errorf("%q is not a stable release version; development builds cannot self-install", s)
	}
	p := strings.Split(strings.Split(strings.TrimPrefix(s, "v"), "+")[0], ".")
	for i := range v {
		n, e := strconv.ParseUint(p[i], 10, 64)
		if e != nil {
			return v, e
		}
		v[i] = n
	}
	return v, nil
}
func Newer(latest, current string) (bool, error) {
	a, e := version(latest)
	if e != nil {
		return false, e
	}
	b, e := version(current)
	if e != nil {
		return false, e
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i], nil
		}
	}
	return false, nil
}
func CanInstall(current string) error {
	if _, e := version(current); e != nil {
		return errors.New("development builds cannot self-install; install a stable release first")
	}
	return nil
}
func AssetName(product, ver, goos, arch string) (string, error) {
	if product != "ntwire" && product != "ntwire-gui" {
		return "", errors.New("unsupported update product")
	}
	if _, e := version(ver); e != nil {
		return "", e
	}
	if (arch != "amd64" && arch != "arm64") || (goos != "linux" && goos != "darwin" && goos != "windows") || (product == "ntwire-gui" && goos == "darwin" && arch != "arm64") {
		return "", errors.New("no release for this platform")
	}
	ext := ".tar.gz"
	if goos == "windows" || (product == "ntwire-gui" && goos == "darwin") {
		ext = ".zip"
	}
	v := strings.TrimPrefix(ver, "v")
	if product == "ntwire-gui" && goos == "darwin" {
		v = "v" + v
	}
	return fmt.Sprintf("%s_%s_%s_%s%s", product, v, goos, arch, ext), nil
}
func Verify(raw, sig []byte, key ed25519.PublicKey) (Manifest, error) {
	var m Manifest
	if len(key) != ed25519.PublicKeySize {
		return m, errors.New("update verification key is not provisioned; see docs/UPDATES.md")
	}
	if !ed25519.Verify(key, raw, sig) {
		return m, errors.New("invalid update manifest signature")
	}
	if len(raw) > maxMetadata {
		return m, errors.New("manifest too large")
	}
	if e := json.Unmarshal(raw, &m); e != nil {
		return m, e
	}
	if _, e := version(m.Version); e != nil {
		return m, e
	}
	seen := map[string]bool{}
	for _, a := range m.Assets {
		name, e := AssetName(a.Product, m.Version, a.OS, a.Arch)
		hash, he := hex.DecodeString(a.SHA256)
		if e != nil || a.Name != name || seen[name] || a.Size <= 0 || a.Size > maxArchive || he != nil || len(hash) != 32 {
			return m, errors.New("invalid or duplicate manifest asset")
		}
		seen[name] = true
	}
	// Publication is atomic from the updater's perspective: require every supported client archive.
	for _, product := range []string{"ntwire", "ntwire-gui"} {
		for _, goos := range []string{"linux", "darwin", "windows"} {
			for _, arch := range []string{"amd64", "arm64"} {
				n, e := AssetName(product, m.Version, goos, arch)
				if e == nil && !seen[n] {
					return m, fmt.Errorf("incomplete release: missing %s", n)
				}
			}
		}
	}
	return m, nil
}
func (c *Client) httpClient() *http.Client {
	original := c.HTTP
	if original == nil {
		original = &http.Client{Timeout: 10 * time.Minute}
	}
	clone := *original
	clone.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return errors.New("update redirects must use HTTPS")
		}
		if len(via) >= 10 {
			return errors.New("too many update redirects")
		}
		if original.CheckRedirect != nil {
			return original.CheckRedirect(req, via)
		}
		return nil
	}
	return &clone
}
func (c *Client) get(ctx context.Context, u string, limit int64) ([]byte, error) {
	req, e := http.NewRequestWithContext(ctx, "GET", u, nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("User-Agent", "ntwire-updater")
	resp, e := c.httpClient().Do(req)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("update server returned HTTP %d (retry later; rate limit resets at %s)", resp.StatusCode, resp.Header.Get("X-RateLimit-Reset"))
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if e == nil && int64(len(b)) > limit {
		e = errors.New("update response too large")
	}
	return b, e
}
func (c *Client) Check(ctx context.Context, product, current string) (*Release, error) {
	if len(c.Key) != ed25519.PublicKeySize {
		return nil, errors.New("update verification key is not provisioned; see docs/UPDATES.md")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	b, e := c.get(ctx, c.API+"/releases/latest", maxMetadata)
	if e != nil {
		return nil, e
	}
	var r struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
		Body       string `json:"body"`
		Assets     []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
			Size int64  `json:"size"`
		} `json:"assets"`
	}
	if e = json.Unmarshal(b, &r); e != nil {
		return nil, e
	}
	if r.Draft || r.Prerelease {
		return nil, errors.New("release is not stable")
	}
	if _, e = version(r.Tag); e != nil {
		return nil, e
	}
	if CanInstall(current) == nil {
		newer, _ := Newer(r.Tag, current)
		if !newer {
			return nil, nil
		}
	}
	urls := map[string]string{}
	sizes := map[string]int64{}
	for _, a := range r.Assets {
		urls[a.Name] = a.URL
		sizes[a.Name] = a.Size
	}
	raw, e := c.get(ctx, urls["update-manifest.json"], maxMetadata)
	if e != nil {
		return nil, fmt.Errorf("release unavailable: %w", e)
	}
	sigText, e := c.get(ctx, urls["update-manifest.sig"], 1024)
	if e != nil {
		return nil, e
	}
	sig, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigText)))
	if e != nil {
		return nil, e
	}
	m, e := Verify(raw, sig, c.Key)
	if e != nil {
		return nil, e
	}
	if strings.TrimPrefix(m.Version, "v") != strings.TrimPrefix(r.Tag, "v") {
		return nil, errors.New("manifest version differs from release tag")
	}
	for _, a := range m.Assets {
		if urls[a.Name] == "" || sizes[a.Name] != a.Size {
			return nil, fmt.Errorf("release unavailable: missing or wrong size for %s", a.Name)
		}
	}
	for _, a := range m.Assets {
		if a.Product == product && a.OS == runtime.GOOS && a.Arch == runtime.GOARCH {
			return &Release{m, a, r.Body, urls[a.Name], raw, sig}, nil
		}
	}
	return nil, errors.New("no update for this platform")
}

// Download writes only a fully verified archive into a private cache directory.
func (c *Client) Download(ctx context.Context, r *Release, dir string, progress func(int64, int64)) (string, error) {
	m, e := Verify(r.Raw, r.Signature, c.Key)
	if e != nil {
		return "", e
	}
	found := false
	for _, a := range m.Assets {
		if a == r.Asset {
			found = true
		}
	}
	if !found {
		return "", errors.New("asset not in signed manifest")
	}
	u, e := url.Parse(r.URL)
	if e != nil || u.Scheme != "https" {
		return "", errors.New("archive URL must use HTTPS")
	}
	if e = os.MkdirAll(dir, 0700); e != nil {
		return "", e
	}
	f, e := os.CreateTemp(dir, ".download-*")
	if e != nil {
		return "", e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	req, e := http.NewRequestWithContext(ctx, "GET", r.URL, nil)
	if e != nil {
		return "", e
	}
	resp, e := c.httpClient().Do(req)
	if e != nil {
		return "", e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("download HTTP %d", resp.StatusCode)
	}
	h := sha256.New()
	reader := io.LimitReader(resp.Body, r.Asset.Size+1)
	var n int64
	buf := make([]byte, 128*1024)
	for {
		count, re := reader.Read(buf)
		if count > 0 {
			if _, e = io.MultiWriter(f, h).Write(buf[:count]); e != nil {
				return "", e
			}
			n += int64(count)
			if progress != nil {
				progress(n, r.Asset.Size)
			}
		}
		if re == io.EOF {
			break
		}
		if re != nil {
			return "", re
		}
	}
	if n != r.Asset.Size || hex.EncodeToString(h.Sum(nil)) != r.Asset.SHA256 {
		return "", errors.New("archive size or SHA-256 mismatch")
	}
	if e = f.Sync(); e != nil {
		return "", e
	}
	if e = f.Close(); e != nil {
		return "", e
	}
	path := filepath.Join(dir, r.Asset.Name)
	if e = os.Rename(f.Name(), path); e != nil {
		return "", e
	}
	return path, nil
}
