package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func signedRelease(t *testing.T, body []byte) (*Client, *Release) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	m := Manifest{Version: "1.2.3"}
	hash := sha256.Sum256(body)
	for _, p := range []string{"ntwire", "ntwire-gui"} {
		for _, s := range []string{"linux", "darwin", "windows"} {
			for _, a := range []string{"amd64", "arm64"} {
				n, e := AssetName(p, m.Version, s, a)
				if e == nil {
					m.Assets = append(m.Assets, Asset{p, s, a, n, int64(len(body)), hex.EncodeToString(hash[:])})
				}
			}
		}
	}
	raw, _ := json.Marshal(m)
	r := &Release{Manifest: m, Raw: raw, Signature: ed25519.Sign(key, raw)}
	for _, a := range m.Assets {
		if a.Product == "ntwire" && a.OS == runtime.GOOS && a.Arch == runtime.GOARCH {
			r.Asset = a
		}
	}
	return &Client{Key: pub, HTTP: http.DefaultClient}, r
}
func TestNewer(t *testing.T) {
	for _, tt := range []struct {
		a, b       string
		want, fail bool
	}{{"v1.2.3", "1.2.2", true, false}, {"1.10.0", "1.9.99", true, false}, {"1.2.3+foo", "v1.2.3", false, false}, {"1.2.3", "2.0.0", false, false}, {"1.2.3-rc.1", "1.0.0", false, true}, {"1.2.3", "dev", false, true}, {"01.2.3", "1.0.0", false, true}, {"1.2", "1.0.0", false, true}, {"1.2.3+", "1.0.0", false, true}} {
		t.Run(tt.a+"_"+tt.b, func(t *testing.T) {
			got, e := Newer(tt.a, tt.b)
			if got != tt.want || (e != nil) != tt.fail {
				t.Fatalf("got %v %v", got, e)
			}
		})
	}
}
func TestPlatformSelection(t *testing.T) {
	for _, tt := range []struct{ p, s, a, want string }{{"ntwire", "darwin", "amd64", "ntwire_1.2.3_darwin_amd64.tar.gz"}, {"ntwire-gui", "darwin", "arm64", "ntwire-gui_v1.2.3_darwin_arm64.zip"}, {"ntwire-gui", "windows", "arm64", "ntwire-gui_1.2.3_windows_arm64.zip"}, {"ntwire-gui", "darwin", "amd64", ""}, {"ntwire-server", "linux", "amd64", ""}, {"ntwire", "linux", "386", ""}} {
		got, e := AssetName(tt.p, "1.2.3", tt.s, tt.a)
		if got != tt.want || (e != nil) != (tt.want == "") {
			t.Fatalf("%+v: %s %v", tt, got, e)
		}
	}
}
func TestVerifyManifest(t *testing.T) {
	c, r := signedRelease(t, []byte("archive"))
	if _, e := Verify(r.Raw, r.Signature, c.Key); e != nil {
		t.Fatal(e)
	}
	if _, e := Verify(r.Raw, r.Signature, nil); e == nil {
		t.Fatal("accepted unprovisioned key")
	}
	bad := append([]byte(nil), r.Raw...)
	bad[0] ^= 1
	if _, e := Verify(bad, r.Signature, c.Key); e == nil {
		t.Fatal("accepted tampering")
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	for _, variant := range []string{"missing", "duplicate", "path", "hash", "size", "prerelease"} {
		t.Run(variant, func(t *testing.T) {
			var m Manifest
			json.Unmarshal(r.Raw, &m)
			switch variant {
			case "missing":
				m.Assets = m.Assets[:1]
			case "duplicate":
				m.Assets = append(m.Assets, m.Assets[0])
			case "path":
				m.Assets[0].Name = "../ntwire"
			case "hash":
				m.Assets[0].SHA256 = "bad"
			case "size":
				m.Assets[0].Size = maxArchive + 1
			case "prerelease":
				m.Version = "1.2.3-beta"
			}
			raw, _ := json.Marshal(m)
			if _, e := Verify(raw, ed25519.Sign(key, raw), pub); e == nil {
				t.Fatal("accepted invalid manifest")
			}
		})
	}
}
func TestCheckRelease(t *testing.T) {
	c, r := signedRelease(t, []byte("archive"))
	missing := ""
	status := 200
	prerelease := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/releases/latest":
			if status != 200 {
				w.WriteHeader(status)
				return
			}
			assets := []map[string]any{}
			for _, a := range r.Manifest.Assets {
				if a.Name != missing {
					assets = append(assets, map[string]any{"name": a.Name, "size": a.Size, "browser_download_url": "https://example.org/" + a.Name})
				}
			}
			for _, name := range []string{"update-manifest.json", "update-manifest.sig"} {
				if name != missing {
					assets = append(assets, map[string]any{"name": name, "browser_download_url": "https://" + req.Host + "/" + name})
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"tag_name": "v1.2.3", "assets": assets, "prerelease": prerelease})
		case "/update-manifest.json":
			w.Write(r.Raw)
		case "/update-manifest.sig":
			fmt.Fprint(w, base64.StdEncoding.EncodeToString(r.Signature))
		default:
			http.NotFound(w, req)
		}
	}))
	defer srv.Close()
	c.HTTP = srv.Client()
	c.API = srv.URL
	for _, v := range []string{"1.0.0", "dev"} {
		got, e := c.Check(context.Background(), "ntwire", v)
		if e != nil || got == nil {
			t.Fatalf("check %s: %v %v", v, got, e)
		}
	}
	for _, v := range []string{"1.2.3", "2.0.0"} {
		got, e := c.Check(context.Background(), "ntwire", v)
		if e != nil || got != nil {
			t.Fatalf("non newer: %v %v", got, e)
		}
	}
	for _, name := range []string{r.Manifest.Assets[0].Name, "update-manifest.json", "update-manifest.sig"} {
		missing = name
		if _, e := c.Check(context.Background(), "ntwire", "1.0.0"); e == nil {
			t.Fatal("accepted incomplete release", name)
		}
	}
	missing = ""
	prerelease = true
	if _, e := c.Check(context.Background(), "ntwire", "1.0.0"); e == nil {
		t.Fatal("accepted prerelease")
	}
	prerelease = false
	status = 429
	if _, e := c.Check(context.Background(), "ntwire", "1.0.0"); e == nil || !strings.Contains(e.Error(), "429") {
		t.Fatalf("rate limit %v", e)
	}
	srv.Close()
	if _, e := c.Check(context.Background(), "ntwire", "1.0.0"); e == nil {
		t.Fatal("offline check succeeded")
	}
}
func TestDownloadVerificationAndCancellation(t *testing.T) {
	body := []byte("signed archive")
	c, r := signedRelease(t, body)
	response := body
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(response) }))
	defer srv.Close()
	c.HTTP = srv.Client()
	r.URL = srv.URL
	dir := t.TempDir()
	var n int64
	file, e := c.Download(context.Background(), r, dir, func(v, total int64) { n = v })
	if e != nil || n != int64(len(body)) {
		t.Fatal(file, e, n)
	}
	b, _ := os.ReadFile(file)
	if string(b) != string(body) {
		t.Fatal("wrong bytes")
	}
	os.Remove(file)
	for _, bad := range [][]byte{[]byte("corrupted!!!!!"), body[:3], append(body, 'x')} {
		response = bad
		if _, e = c.Download(context.Background(), r, dir, nil); e == nil {
			t.Fatal("accepted corruption")
		}
		files, _ := os.ReadDir(dir)
		if len(files) != 0 {
			t.Fatal("partial download left in cache")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = c.Download(ctx, r, dir, nil); e == nil {
		t.Fatal("cancel ignored")
	}
	r.URL = "http://example.org"
	if _, e = c.Download(context.Background(), r, dir, nil); e == nil {
		t.Fatal("accepted HTTP archive")
	}
}
func TestInstallRejectsCorruptAndDowngrade(t *testing.T) {
	c, r := signedRelease(t, []byte("signed archive"))
	dir := t.TempDir()
	target := filepath.Join(dir, expectedTarget(r.Asset))
	os.WriteFile(target, []byte("old"), 0755)
	archive := filepath.Join(dir, "archive")
	os.WriteFile(archive, []byte("corrupt"), 0600)
	for _, v := range []string{"dev", "1.2.3", "2.0.0", "1.0.0"} {
		if e := c.Install(Job{Release: *r, Archive: archive, Target: target, Current: v}); e == nil {
			t.Fatal("accepted invalid install", v)
		}
	}
	got, _ := os.ReadFile(target)
	if string(got) != "old" {
		t.Fatal("changed current app")
	}
}

// Ensure a server cannot redirect an authenticated download to plain HTTP.
func TestHTTPRedirectIsRejected(t *testing.T) {
	c, r := signedRelease(t, []byte("archive"))
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/plain", http.StatusFound)
	}))
	defer srv.Close()
	c.HTTP = srv.Client()
	r.URL = srv.URL
	if _, e := c.Download(context.Background(), r, t.TempDir(), nil); e == nil || !strings.Contains(e.Error(), "HTTPS") {
		t.Fatalf("redirect result %v", e)
	}
}
