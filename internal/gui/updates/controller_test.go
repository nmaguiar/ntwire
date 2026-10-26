package updates

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/updater"
)

func testController(t *testing.T) *Controller {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	c := &Controller{ctx: ctx, cancel: cancel, client: updater.NewClient(), dir: t.TempDir(), status: Status{Current: "1.0.0"}, preferences: func() Preferences { return Preferences{} }}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	c.client.Key = pub
	t.Cleanup(c.Close)
	return c
}
func waitIdle(t *testing.T, c *Controller) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c.Status().Busy == "" {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("controller remained busy")
}
func TestCheckSerializesAndCancellation(t *testing.T) {
	c := testController(t)
	entered := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() }))
	defer srv.Close()
	c.client.API = srv.URL
	c.client.HTTP = srv.Client()
	if e := c.Check(); e != nil {
		t.Fatal(e)
	}
	<-entered
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := c.Check(); e == nil {
				t.Error("concurrent check accepted")
			}
			_ = c.Status()
		}()
	}
	wg.Wait()
	c.Close()
	s := c.Status()
	if !strings.Contains(s.Error, "canceled") || !s.LastCheck.IsZero() {
		t.Fatalf("cancel status %+v", s)
	}
	if e := c.Download(); e == nil {
		t.Fatal("closed controller accepted operation")
	}
}
func TestSuccessfulCheckTimestampAndCache(t *testing.T) {
	c := testController(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"tag_name": "v1.0.0"})
	}))
	defer srv.Close()
	c.client.API = srv.URL
	c.client.HTTP = srv.Client()
	if e := c.Check(); e != nil {
		t.Fatal(e)
	}
	waitIdle(t, c)
	if c.Status().LastCheck.IsZero() {
		t.Fatal("successful check not persisted")
	}
	b, e := os.ReadFile(filepath.Join(c.dir, "state.json"))
	if e != nil {
		t.Fatal(e)
	}
	var state cached
	json.Unmarshal(b, &state)
	if state.LastCheck.IsZero() {
		t.Fatal("missing cached last check")
	}
	if e = c.Download(); e == nil {
		t.Fatal("download without release accepted")
	}
	if e = c.InstallOnExit(false); e == nil {
		t.Fatal("installed without ready download")
	}
}
func TestAutomaticChecksDisabledAndDevelopment(t *testing.T) {
	for _, dev := range []bool{false, true} {
		c := testController(t)
		if dev {
			c.status.Current = "dev"
		} else {
			c.preferences = func() Preferences { return Preferences{Disabled: true} }
		}
		c.Start()
		time.Sleep(20 * time.Millisecond)
		c.Close()
		if s := c.Status(); s.Busy != "" || s.Error != "" || !s.LastCheck.IsZero() {
			t.Fatalf("automatic check ran: %+v", s)
		}
	}
}
func TestPreferencesAndStateAreSeparate(t *testing.T) {
	// New may inspect only the test binary and this isolated cache; no home config.
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("LOCALAPPDATA", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	old := updater.PublicKey
	updater.PublicKey = base64.StdEncoding.EncodeToString(pub)
	defer func() { updater.PublicKey = old }()
	c := New("1.0.0", filepath.Join(t.TempDir(), "gui.yaml"), func() Preferences { return Preferences{Disabled: true} })
	defer c.Close()
	if c.dir == "" {
		t.Fatal("missing private cache")
	}
	c.mu.Lock()
	c.cache.LastCheck = time.Now()
	e := c.saveLocked()
	c.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	other := New("1.0.0", "other-config", c.preferences)
	defer other.Close()
	if other.dir == c.dir {
		t.Fatal("different config shares cache")
	}
	if !other.Status().LastCheck.IsZero() {
		t.Fatal("state leaked between installations")
	}
	if e = c.InstallOnExit(true); e == nil || errors.Is(e, context.Canceled) {
		t.Fatal("elevation requested without ready update", e)
	}
}

func TestElevationCancellationLeavesUpdateStaged(t *testing.T) {
	c := testController(t)
	c.status.Ready = true
	c.cache.Release = &updater.Release{}
	c.target = filepath.Join(t.TempDir(), "missing-parent", "ntwire-gui")
	called := false
	c.launch = func(j updater.Job, dir string, elevate bool) error {
		called = true
		if !elevate {
			t.Error("expected explicit elevation")
		}
		return errors.New("authorization cancelled")
	}
	if e := c.InstallOnExit(false); e == nil || called {
		t.Fatal("background operation attempted elevation", e)
	}
	if e := c.InstallOnExit(true); e == nil || !strings.Contains(e.Error(), "cancelled") {
		t.Fatal(e)
	}
	if s := c.Status(); !s.Ready || c.started || s.Error == "" {
		t.Fatalf("cancellation lost staged update: %+v", s)
	}
}

func TestAutomaticDownloadAndNotificationOnly(t *testing.T) {
	if _, e := updater.AssetName("ntwire-gui", "1.2.3", runtime.GOOS, runtime.GOARCH); e != nil {
		t.Skip("GUI has no release for this native platform")
	}
	for _, auto := range []bool{false, true} {
		t.Run(map[bool]string{false: "notifications", true: "automatic"}[auto], func(t *testing.T) {
			c := testController(t)
			c.preferences = func() Preferences { return Preferences{Automatic: auto} }
			body := []byte("verified archive")
			sum := sha256.Sum256(body)
			pub, key, _ := ed25519.GenerateKey(rand.Reader)
			c.client.Key = pub
			m := updater.Manifest{Version: "1.2.3"}
			var selected updater.Asset
			for _, product := range []string{"ntwire", "ntwire-gui"} {
				for _, goos := range []string{"linux", "darwin", "windows"} {
					for _, arch := range []string{"amd64", "arm64"} {
						name, e := updater.AssetName(product, m.Version, goos, arch)
						if e == nil {
							a := updater.Asset{Product: product, OS: goos, Arch: arch, Name: name, Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])}
							m.Assets = append(m.Assets, a)
							if product == "ntwire-gui" && goos == runtime.GOOS && arch == runtime.GOARCH {
								selected = a
							}
						}
					}
				}
			}
			raw, _ := json.Marshal(m)
			sig := ed25519.Sign(key, raw)
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/releases/latest":
					assets := []map[string]any{}
					for _, a := range m.Assets {
						assets = append(assets, map[string]any{"name": a.Name, "size": a.Size, "browser_download_url": "https://" + r.Host + "/" + a.Name})
					}
					for _, n := range []string{"update-manifest.json", "update-manifest.sig"} {
						assets = append(assets, map[string]any{"name": n, "browser_download_url": "https://" + r.Host + "/" + n})
					}
					json.NewEncoder(w).Encode(map[string]any{"tag_name": "v1.2.3", "assets": assets})
				case "/update-manifest.json":
					w.Write(raw)
				case "/update-manifest.sig":
					w.Write([]byte(base64.StdEncoding.EncodeToString(sig)))
				default:
					w.Write(body)
				}
			}))
			defer srv.Close()
			c.client.API = srv.URL
			c.client.HTTP = srv.Client()
			if e := c.Check(); e != nil {
				t.Fatal(e)
			}
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				s := c.Status()
				if s.Latest != "" && s.Busy == "" && (!auto || s.Ready) {
					break
				}
				time.Sleep(time.Millisecond)
			}
			s := c.Status()
			if s.Latest != "1.2.3" || s.Ready != auto || s.Error != "" {
				t.Fatalf("status %+v", s)
			}
			if !auto {
				if _, e := os.Stat(filepath.Join(c.dir, selected.Name)); !os.IsNotExist(e) {
					t.Fatal("notification-only check downloaded archive")
				}
				if e := c.Download(); e != nil {
					t.Fatal(e)
				}
				waitIdle(t, c)
				if !c.Status().Ready {
					t.Fatal("manual download did not stage", c.Status())
				}
			}
			if e := c.client.VerifyArchive(c.cache.Release, c.cache.Archive); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(c.cache.Archive, []byte("tampered"), 0600); e != nil {
				t.Fatal(e)
			}
			if e := c.client.VerifyArchive(c.cache.Release, c.cache.Archive); e == nil {
				t.Fatal("cached corruption accepted")
			}
		})
	}
}

func TestStatusRemainsResponsiveDuringAuthorization(t *testing.T) {
	c := testController(t)
	c.status.Ready = true
	c.cache.Release = &updater.Release{}
	c.target = filepath.Join(t.TempDir(), "ntwire-gui")
	entered, release := make(chan struct{}), make(chan struct{})
	c.launch = func(j updater.Job, dir string, elevate bool) error {
		close(entered)
		<-release
		return errors.New("cancelled")
	}
	done := make(chan error, 1)
	go func() { done <- c.InstallOnExit(true) }()
	<-entered
	if s := c.Status(); s.Busy != "awaiting administrator authorization" {
		t.Fatal(s)
	}
	if e := c.Download(); e == nil {
		t.Fatal("download accepted while authorization pending")
	}
	close(release)
	if e := <-done; e == nil {
		t.Fatal("cancellation missing")
	}
}
