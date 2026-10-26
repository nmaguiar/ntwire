// Package updates coordinates GUI preferences, serialized background work and
// private cached release evidence. It never activates an update while running.
package updates

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/nmaguiar/ntwire/pkg/updater"
)

type Preferences struct {
	Disabled  bool `json:"disabled"`
	Automatic bool `json:"automatic"`
}
type Status struct {
	Current           string    `json:"current"`
	Available         bool      `json:"available"`
	Latest            string    `json:"latest,omitempty"`
	Notes             string    `json:"notes,omitempty"`
	LastCheck         time.Time `json:"last_check"`
	Busy              string    `json:"busy,omitempty"`
	Downloaded        int64     `json:"downloaded"`
	Total             int64     `json:"total"`
	Ready             bool      `json:"ready"`
	Error             string    `json:"error,omitempty"`
	Limitation        string    `json:"limitation,omitempty"`
	NeedsAdmin        bool      `json:"needs_admin"`
	InstallationError string    `json:"installation_error,omitempty"`
	Installed         string    `json:"installed,omitempty"`
}
type cached struct {
	LastCheck time.Time        `json:"last_check"`
	Release   *updater.Release `json:"release,omitempty"`
	Archive   string           `json:"archive,omitempty"`
}
type Controller struct {
	mu          sync.Mutex
	client      *updater.Client
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	status      Status
	cache       cached
	dir, target string
	preferences func() Preferences
	launch      func(updater.Job, string, bool) error
	started     bool
}

func New(current, configPath string, prefs func() Preferences) *Controller {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Controller{client: updater.NewClient(), ctx: ctx, cancel: cancel, status: Status{Current: current}, preferences: prefs, launch: updater.StartHelper}
	self, e := os.Executable()
	if e == nil {
		c.target, e = updater.Target(self, "ntwire-gui")
	}
	if e != nil {
		c.status.Limitation = e.Error()
	}
	if e = updater.CanInstall(current); e != nil {
		c.status.Limitation = e.Error()
	}
	if c.target != "" {
		c.status.NeedsAdmin = updater.Writable(c.target) != nil
	}
	cacheDir, e := os.UserCacheDir()
	if e != nil {
		c.status.Limitation = e.Error()
		return c
	}
	key := sha256.Sum256([]byte(self + "\x00" + configPath))
	c.dir = filepath.Join(cacheDir, "ntwire", "updates", hex.EncodeToString(key[:8]))
	if e = os.MkdirAll(c.dir, 0700); e != nil {
		c.status.Limitation = e.Error()
		return c
	}
	if b, e := os.ReadFile(filepath.Join(c.dir, "state.json")); e == nil {
		_ = json.Unmarshal(b, &c.cache)
	}
	c.status.LastCheck = c.cache.LastCheck
	if r := c.cache.Release; r != nil {
		m, e := updater.Verify(r.Raw, r.Signature, c.client.Key)
		newer, ve := updater.Newer(m.Version, current)
		if e == nil && ve == nil && newer {
			c.status.Latest = m.Version
			c.status.Available = true
			c.status.Notes = r.Notes
			r.Manifest = m
			if filepath.Dir(c.cache.Archive) == c.dir && c.client.VerifyArchive(r, c.cache.Archive) == nil {
				c.status.Ready = true
			}
		} else {
			if e != nil {
				c.status.Error = "cached update rejected: " + e.Error()
			}
			c.cache.Release = nil
			c.cache.Archive = ""
		}
	}
	if b, e := os.ReadFile(c.resultPath()); e == nil {
		var result struct {
			Error     string `json:"error"`
			Installed string `json:"installed"`
		}
		if json.Unmarshal(b, &result) == nil {
			c.status.InstallationError = result.Error
			c.status.Installed = result.Installed
		}
		_ = os.Remove(c.resultPath())
	}
	return c
}
func (c *Controller) resultPath() string { return filepath.Join(c.dir, "result.json") }
func (c *Controller) Status() Status     { c.mu.Lock(); defer c.mu.Unlock(); return c.status }
func (c *Controller) saveLocked() error {
	if c.dir == "" {
		return errors.New("private update cache is unavailable")
	}
	b, e := json.Marshal(c.cache)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(c.dir, ".state-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	_, e = f.Write(b)
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return os.Rename(f.Name(), filepath.Join(c.dir, "state.json"))
}

// Start performs startup and periodic checks asynchronously. Failed checks do
// not advance LastCheck; a failed/offline session retries on a later hourly tick.
func (c *Controller) Start() {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		tick := time.NewTicker(time.Hour)
		defer tick.Stop()
		for {
			p := c.preferences()
			s := c.Status()
			if !p.Disabled && updater.CanInstall(s.Current) == nil && time.Since(s.LastCheck) >= 24*time.Hour {
				_ = c.Check()
			}
			select {
			case <-c.ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
}
func (c *Controller) Close() { c.mu.Lock(); c.cancel(); c.mu.Unlock(); c.wg.Wait() }
func (c *Controller) begin(work string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx.Err() != nil {
		return c.ctx.Err()
	}
	if c.status.Busy != "" || c.started {
		return errors.New("an update operation is already in progress")
	}
	c.status.Busy = work
	c.status.Error = ""
	c.wg.Add(1)
	return nil
}
func (c *Controller) Check() error {
	if e := c.begin("checking"); e != nil {
		return e
	}
	go func() {
		defer c.wg.Done()
		r, e := c.client.Check(c.ctx, "ntwire-gui", c.status.Current)
		c.mu.Lock()
		c.status.Busy = ""
		if e != nil {
			c.status.Error = e.Error()
		} else {
			c.cache.LastCheck = time.Now()
			c.status.LastCheck = c.cache.LastCheck
			if r != nil {
				if c.cache.Release == nil || c.cache.Release.Asset != r.Asset {
					c.cache.Archive = ""
					c.status.Ready = false
				}
				c.cache.Release = r
				c.status.Latest = r.Manifest.Version
				c.status.Available = true
				c.status.Notes = r.Notes
			} else {
				c.cache.Release = nil
				c.cache.Archive = ""
				c.status.Latest = c.status.Current
				c.status.Available = false
				c.status.Ready = false
			}
			if e = c.saveLocked(); e != nil {
				c.status.Error = e.Error()
			}
		}
		ready := c.status.Ready
		c.mu.Unlock()
		if e == nil && r != nil && !ready && c.preferences().Automatic {
			_ = c.Download()
		}
	}()
	return nil
}
func (c *Controller) Download() error {
	if e := c.begin("downloading"); e != nil {
		return e
	}
	c.mu.Lock()
	r := c.cache.Release
	limitation := c.status.Limitation
	c.status.Downloaded = 0
	c.mu.Unlock()
	if r == nil || limitation != "" {
		c.mu.Lock()
		c.status.Busy = ""
		c.mu.Unlock()
		c.wg.Done()
		if limitation != "" {
			return errors.New(limitation)
		}
		return errors.New("check for an available update first")
	}
	go func() {
		defer c.wg.Done()
		archive, e := c.client.Download(c.ctx, r, c.dir, func(n, total int64) { c.mu.Lock(); c.status.Downloaded = n; c.status.Total = total; c.mu.Unlock() })
		c.mu.Lock()
		defer c.mu.Unlock()
		c.status.Busy = ""
		if e != nil {
			c.status.Error = e.Error()
			return
		}
		c.cache.Archive = archive
		c.status.Ready = true
		if e = c.saveLocked(); e != nil {
			c.status.Ready = false
			c.status.Error = e.Error()
		}
	}()
	return nil
}

// InstallOnExit starts a helper waiting for this process. Elevation is allowed
// only from the explicit Settings action, never from automatic downloads/quit.
func (c *Controller) InstallOnExit(elevate bool) error { return c.install(elevate, false) }

// FinishOnExit prepares an already-staged update after Close has joined background
// work. It is synchronous and never elevates; only the owning exit path calls it.
func (c *Controller) FinishOnExit() error { return c.install(false, true) }
func (c *Controller) install(elevate, closing bool) error {
	c.mu.Lock()
	if c.ctx.Err() != nil && !closing {
		c.mu.Unlock()
		return c.ctx.Err()
	}

	if c.started {
		c.mu.Unlock()
		return nil
	}
	if !c.status.Ready || c.cache.Release == nil {
		c.mu.Unlock()
		return errors.New("no verified update is ready")
	}
	if c.status.Busy != "" {
		c.mu.Unlock()
		return errors.New("update operation is busy")
	}
	if c.status.Limitation != "" {
		e := errors.New(c.status.Limitation)
		c.mu.Unlock()
		return e
	}
	if e := updater.Writable(c.target); e != nil && !elevate {
		c.mu.Unlock()
		return e
	}
	j := updater.Job{Release: *c.cache.Release, Archive: c.cache.Archive, Target: c.target, Current: c.status.Current, Result: c.resultPath()}
	c.status.Busy = "preparing installation"
	if elevate {
		c.status.Busy = "awaiting administrator authorization"
	}
	if !closing {
		c.wg.Add(1)
	}
	c.mu.Unlock()
	if !closing {
		defer c.wg.Done()
	}
	e := c.launch(j, c.dir, elevate)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status.Busy = ""
	if e != nil {
		c.status.Error = e.Error()
		return e
	}
	c.started = true
	return nil
}
