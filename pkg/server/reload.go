package server

import (
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// WatchConfig watches the configuration directory, including projected-volume
// pointer swaps, and the authorized-key directory. Closing the watcher stops it.
func WatchConfig(path string, s *Server, log *slog.Logger) (*fsnotify.Watcher, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	configDir := filepath.Dir(path)
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	if err = w.Add(configDir); err != nil {
		w.Close()
		return nil, err
	}
	s.mu.Lock()
	keysDir := s.Config.Auth.AuthorizedKeysDir
	s.mu.Unlock()
	if keysDir != "" {
		keysDir, err = filepath.Abs(keysDir)
		if err == nil {
			err = w.Add(keysDir)
		}
		if err != nil {
			w.Close()
			return nil, err
		}
	}
	target, _ := filepath.EvalSymlinks(path)
	go func() {
		// Some watcher backends follow existing symlinks and report no event
		// when an intermediate projection pointer is replaced. Detect that
		// change independently without reading the file on every tick.
		projectionTick := time.NewTicker(250 * time.Millisecond)
		defer projectionTick.Stop()
		// Atomic replacements commonly generate several events. Read only
		// after the short burst settles, retaining the last valid config.
		timer := time.NewTimer(time.Hour)
		timer.Stop()
		defer timer.Stop()
		var pending <-chan time.Time
		for {
			select {
			case <-projectionTick.C:
				if next, err := filepath.EvalSymlinks(path); err == nil && next != target {
					target = next
					timer.Reset(25 * time.Millisecond)
					pending = timer.C
				}
			case e, ok := <-w.Events:
				if !ok {
					return
				}
				name := filepath.Clean(e.Name)
				parent := filepath.Dir(name)
				projection := parent == configDir && strings.HasPrefix(filepath.Base(name), "..")
				keyEvent := keysDir != "" && (parent == keysDir || name == keysDir)
				if name != path && !projection && !keyEvent {
					continue
				}
				if !e.Has(fsnotify.Write | fsnotify.Create | fsnotify.Rename | fsnotify.Remove) {
					continue
				}
				timer.Reset(25 * time.Millisecond)
				pending = timer.C
			case <-pending:
				pending = nil
				c, err := LoadConfig(path)
				if err != nil {
					log.Warn("configuration reload rejected", "error", err)
					continue
				}
				nextKeys := c.Auth.AuthorizedKeysDir
				if nextKeys != "" {
					nextKeys, err = filepath.Abs(nextKeys)
					if err == nil && nextKeys != keysDir {
						err = w.Add(nextKeys)
					}
					if err != nil {
						log.Warn("configuration key watch rejected", "error", err)
						continue
					}
				}
				s.Reload(c)
				if keysDir != "" && keysDir != nextKeys && keysDir != configDir {
					_ = w.Remove(keysDir)
				}
				keysDir = nextKeys
			case err, ok := <-w.Errors:
				if !ok {
					return
				}
				log.Warn("configuration watch error", "error", err)
			}
		}
	}()
	return w, nil
}
