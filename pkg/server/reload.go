package server

import (
	"github.com/fsnotify/fsnotify"
	"log/slog"
	"path/filepath"
)

// WatchConfig watches the parent directory, which also handles Kubernetes
// ConfigMap symlink swaps. It returns when the watcher is closed.
func WatchConfig(path string, s *Server, log *slog.Logger) (*fsnotify.Watcher, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	if err = w.Add(filepath.Dir(path)); err != nil {
		w.Close()
		return nil, err
	}
	// Keys are independently watched so revocation takes effect without a YAML
	// touch. Watching the directory also handles Kubernetes projected volumes.
	// An OIDC-only config has no keys directory to watch.
	keysDir := s.Config.Auth.AuthorizedKeysDir
	if keysDir != "" {
		if err = w.Add(keysDir); err != nil {
			w.Close()
			return nil, err
		}
	}
	go func() {
		for {
			select {
			case e, ok := <-w.Events:
				if !ok {
					return
				}
				if filepath.Clean(e.Name) != filepath.Clean(path) && (keysDir == "" || filepath.Dir(filepath.Clean(e.Name)) != filepath.Clean(keysDir)) {
					continue
				}
				if e.Has(fsnotify.Write | fsnotify.Create | fsnotify.Rename) {
					c, err := LoadConfig(path)
					if err != nil {
						log.Warn("configuration reload rejected", "error", err)
						continue
					}
					s.Reload(c)
				}
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
