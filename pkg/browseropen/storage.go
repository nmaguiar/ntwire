package browseropen

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ProfileSettings describes one tunnel's optional local browser settings.
type ProfileSettings struct {
	Folder string `yaml:"folder,omitempty"`
	Name   string `yaml:"name,omitempty"`
}

// ValidateStorage validates local folder settings without touching the filesystem.
func ValidateStorage(folder string, profiles map[string]ProfileSettings) error {
	if err := validateFolder(folder); err != nil {
		return err
	}
	for tunnel, p := range profiles {
		if strings.TrimSpace(tunnel) == "" || strings.ContainsAny(tunnel+p.Name, "\x00\r\n") {
			return errors.New("invalid tunnel or browser profile name")
		}
		if err := validateFolder(p.Folder); err != nil {
			return fmt.Errorf("tunnel %q: %w", tunnel, err)
		}
	}
	return nil
}

func validateFolder(folder string) error {
	if folder != "" && (!filepath.IsAbs(folder) || strings.ContainsAny(folder, "\x00\r\n")) {
		return fmt.Errorf("browser profiles folder must be an absolute local path: %q", folder)
	}
	return nil
}

// SelectProfile applies the client-wide folder when the tunnel has no override.
func SelectProfile(folder string, p ProfileSettings) ProfileSettings {
	if p.Folder == "" {
		p.Folder = folder
	}
	return p
}

func defaultFolder() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ntwire", "browser-profiles"), nil
}

func storageID(value string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(value)))
}

func profileLocation(key string, p ProfileSettings) (string, error) {
	if err := ValidateStorage(p.Folder, map[string]ProfileSettings{key: p}); err != nil {
		return "", err
	}
	name := sanitize(key)
	if !filepath.IsLocal(name) || name == "." || name == ".." {
		return "", fmt.Errorf("invalid browser profile key %q", key)
	}
	if p.Folder == "" {
		base, err := defaultFolder()
		if err != nil {
			return "", err
		}
		return filepath.Join(base, name), nil
	}
	return filepath.Join(p.Folder, "ntwire-"+storageID(key)), nil
}

// ProfilePath previews the profile's user-data directory without creating it.
func ProfilePath(key string, p ProfileSettings) (string, error) {
	path, err := profileLocation(key, p)
	if err != nil || p.Folder == "" {
		return path, err
	}
	base, err := canonicalFolder(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	if err := checkCustomFolder(base); err != nil {
		return "", err
	}
	return filepath.Join(base, filepath.Base(path)), nil
}

// canonicalFolder resolves the existing ancestors of a folder that may not
// exist yet, so previews and launches agree even when a parent is a symlink.
func canonicalFolder(path string) (string, error) {
	canonical, err := filepath.EvalSymlinks(path)
	if err == nil {
		return canonical, nil
	}
	parent := filepath.Dir(path)
	if !errors.Is(err, os.ErrNotExist) || parent == path {
		return "", err
	}
	base, err := canonicalFolder(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(base, filepath.Base(path)), nil
}

func checkCustomFolder(folder string) error {
	base, err := defaultFolder()
	if err != nil {
		return err
	}
	for _, reserved := range []string{base, base + "-registry"} {
		reserved, err = canonicalFolder(reserved)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(reserved, folder)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return errors.New("choose a folder outside ntwire's built-in browser profile directories, or leave the folder blank")
		}
	}
	return nil
}

const profileMarker = ".ntwire-profile.json"

type managedProfile struct {
	Key  string
	Path string
	Name string
}

func writeProfileRecord(path string, record managedProfile) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".record-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	err = json.NewEncoder(f).Encode(record)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func readProfileRecord(path string) (managedProfile, error) {
	var record managedProfile
	data, err := os.ReadFile(path)
	if err != nil {
		return record, err
	}
	err = json.Unmarshal(data, &record)
	return record, err
}

func registryFolder() (string, error) {
	base, err := defaultFolder()
	if err != nil {
		return "", err
	}
	return base + "-registry", nil
}

func prepareProfile(key string, p ProfileSettings) (string, error) {
	path, err := ProfilePath(key, p)
	if err != nil {
		return "", err
	}
	base := filepath.Dir(path)
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", err
	}
	if p.Folder == "" && p.Name == "" {
		// Preserve legacy browser-created directories. An existing marker
		// needs updating when the user clears a previously saved label.
		if _, err := os.Lstat(filepath.Join(path, profileMarker)); errors.Is(err, os.ErrNotExist) {
			return path, nil
		}
	}
	canonical, err := filepath.EvalSymlinks(base)
	if err != nil {
		return "", err
	}
	if p.Folder != "" {
		if err := checkCustomFolder(canonical); err != nil {
			return "", err
		}
	}
	path = filepath.Join(canonical, filepath.Base(path))
	record := managedProfile{Key: key, Path: path, Name: p.Name}
	marker := filepath.Join(path, profileMarker)
	err = os.Mkdir(path, 0o700)
	created := err == nil
	if errors.Is(err, os.ErrExist) {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() {
			return "", fmt.Errorf("browser profile path is not a directory: %s", path)
		}
		if p.Folder != "" {
			if _, err := profileOwner(record); err != nil {
				return "", err
			}
		}
	} else if err != nil {
		return "", err
	}
	if err := writeProfileRecord(marker, record); err != nil {
		if created {
			_ = os.Remove(path)
		}
		return "", err
	}
	if p.Folder != "" {
		registry, err := registryFolder()
		if err != nil {
			return "", err
		}
		if err := os.MkdirAll(registry, 0o700); err != nil {
			return "", err
		}
		if err := writeProfileRecord(filepath.Join(registry, storageID(path)+".json"), record); err != nil {
			return "", err
		}
	}
	return path, nil
}

func profileOwner(record managedProfile) (managedProfile, error) {
	owner, err := readProfileRecord(filepath.Join(record.Path, profileMarker))
	if err != nil || owner.Path != record.Path || owner.Key != record.Key {
		return owner, fmt.Errorf("browser profile directory is not managed by ntwire: %s", record.Path)
	}
	return owner, nil
}

func managedProfiles() ([]managedProfile, error) {
	registry, err := registryFolder()
	if err != nil {
		return nil, err
	}
	items, err := os.ReadDir(registry)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var records []managedProfile
	for _, entry := range items {
		if entry.Type().IsRegular() && filepath.Ext(entry.Name()) == ".json" {
			record, err := readProfileRecord(filepath.Join(registry, entry.Name()))
			if err != nil {
				return nil, err
			}
			if filepath.IsAbs(record.Path) && entry.Name() == storageID(record.Path)+".json" &&
				filepath.Base(record.Path) == "ntwire-"+storageID(record.Key) {
				records = append(records, record)
			}
		}
	}
	return records, nil
}

// CleanConfiguredProfile removes the current directory for a tunnel.
func CleanConfiguredProfile(key string, p ProfileSettings) error {
	if p.Folder == "" {
		return CleanProfile(key)
	}
	path, err := ProfilePath(key, p)
	if err != nil {
		return err
	}
	return CleanProfile("custom:" + storageID(path))
}

func cleanManagedProfile(record managedProfile) error {
	parent := filepath.Dir(record.Path)
	base, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return err
	}
	if base != parent {
		return fmt.Errorf("browser profile parent has changed: %s", parent)
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return err
	}
	defer root.Close()
	name := filepath.Base(record.Path)
	info, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("browser profile path is not a directory: %s", record.Path)
	}
	data, err := root.ReadFile(filepath.Join(name, profileMarker))
	var owner managedProfile
	if err != nil || json.Unmarshal(data, &owner) != nil || owner.Path != record.Path || owner.Key != record.Key {
		return fmt.Errorf("browser profile directory is not managed by ntwire: %s", record.Path)
	}
	if _, err := root.Lstat(filepath.Join(name, "SingletonLock")); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("browser profile still in use or cannot be checked: %s", record.Path)
	}
	return root.RemoveAll(name)
}

// ProfileGuideURL describes how to populate a dedicated browser profile.
const ProfileGuideURL = "https://github.com/nmaguiar/ntwire/blob/main/docs/CONFIGURATION.md#socks-browser-profiles"

// DisplayName returns the user label or the original tunnel key.
func (p ProfileEntry) DisplayName() string {
	if p.Name != "" {
		return p.Name
	}
	if p.TunnelKey != "" {
		return p.TunnelKey
	}
	return p.Key
}
