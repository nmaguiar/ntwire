package client

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// Status is a local, non-secret record for the currently running connect
// process. It intentionally contains neither SSH keys nor session tokens.
type Status struct {
	PID            int      `json:"pid"`
	Server         string   `json:"server"`
	UIURL          string   `json:"ui_url"`
	LocalAddresses []string `json:"local_addresses"`
	UpdatedAt      string   `json:"updated_at"`
}

func DefaultStatusFile() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(h, ".nwire", "status.json")
}

func ReadStatus(path string) (Status, error) {
	if path == "" {
		path = DefaultStatusFile()
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Status{}, err
	}
	var s Status
	if err = json.Unmarshal(b, &s); err != nil {
		return Status{}, err
	}
	if s.PID < 1 {
		return Status{}, errors.New("invalid nwire status file")
	}
	return s, nil
}

func writeStatus(path string, s Status) error {
	if path == "" {
		path = DefaultStatusFile()
	}
	if path == "" {
		return nil
	}
	s.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}
