package config

import (
	"crypto/rand"
	"encoding/hex"
)

// NewID returns a new random profile identifier, stable for the profile's
// lifetime -- it names that profile's status file
// (~/.ntwire/gui/status-<id>.json) and its LaunchAgent/autostart registration
// key, so it must not change once assigned.
func NewID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read on any supported platform only fails if the OS
		// entropy source is unavailable, which is unrecoverable anyway; a
		// panic here surfaces that immediately instead of silently handing
		// out a colliding empty ID.
		panic("gui/config: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}
