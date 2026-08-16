package client

import (
	"os"
	"testing"

	"github.com/zalando/go-keyring"
)

// TestMain swaps the OS credential store for an in-memory mock so tests
// exercise the real native-store code path deterministically, instead of
// silently falling back to the file cache (or failing) depending on
// whatever secret-store daemon happens to be running on the host.
func TestMain(m *testing.M) {
	keyring.MockInit()
	os.Exit(m.Run())
}
