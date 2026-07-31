package singleinstance

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testClient() *http.Client {
	return &http.Client{Timeout: 2 * time.Second}
}

func TestLockPathRejectsEmptyGuiConfigPath(t *testing.T) {
	if _, err := LockPath(""); err == nil {
		t.Fatal("LockPath(\"\") should error rather than silently resolving under the current directory")
	}
}

func TestLockPathIsColocatedWithGuiConfig(t *testing.T) {
	got, err := LockPath("/home/user/.ntwire/gui.yaml")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join("/home/user/.ntwire", lockFileName)
	if got != want {
		t.Errorf("LockPath = %q, want %q", got, want)
	}
}

func TestExistingReturnsNilWhenNoLockFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), lockFileName)
	got, err := Existing(path, testClient())
	if err != nil || got != nil {
		t.Fatalf("Existing on a missing file = (%v, %v), want (nil, nil)", got, err)
	}
}

func TestWriteThenExistingFindsALiveServer(t *testing.T) {
	var gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.URL.Query().Get("token")
		if gotToken != "s3cr3t" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), lockFileName)
	info := Info{PID: 1234, URL: srv.URL, Token: "s3cr3t"}
	if err := Write(path, info); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := Existing(path, testClient())
	if err != nil {
		t.Fatalf("Existing: %v", err)
	}
	if got == nil {
		t.Fatal("Existing = nil, want the live instance's Info")
	}
	if *got != info {
		t.Errorf("Existing = %+v, want %+v", *got, info)
	}
	if gotToken != "s3cr3t" {
		t.Errorf("server observed token %q, want the one recorded in the lock file", gotToken)
	}
}

// TestExistingReturnsNilForADeadURL is the actual reason this package
// probes instead of trusting the file's existence: a process that
// crashed without cleaning up its lock file must not be mistaken for a
// live instance.
func TestExistingReturnsNilForADeadURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	deadURL := srv.URL
	srv.Close() // nothing listens here anymore

	path := filepath.Join(t.TempDir(), lockFileName)
	if err := Write(path, Info{PID: 1, URL: deadURL, Token: "x"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := Existing(path, testClient())
	if err != nil || got != nil {
		t.Fatalf("Existing for a dead URL = (%v, %v), want (nil, nil)", got, err)
	}
}

func TestExistingReturnsNilForWrongToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "the-real-token" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), lockFileName)
	// Simulates a lock file whose recorded token no longer matches the
	// server behind its URL (e.g. hand-edited, or from an unrelated run).
	if err := Write(path, Info{PID: 1, URL: srv.URL, Token: "stale-token"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := Existing(path, testClient())
	if err != nil || got != nil {
		t.Fatalf("Existing with a wrong token = (%v, %v), want (nil, nil)", got, err)
	}
}

// poisonTransport panics if ever asked to perform a request -- used to
// prove a non-loopback URL is rejected before any network call, not
// merely that the call happens to fail.
type poisonTransport struct{}

func (poisonTransport) RoundTrip(*http.Request) (*http.Response, error) {
	panic("singleinstance: must not probe a non-loopback URL")
}

func TestExistingRejectsNonLoopbackURLWithoutProbing(t *testing.T) {
	path := filepath.Join(t.TempDir(), lockFileName)
	if err := Write(path, Info{PID: 1, URL: "http://example.com:8080", Token: "x"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	client := &http.Client{Transport: poisonTransport{}, Timeout: 2 * time.Second}
	got, err := Existing(path, client)
	if err != nil || got != nil {
		t.Fatalf("Existing for a non-loopback URL = (%v, %v), want (nil, nil)", got, err)
	}
}

func TestExistingReturnsNilForCorruptLockFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), lockFileName)
	if err := os.WriteFile(path, []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Existing(path, testClient())
	if err != nil || got != nil {
		t.Fatalf("Existing for a corrupt file = (%v, %v), want (nil, nil)", got, err)
	}
}

func TestRemoveOnMissingFileIsNotAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), lockFileName)
	if err := Remove(path); err != nil {
		t.Errorf("Remove on a missing file = %v, want nil", err)
	}
}

func TestWriteThenRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), lockFileName)
	if err := Write(path, Info{PID: 1, URL: "http://127.0.0.1:1", Token: "x"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	got, err := Existing(path, testClient())
	if err != nil || got != nil {
		t.Fatalf("Existing after Remove = (%v, %v), want (nil, nil)", got, err)
	}
}
