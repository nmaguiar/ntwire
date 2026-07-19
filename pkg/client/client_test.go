package client

import (
	"os"
	"strings"
	"testing"
)

func TestTrustServerPersistsPin(t *testing.T) {
	path := t.TempDir() + "/known_servers"
	if err := TrustServer(path, "server.example:8443", "SHA256:example"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "server.example:8443") || !strings.Contains(string(b), "SHA256:example") {
		t.Fatalf("pin was not persisted: %s", b)
	}
}

func TestStatusRoundTrip(t *testing.T) {
	path := t.TempDir() + "/status.json"
	want := Status{PID: 42, Server: "https://server.example", UIURL: "http://127.0.0.1:1234/?token=x", LocalAddresses: []string{"127.0.0.1:2345"}}
	if err := writeStatus(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadStatus(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.PID != want.PID || got.Server != want.Server || len(got.LocalAddresses) != 1 {
		t.Fatalf("unexpected status: %#v", got)
	}
}
