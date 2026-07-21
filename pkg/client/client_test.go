package client

import (
	"bytes"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/nmaguiar/ntwire/pkg/wgnet"
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

func TestReplacePortSwitchesLocalListener(t *testing.T) {
	old, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("sandbox does not permit loopback listeners")
		}
		t.Fatal(err)
	}
	defer old.Close()
	c := &Connection{
		Stack:          &wgnet.Stack{},
		tunnels:        []*localTunnel{{name: "database", listener: old, localAddr: old.Addr().String()}},
		LocalAddresses: []string{old.Addr().String()},
		statusFile:     t.TempDir() + "/status.json",
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()
	got, err := c.ReplacePort("database", port)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(got, ":"+strconv.Itoa(port)) || c.LocalAddresses[0] != got {
		t.Fatalf("replacement address = %q, addresses = %#v", got, c.LocalAddresses)
	}
	if _, err := net.Dial("tcp", got); err != nil {
		t.Fatalf("new listener is not accepting: %v", err)
	}
	if _, err := net.Dial("tcp", old.Addr().String()); err == nil {
		t.Fatal("old listener still accepts connections")
	}
	_ = c.tunnels[0].listener.Close()
}

func TestListenLocalUsesConfiguredPortAndFallsBackWhenOccupied(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("sandbox does not permit loopback listeners")
		}
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}

	l, err := listenLocal(port, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := l.Addr().(*net.TCPAddr).Port; got != port {
		t.Fatalf("configured port = %d, want %d", got, port)
	}
	_ = l.Close()

	occupied, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	l, err = listenLocal(port, true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if got := l.Addr().(*net.TCPAddr).Port; got == port {
		t.Fatalf("fallback retained occupied port %d", port)
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

func TestCountingWriterUpdatesTunnelStatsWhileStreaming(t *testing.T) {
	tunnel := &localTunnel{}
	var outgoing, incoming bytes.Buffer
	if _, err := (countingWriter{w: &outgoing, counter: &tunnel.toTunnel}).Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if _, err := (countingWriter{w: &incoming, counter: &tunnel.fromTunnel}).Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	got := tunnel.stats()
	if got.BytesToTunnel != uint64(len("request")) || got.BytesFromTunnel != uint64(len("response")) {
		t.Fatalf("stats = %#v, want request and response byte counts", got)
	}
}
