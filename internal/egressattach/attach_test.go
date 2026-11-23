package egressattach

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/internal/localproxy"
	"github.com/nmaguiar/ntwire/pkg/egressrouter"
)

type dialFunc func(context.Context, egressrouter.Destination) (net.Conn, error)

func (d dialFunc) DialDestination(ctx context.Context, dst egressrouter.Destination) (net.Conn, error) {
	return d(ctx, dst)
}

func TestAttachmentIdentityAndHalfClose(t *testing.T) {
	root := filepath.Join(t.TempDir(), "egress")
	path, _ := ProfilePath(root, "test")
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	go func() {
		c, err := origin.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		req, _ := io.ReadAll(c)
		_, _ = c.Write(append([]byte("ack:"), req...))
	}()
	member := egressrouter.Member{ProfileID: "test", Tunnel: "internet", ExpectedServer: "https://example.net"}
	source := func(m egressrouter.Member) egressrouter.Candidate {
		if m != member {
			return egressrouter.Candidate{Reason: "grant_unavailable"}
		}
		return egressrouter.Candidate{Generation: "one", Dialer: dialFunc(func(ctx context.Context, dst egressrouter.Destination) (net.Conn, error) {
			if dst.Host != "remote.invalid" || dst.Port != 443 {
				t.Errorf("unexpected destination %+v", dst)
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp", origin.Addr().String())
		})}
	}
	service, err := Start(path, source, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if duplicate, err := Start(path, source, nil); err == nil {
		duplicate.Close()
		t.Fatal("second publisher acquired the same ID")
	}
	registry := NewRegistry(root)
	registry.Refresh(t.Context(), []egressrouter.Member{member})
	candidate := registry.Candidate(member)
	if candidate.Dialer == nil {
		t.Fatalf("publisher unavailable: %+v", candidate)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	conn, err := candidate.Dialer.DialDestination(ctx, egressrouter.Destination{Host: "remote.invalid", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = io.WriteString(conn, "payload"); err != nil {
		t.Fatal(err)
	}
	if err = localproxy.CloseWrite(conn); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(conn)
	if err != nil || string(reply) != "ack:payload" {
		t.Fatalf("reply=%q err=%v", reply, err)
	}
	service.Close()
	if _, err = os.Stat(filepath.Join(path, "discovery.json")); !os.IsNotExist(err) {
		t.Fatalf("instance record still exists, %v", err)
	}
}
func TestAttachmentRejectsWrongTLSIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "publishers", "a")
	first, err := Start(path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	stale := first.info
	first.Close()
	second, err := Start(path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	stale.Address = second.info.Address
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, err = (attached{info: stale}).DialDestination(ctx, egressrouter.Destination{Host: "remote.invalid", Port: 443})
	var failure *egressrouter.Failure
	if !errors.As(err, &failure) || failure.Retry || failure.Class != "attachment_identity" {
		t.Fatalf("unexpected stale identity result %v", err)
	}
}
