package wstransport

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
)

func TestWebSocketBindRoundTrip(t *testing.T) {
	server := NewServer()
	serverFns, _, err := server.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := server.ServeHTTP(w, r, "session"); err != nil {
			t.Error(err)
		}
	})
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listeners unavailable: %v", err)
	}
	h := &httptest.Server{Listener: l, Config: &http.Server{Handler: handler}}
	h.Start()
	defer h.Close()
	client := NewClient("ws"+h.URL[len("http"):], h.Client(), nil)
	clientFns, _, err := client.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ep, err := client.ParseEndpoint("127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Send([][]byte{make([]byte, 16)}, ep); err != nil {
		t.Fatal(err)
	}
	serverBuf, serverSizes, serverEP := [][]byte{make([]byte, 64)}, make([]int, 1), make([]conn.Endpoint, 1)
	if n, err := serverFns[0](serverBuf, serverSizes, serverEP); err != nil || n != 1 || serverSizes[0] != 16 {
		t.Fatalf("server receive: n=%d err=%v size=%d", n, err, serverSizes[0])
	}
	if err = server.Send([][]byte{serverBuf[0][:serverSizes[0]]}, serverEP[0]); err != nil {
		t.Fatal(err)
	}
	clientBuf, clientSizes, clientEP := [][]byte{make([]byte, 64)}, make([]int, 1), make([]conn.Endpoint, 1)
	if n, err := clientFns[0](clientBuf, clientSizes, clientEP); err != nil || n != 1 || clientSizes[0] != 16 {
		t.Fatalf("client receive: n=%d err=%v size=%d", n, err, clientSizes[0])
	}
}
