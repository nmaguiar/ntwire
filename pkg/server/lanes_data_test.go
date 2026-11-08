package server

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/client"
	"github.com/nmaguiar/ntwire/pkg/protocol"
)

// TestWSSLanes_TunnelDataIntegrity pushes a bulk TCP stream through a real
// tunnel over the WSS carrier, with and without lanes, and checks every byte
// arrives intact and in order (spilling across lanes may reorder WireGuard
// packets; the inner TCP must still deliver a correct stream).
func TestWSSLanes_TunnelDataIntegrity(t *testing.T) {
	for _, tc := range []struct {
		lanes     int
		multipath bool
	}{{1, false}, {3, false}, {3, true}} {
		lanes := tc.lanes
		t.Run(fmt.Sprintf("lanes=%d,multipath=%v", lanes, tc.multipath), func(t *testing.T) {
			echo, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			go func() {
				for {
					c, err := echo.Accept()
					if err != nil {
						return
					}
					go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
				}
			}()
			s, keyPath, _ := newTestServer(t, []TunnelConfig{{Name: "echo", Target: echo.Addr().String(), VirtualPort: 18080, Allow: []string{"*"}}})
			s.Config.Network.TunnelCIDR = "100.66.0.0/16"
			s.Config.Listen.WireGuard = "127.0.0.1:0"
			if tc.multipath {
				port := freeUDPPort(t)
				s.Config.Listen.WireGuard = "127.0.0.1:" + fmt.Sprint(port)
				s.Config.Network.AdvertisedEndpoint = "127.0.0.1:" + fmt.Sprint(port)
			}
			s.Config.Transport.WSSLanes = lanes
			if err := s.StartDataPlane(); err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			httpSrv := httptest.NewTLSServer(s.Handler())
			defer httpSrv.Close()
			localLn, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			localPort := localLn.Addr().(*net.TCPAddr).Port
			_ = localLn.Close()
			conn, err := client.ConnectWithOptions(httpSrv.URL, keyPath, protocol.ClientInfo{OS: "darwin"}, client.Options{
				Insecure: true, NoWebUI: true, StatusFile: filepath.Join(t.TempDir(), "status.json"),
				UseWebSocket: !tc.multipath, WSSLanes: lanes, Ports: map[string]int{"echo": localPort},
			})
			if err != nil {
				t.Fatalf("ConnectWithOptions() = %v", err)
			}
			defer conn.Close()
			deadline := time.Now().Add(5 * time.Second)
			for lanes > 1 && time.Now().Before(deadline) && s.data.ws.WebSocket.LanesUp(conn.Stack.PublicKey()) != lanes {
				time.Sleep(20 * time.Millisecond)
			}
			c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", localPort), 5*time.Second)
			if err != nil {
				t.Fatalf("dial local tunnel: %v", err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(60 * time.Second))
			payload := make([]byte, 8<<20)
			if _, err := rand.Read(payload); err != nil {
				t.Fatal(err)
			}
			writeErr := make(chan error, 1)
			go func() {
				_, err := c.Write(payload)
				writeErr <- err
			}()
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(c, got); err != nil {
				t.Fatalf("read echo: %v", err)
			}
			if err := <-writeErr; err != nil {
				t.Fatalf("write: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("echoed stream differs from what was sent")
			}
			if tc.multipath {
				if !protocol.HasCapability(conn.Response.TransportCapabilities, protocol.CapabilityMultipathV3) {
					t.Fatal("multipath-v3 was not negotiated")
				}
				// The server's WireGuard peer must still use the stable
				// multipath endpoint (its id is the client's public key), not
				// a raw WSS lane address.
				ep, _, err := s.data.stack.PeerEndpoint(conn.Stack.PublicKey())
				if err != nil {
					t.Fatal(err)
				}
				if ep != conn.Stack.PublicKey() {
					t.Fatalf("server peer endpoint = %q, want the multipath logical endpoint", ep)
				}
			}
		})
	}
}
