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

// TestWSS_TunnelDataIntegrity pushes a bulk TCP stream through a real tunnel
// over the WSS carrier, both WSS-only and as a multipath session's
// bootstrap, and checks every byte arrives intact and in order.
func TestWSS_TunnelDataIntegrity(t *testing.T) {
	for _, multipath := range []bool{false, true} {
		t.Run(fmt.Sprintf("multipath=%v", multipath), func(t *testing.T) {
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
			if multipath {
				port := freeUDPPort(t)
				s.Config.Listen.WireGuard = "127.0.0.1:" + fmt.Sprint(port)
				s.Config.Network.AdvertisedEndpoint = "127.0.0.1:" + fmt.Sprint(port)
			}
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
				UseWebSocket: !multipath, Ports: map[string]int{"echo": localPort},
			})
			if err != nil {
				t.Fatalf("ConnectWithOptions() = %v", err)
			}
			defer conn.Close()
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
			if multipath && !protocol.HasCapability(conn.Response.TransportCapabilities, protocol.CapabilityMultipathV3) {
				t.Fatal("multipath-v3 was not negotiated")
			}
		})
	}
}
