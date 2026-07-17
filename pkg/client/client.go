// Package client implements the HTTPS authentication side of nwire.
package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/nmaguiar/nwire/pkg/protocol"
	"github.com/nmaguiar/nwire/pkg/sshkey"
	"github.com/nmaguiar/nwire/pkg/wgnet"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

type Collector interface {
	Collect() (map[string]string, error)
}
type ExecCollector struct{ Command string }

func BuiltinInfo() protocol.ClientInfo {
	h, _ := os.Hostname()
	u := os.Getenv("USER")
	return protocol.ClientInfo{OS: runtime.GOOS, Arch: runtime.GOARCH, Hostname: h, Username: u, ClientVersion: "dev", Extra: map[string]string{}}
}
func (c ExecCollector) Collect() (map[string]string, error) {
	out, err := exec.Command("sh", "-c", c.Command).Output()
	if err != nil {
		return nil, err
	}
	if len(out) > 64<<10 {
		return nil, fmt.Errorf("collector output exceeds 64KiB")
	}
	var v map[string]string
	if err = json.Unmarshal(out, &v); err != nil {
		return nil, fmt.Errorf("collector must emit a JSON object: %w", err)
	}
	for k, x := range v {
		if len(k) > 256 || len(x) > 4096 {
			return nil, fmt.Errorf("collector value too large")
		}
	}
	return v, nil
}
func Authenticate(url, keyPath string, info protocol.ClientInfo) (protocol.AuthResponse, error) {
	k, err := wgnet.GenerateKey()
	if err != nil {
		return protocol.AuthResponse{}, err
	}
	return authenticate(url, keyPath, info, k.Public)
}
func authenticate(url, keyPath string, info protocol.ClientInfo, wgPublic string) (protocol.AuthResponse, error) {
	pub, err := sshkey.PublicFromPrivate(keyPath)
	if err != nil {
		return protocol.AuthResponse{}, err
	}
	n := make([]byte, 32)
	if _, err = rand.Read(n); err != nil {
		return protocol.AuthResponse{}, err
	}
	r := protocol.AuthRequest{Version: protocol.Version, PublicKey: pub, WireGuardPublicKey: wgPublic, Timestamp: time.Now().UTC().Format(time.RFC3339), Nonce: base64.RawURLEncoding.EncodeToString(n), Info: info}
	p, err := protocol.SigningPayload(r)
	if err != nil {
		return protocol.AuthResponse{}, err
	}
	r.Signature, err = sshkey.SignFile(keyPath, p)
	if err != nil {
		return protocol.AuthResponse{}, err
	}
	b, _ := json.Marshal(r)
	resp, err := http.Post(url+"/v1/auth", "application/json", bytes.NewReader(b))
	if err != nil {
		return protocol.AuthResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return protocol.AuthResponse{}, fmt.Errorf("authentication failed: %s", resp.Status)
	}
	var out protocol.AuthResponse
	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}

// Connection is a persistent, local-listener view of one WireGuard session.
type Connection struct {
	Response       protocol.AuthResponse
	Stack          *wgnet.Stack
	listeners      []net.Listener
	LocalAddresses []string
	token, base    string
	mu             sync.Mutex
}

func Connect(url, keyPath string, info protocol.ClientInfo, ports map[string]int) (*Connection, error) {
	key, err := wgnet.GenerateKey()
	if err != nil {
		return nil, err
	}
	r, err := authenticate(url, keyPath, info, key.Public)
	if err != nil {
		return nil, err
	}
	clientIP, err := netip.ParseAddr(r.TunnelIP)
	if err != nil {
		return nil, fmt.Errorf("server did not return a tunnel IP: %w", err)
	}
	st, err := wgnet.New(wgnet.Config{PrivateKey: key.Private, Addresses: []netip.Addr{clientIP}})
	if err != nil {
		return nil, err
	}
	endpoint := r.UDP
	if endpoint == "" {
		st.Close()
		return nil, fmt.Errorf("server did not advertise a WireGuard endpoint")
	}
	serverIP := clientIP
	a := serverIP.As4()
	a[3] = 1
	serverIP = netip.AddrFrom4(a)
	if err = st.AddPeer(wgnet.Endpoint{PublicKey: r.ServerPublicKey, Address: "0.0.0.0/0@" + endpoint}); err != nil {
		st.Close()
		return nil, err
	}
	c := &Connection{Response: r, Stack: st, token: r.Token, base: strings.TrimRight(url, "/")}
	for _, t := range r.Tunnels {
		p := ports[t.Name]
		addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(p))
		l, e := net.Listen("tcp", addr)
		if e != nil {
			c.Close()
			return nil, e
		}
		c.listeners = append(c.listeners, l)
		c.LocalAddresses = append(c.LocalAddresses, l.Addr().String())
		go c.forward(l, net.JoinHostPort(serverIP.String(), fmt.Sprint(t.VirtualPort)))
	}
	return c, nil
}
func (c *Connection) forward(l net.Listener, target string) {
	for {
		in, e := l.Accept()
		if e != nil {
			return
		}
		go func() {
			defer in.Close()
			out, e := c.Stack.DialContext(context.Background(), "tcp", target)
			if e != nil {
				return
			}
			defer out.Close()
			go io.Copy(out, in)
			io.Copy(in, out)
		}()
	}
}
func (c *Connection) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, l := range c.listeners {
		_ = l.Close()
	}
	c.listeners = nil
	if c.Stack != nil {
		_ = c.Stack.Close()
		c.Stack = nil
	}
}
