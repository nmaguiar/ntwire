// Package client implements the HTTPS authentication side of nwire.
package client

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/nmaguiar/nwire/pkg/protocol"
	"github.com/nmaguiar/nwire/pkg/sshkey"
	"net/http"
	"os"
	"runtime"
	"time"
)

type Collector interface {
	Collect() (map[string]string, error)
}
type ExecCollector struct{ Command string }

func BuiltinInfo() protocol.ClientInfo {
	h, _ := os.Hostname()
	return protocol.ClientInfo{OS: runtime.GOOS, Arch: runtime.GOARCH, Hostname: h, ClientVersion: "dev", Extra: map[string]string{}}
}
func Authenticate(url, keyPath string, info protocol.ClientInfo) (protocol.AuthResponse, error) {
	pub, err := sshkey.PublicFromPrivate(keyPath)
	if err != nil {
		return protocol.AuthResponse{}, err
	}
	n := make([]byte, 32)
	if _, err = rand.Read(n); err != nil {
		return protocol.AuthResponse{}, err
	}
	r := protocol.AuthRequest{Version: protocol.Version, PublicKey: pub, Timestamp: time.Now().UTC().Format(time.RFC3339), Nonce: base64.RawURLEncoding.EncodeToString(n), Info: info}
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
