// Command fixtures creates the short-lived identities, TLS material, and
// configuration files consumed by the Docker Compose end-to-end test.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/nmaguiar/ntwire/pkg/sshkey"
)

func main() {
	out := flag.String("out", "", "directory for generated E2E fixtures")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "usage: fixtures -out directory")
		os.Exit(2)
	}
	if err := generate(*out); err != nil {
		fmt.Fprintln(os.Stderr, "generate E2E fixtures:", err)
		os.Exit(1)
	}
}

func generate(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0755); err != nil {
		return err
	}
	for _, name := range []string{"direct-client", "relay-client", "keys"} {
		mode := os.FileMode(0755)
		if name == "direct-client" || name == "relay-client" {
			mode = 0777 // mounted as the client image's non-root HOME
		}
		if err := os.MkdirAll(filepath.Join(dir, name), mode); err != nil {
			return err
		}
		if err := os.Chmod(filepath.Join(dir, name), mode); err != nil {
			return err
		}
	}

	clientKey := filepath.Join(dir, "client-id")
	if _, err := sshkey.GenerateIdentityFile(clientKey); err != nil {
		return err
	}
	if err := os.Chmod(clientKey, 0644); err != nil {
		return err
	}
	clientPublic, err := os.ReadFile(clientKey + ".pub")
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(dir, "keys", "e2e.pub"), clientPublic, 0644); err != nil {
		return err
	}

	relayIdentity := filepath.Join(dir, "relay-id")
	if _, err := sshkey.GenerateIdentityFile(relayIdentity); err != nil {
		return err
	}
	if err := os.Chmod(relayIdentity, 0644); err != nil {
		return err
	}
	relayPublic, err := os.ReadFile(relayIdentity + ".pub")
	if err != nil {
		return err
	}

	directFP, err := writeCertificate(dir, "direct-server", "direct-server")
	if err != nil {
		return err
	}
	relayedFP, err := writeCertificate(dir, "relayed-server", "home.relay.test")
	if err != nil {
		return err
	}
	relayFP, err := writeCertificate(dir, "relay", "relay")
	if err != nil {
		return err
	}

	if err := writeFile(filepath.Join(dir, "direct-known-servers.yaml"), []byte(fmt.Sprintf("servers:\n  \"direct-server:8443\": %q\n", directFP)), 0644); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(dir, "relay-known-servers.yaml"), []byte(fmt.Sprintf("servers:\n  \"home.relay.test:9443\": %q\n", relayedFP)), 0644); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(dir, "direct-server.yaml"), []byte(directServerConfig()), 0644); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(dir, "relayed-server.yaml"), []byte(relayedServerConfig(relayFP)), 0644); err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, "relay.yaml"), []byte(relayConfig(string(relayPublic))), 0644)
}

func directServerConfig() string {
	return `tls:
  cert_file: /e2e/direct-server-cert.pem
  key_file: /e2e/direct-server-key.pem
listen:
  https: ":8443"
  wireguard: ":51820"
auth:
  authorized_keys_dir: /e2e/keys
network:
  tunnel_cidr: 100.64.0.0/16
  advertised_endpoint: 172.31.240.2:51820
tunnels:
  - name: fixed-http
    target: dummy:8080
    virtual_port: 18080
    local_port: 18080
    allow: ["*"]
  - name: socks-http
    target: socks
    virtual_port: 11080
    local_port: 11080
    allow: ["*"]
    socks:
      domain_filters: ["dummy"]
`
}

func relayedServerConfig(relayFingerprint string) string {
	return fmt.Sprintf(`tls:
  cert_file: /e2e/relayed-server-cert.pem
  key_file: /e2e/relayed-server-key.pem
listen:
  https: ":8443"
  wireguard: "127.0.0.1:0"
auth:
  authorized_keys_dir: /e2e/keys
network:
  tunnel_cidr: 100.65.0.0/16
relay:
  enabled: true
  url: wss://relay:9444
  name: home
  identity_file: /e2e/relay-id
  fingerprint: %q
  reconnect_min: 100ms
  reconnect_max: 1s
tunnels:
  - name: fixed-http
    target: dummy:8080
    virtual_port: 18080
    local_port: 18080
    allow: ["*"]
  - name: socks-http
    target: socks
    virtual_port: 11080
    local_port: 11080
    allow: ["*"]
    socks:
      domain_filters: ["dummy"]
`, relayFingerprint)
}

func relayConfig(publicKey string) string {
	return fmt.Sprintf(`tls:
  cert_file: /e2e/relay-cert.pem
  key_file: /e2e/relay-key.pem
listen:
  public: ":9443"
  agents: ":9444"
domain: relay.test
registrations:
  - name: home
    public_key: %q
`, publicKey)
}

func writeCertificate(dir, name, dnsName string) (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", err
	}
	cert := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, &cert, &cert, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	if err := writeFile(filepath.Join(dir, name+"-cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		return "", err
	}
	if err := writeFile(filepath.Join(dir, name+"-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0644); err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	return os.WriteFile(path, data, mode)
}
