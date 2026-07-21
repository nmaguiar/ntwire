package relay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// loadTLSCertificate returns the listen.agents certificate: an explicit
// cert_file/key_file pair, or a self-signed certificate persisted under
// tls.state_dir (or generated fresh in memory when tls.ephemeral is set).
// Unlike pkg/server's TLSManager, this has no hot-reload path: the agents
// listener's cert is loaded once at relay startup.
func loadTLSCertificate(c Config) (tls.Certificate, error) {
	if c.TLS.CertFile != "" || c.TLS.KeyFile != "" {
		return tls.LoadX509KeyPair(c.TLS.CertFile, c.TLS.KeyFile)
	}
	if c.TLS.Ephemeral || c.TLS.StateDir == "" {
		return generateSelfSigned()
	}
	pair, err := loadOrCreateSelfSigned(c.TLS.StateDir)
	if err != nil {
		slog.Warn("cannot persist self-signed TLS certificate; using ephemeral certificate", "dir", c.TLS.StateDir, "error", err)
		return generateSelfSigned()
	}
	return pair, nil
}

// fingerprint returns the same SHA256 pin representation used elsewhere in
// ntwire, purely for operator-facing logging: relay TLS is never pinned by
// an ntwire client (that pin is always the origin server's certificate).
func fingerprint(pair tls.Certificate) string {
	if len(pair.Certificate) == 0 {
		return ""
	}
	sum := sha256.Sum256(pair.Certificate[0])
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func loadOrCreateSelfSigned(dir string) (tls.Certificate, error) {
	certPath, keyPath := filepath.Join(dir, "relay-selfsigned-cert.pem"), filepath.Join(dir, "relay-selfsigned-key.pem")
	if pair, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil && len(pair.Certificate) > 0 {
		cert, parseErr := x509.ParseCertificate(pair.Certificate[0])
		if parseErr == nil && time.Until(cert.NotAfter) > 30*24*time.Hour {
			return pair, nil
		}
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return tls.Certificate{}, err
	}
	pair, err := generateSelfSigned()
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err = atomicWrite(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}), 0600); err != nil {
		return tls.Certificate{}, err
	}
	if err = atomicWrite(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		return tls.Certificate{}, err
	}
	return pair, nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".ntwire-relay-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}

func generateSelfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	host, _ := os.Hostname()
	dns := []string{"localhost"}
	if host != "" {
		dns = append(dns, host)
	}
	t := x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "ntwire-relay"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: dns, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &t, &t, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	der2, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der2}))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create self-signed TLS pair: %w", err)
	}
	return pair, nil
}
