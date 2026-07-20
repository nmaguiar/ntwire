package server

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
	"sync/atomic"
	"time"
)

type TLSManager struct {
	certFile, keyFile string
	selfSigned        bool
	cert              atomic.Pointer[tls.Certificate]
}

func NewTLSManager(c Config) (*TLSManager, error) {
	m := &TLSManager{certFile: c.TLS.CertFile, keyFile: c.TLS.KeyFile}
	if c.TLS.CertFile != "" || c.TLS.KeyFile != "" {
		pair, err := tls.LoadX509KeyPair(c.TLS.CertFile, c.TLS.KeyFile)
		if err != nil {
			return nil, err
		}
		m.cert.Store(&pair)
		return m, nil
	}
	m.selfSigned = true
	var pair tls.Certificate
	var err error
	if c.TLS.Ephemeral || c.TLS.StateDir == "" {
		pair, err = generateSelfSigned()
	} else {
		pair, err = loadOrCreateSelfSigned(c.TLS.StateDir)
		if err != nil {
			slog.Warn("cannot persist self-signed TLS certificate; using ephemeral certificate", "dir", c.TLS.StateDir, "error", err)
			pair, err = generateSelfSigned()
		}
	}
	if err != nil {
		return nil, err
	}
	m.cert.Store(&pair)
	return m, nil
}

func (m *TLSManager) Config() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: m.getCertificate}
}
func (m *TLSManager) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.cert.Load(), nil
}
func (m *TLSManager) Reload() error {
	if m.selfSigned {
		return nil
	}
	pair, err := tls.LoadX509KeyPair(m.certFile, m.keyFile)
	if err != nil {
		return err
	}
	m.cert.Store(&pair)
	return nil
}

// Fingerprint returns the same pin representation displayed by the client.
func (m *TLSManager) Fingerprint() string {
	pair := m.cert.Load()
	if pair == nil || len(pair.Certificate) == 0 {
		return ""
	}
	sum := sha256.Sum256(pair.Certificate[0])
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func loadOrCreateSelfSigned(dir string) (tls.Certificate, error) {
	certPath, keyPath := filepath.Join(dir, "selfsigned-cert.pem"), filepath.Join(dir, "selfsigned-key.pem")
	if pair, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil && len(pair.Certificate) > 0 {
		cert, parseErr := x509.ParseCertificate(pair.Certificate[0])
		if parseErr == nil && time.Until(cert.NotAfter) > 30*24*time.Hour {
			return pair, nil
		}
		slog.Warn("stored self-signed TLS certificate is expiring or invalid; regenerating", "dir", dir)
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
	f, err := os.CreateTemp(filepath.Dir(path), ".ntwire-*")
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
	t := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "ntwire"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: dns, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}
	b, err := x509.CreateCertificate(rand.Reader, &t, &t, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create self-signed TLS pair: %w", err)
	}
	return pair, nil
}
