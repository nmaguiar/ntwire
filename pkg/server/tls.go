package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sync/atomic"
	"time"
)

// TLSManager serves the configured certificate pair or an in-memory
// self-signed certificate (the latter intentionally paired with client-side
// TOFU) through tls.Config.GetCertificate, so a certificate reload can swap
// it without restarting the listener.
type TLSManager struct {
	certFile, keyFile string
	selfSigned        bool // true when there is no cert_file/key_file to reload from
	cert              atomic.Pointer[tls.Certificate]
}

// NewTLSManager loads the initial certificate.
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
	pair, err := generateSelfSigned()
	if err != nil {
		return nil, err
	}
	m.cert.Store(&pair)
	return m, nil
}

// Config returns a *tls.Config that always serves the current certificate,
// reflecting any later call to Reload.
func (m *TLSManager) Config() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: m.getCertificate}
}
func (m *TLSManager) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.cert.Load(), nil
}

// Reload re-reads the configured cert_file/key_file pair and swaps the
// served certificate. It is a deliberate no-op for a self-signed
// certificate: regenerating it would invalidate every client's TOFU pin.
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

func generateSelfSigned() (tls.Certificate, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return tls.Certificate{}, e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return tls.Certificate{}, e
	}
	t := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "ntwire"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}}
	b, e := x509.CreateCertificate(rand.Reader, &t, &t, &key.PublicKey, key)
	if e != nil {
		return tls.Certificate{}, e
	}
	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return tls.Certificate{}, e
	}
	return tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}
