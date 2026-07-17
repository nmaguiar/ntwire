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
	"time"
)

// TLSConfig loads the configured pair or creates an in-memory self-signed
// certificate. The latter is intentionally paired with client-side TOFU.
func TLSConfig(c Config) (*tls.Config, error) {
	if c.TLS.CertFile != "" || c.TLS.KeyFile != "" {
		pair, e := tls.LoadX509KeyPair(c.TLS.CertFile, c.TLS.KeyFile)
		if e != nil {
			return nil, e
		}
		return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}, nil
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return nil, e
	}
	t := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "nwire"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}}
	b, e := x509.CreateCertificate(rand.Reader, &t, &t, &key.PublicKey, key)
	if e != nil {
		return nil, e
	}
	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, e
	}
	pair, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if e != nil {
		return nil, e
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}, nil
}
