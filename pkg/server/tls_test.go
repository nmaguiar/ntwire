package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// genCertFiles writes a freshly generated self-signed cert/key PEM pair to
// dir and returns their paths. Each call produces distinct DER bytes (the
// certificate's random serial number differs), which lets tests tell two
// generated certificates apart.
func genCertFiles(t *testing.T, dir, name string) (certPath, keyPath string) {
	t.Helper()
	pair, err := generateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, name+"-cert.pem")
	keyPath = filepath.Join(dir, name+"-key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestTLSManagerReloadsFileBackedCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := genCertFiles(t, dir, "first")

	cfg := Config{}
	cfg.TLS.CertFile = certPath
	cfg.TLS.KeyFile = keyPath
	m, err := NewTLSManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	before, err := m.getCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a certificate renewal: write a new pair over the same paths.
	newCertPath, newKeyPath := genCertFiles(t, dir, "second")
	if err := os.Rename(newCertPath, certPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(newKeyPath, keyPath); err != nil {
		t.Fatal(err)
	}

	if err := m.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	after, err := m.getCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before.Certificate[0], after.Certificate[0]) {
		t.Fatal("expected Reload to swap in the renewed certificate")
	}
}

func TestTLSManagerReloadKeepsServingOldCertOnError(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := genCertFiles(t, dir, "only")

	cfg := Config{}
	cfg.TLS.CertFile = certPath
	cfg.TLS.KeyFile = keyPath
	m, err := NewTLSManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := m.getCertificate(nil)

	// Corrupt the key file so the next Reload fails to parse it.
	if err := os.WriteFile(keyPath, []byte("not a key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Reload(); err == nil {
		t.Fatal("expected Reload to fail on a corrupted key file")
	}

	after, _ := m.getCertificate(nil)
	if !bytes.Equal(before.Certificate[0], after.Certificate[0]) {
		t.Fatal("a failed Reload should keep serving the previously loaded certificate")
	}
}

func TestTLSManagerSelfSignedNeverReloads(t *testing.T) {
	m, err := NewTLSManager(Config{})
	if err != nil {
		t.Fatal(err)
	}
	before, err := m.getCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Reload(); err != nil {
		t.Fatalf("Reload on a self-signed manager should be a no-op, got error: %v", err)
	}
	after, err := m.getCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("self-signed certificate must never be swapped by Reload (it would break TOFU-pinned clients)")
	}
}

// Confirm the manager actually plugs into tls.Config the way main.go uses it.
func TestTLSManagerConfigUsesGetCertificate(t *testing.T) {
	m, err := NewTLSManager(Config{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := m.Config()
	if cfg.GetCertificate == nil {
		t.Fatal("expected Config() to set GetCertificate")
	}
	if len(cfg.Certificates) != 0 {
		t.Fatal("expected Config() not to set a static Certificates list")
	}
	if _, err := cfg.GetCertificate(&tls.ClientHelloInfo{}); err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
}
