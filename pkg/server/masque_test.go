package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

func TestIssueMASQUECertificate_ClampsToSessionAndSignsCSR(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeMASQUECA(t, dir)
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	certPEM, issuerPEM, expires, err := issueMASQUECertificate(MASQUEConfig{IssuerCertFile: certFile, IssuerKeyFile: keyFile, CertificateTTL: time.Hour}, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})), "opaque-session-id", now.Add(10*time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	if !expires.Equal(now.Add(10 * time.Minute)) {
		t.Fatalf("expires = %v, want session expiry %v", expires, now.Add(10*time.Minute))
	}
	block, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "ntwire relay client" || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("unexpected certificate template: %+v", cert)
	}
	if string(cert.SubjectKeyId) != "opaque-session-id" {
		t.Fatalf("subject key ID = %q", cert.SubjectKeyId)
	}
	if block, _ := pem.Decode([]byte(issuerPEM)); block == nil {
		t.Fatal("missing issuer PEM")
	}
}

func TestIssueMASQUECertificate_RejectsUnsignedOrExtraCSRData(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeMASQUECA(t, dir)
	_, _, _, err := issueMASQUECertificate(MASQUEConfig{IssuerCertFile: certFile, IssuerKeyFile: keyFile, CertificateTTL: time.Hour}, "not a csr", "s", time.Now().Add(time.Hour), time.Now())
	if err == nil {
		t.Fatal("expected invalid CSR rejection")
	}
}

func TestMASQUECertificateHandler_RequiresLiveSession(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeMASQUECA(t, dir)
	s := New(Config{MASQUE: MASQUEConfig{Enabled: true, HTTP2URL: "https://relay.example.test", MatchDomains: []string{"private.example.test"}, ClientCAFile: certFile, IssuerCertFile: certFile, IssuerKeyFile: keyFile, CertificateTTL: time.Minute}}, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/masque/certificate", bytes.NewBufferString(`{"csr_pem":"invalid"}`))
	w := httptest.NewRecorder()
	s.masqueCertificate(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	var result protocol.Error
	if err := json.NewDecoder(w.Result().Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Code != protocol.ErrorInvalidRequest {
		t.Fatalf("error code = %q", result.Code)
	}
}

func writeMASQUECA(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "ntwire MASQUE test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
