package server

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

const maxMASQUECSRSize = 16 << 10

// masqueCertificate issues a certificate bound to a live ntwire session. The
// client key remains on the device: only its validated CSR is accepted here.
// This endpoint intentionally uses the existing authenticated control channel;
// the resulting certificate is for the separate mTLS relay listener only.
func (s *Server) masqueCertificate(w http.ResponseWriter, r *http.Request) {
	if !s.Config.MASQUE.Enabled {
		http.NotFound(w, r)
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		fail(w, http.StatusUnauthorized, protocol.ErrorInvalidRequest, "valid session required")
		return
	}
	session, ok := s.sessions.Get(token)
	if !ok {
		fail(w, http.StatusUnauthorized, protocol.ErrorInvalidRequest, "valid session required")
		return
	}
	var req protocol.MASQUECertificateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxMASQUECSRSize)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, protocol.ErrorInvalidRequest, "invalid certificate request")
		return
	}
	certificate, issuer, expires, err := issueMASQUECertificate(s.Config.MASQUE, req.CSRPEM, session.ID, session.Expires, time.Now())
	if err != nil {
		s.log.Warn("MASQUE certificate request rejected", "error", err)
		fail(w, http.StatusBadRequest, protocol.ErrorInvalidRequest, "certificate request rejected")
		return
	}
	s.audit("masque_certificate_issued", session, "issued", 0)
	write(w, http.StatusOK, protocol.MASQUECertificateResponse{CertificatePEM: certificate, IssuerPEM: issuer, ExpiresAt: expires})
}

func issueMASQUECertificate(c MASQUEConfig, csrPEM, sessionID string, sessionExpires, now time.Time) (certificatePEM, issuerPEM string, expires time.Time, err error) {
	block, rest := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(strings.TrimSpace(string(rest))) != 0 {
		return "", "", time.Time{}, fmt.Errorf("CSR must contain exactly one PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return "", "", time.Time{}, fmt.Errorf("invalid CSR")
	}
	signer, err := loadMASQUEIssuer(c.IssuerCertFile, c.IssuerKeyFile)
	if err != nil {
		return "", "", time.Time{}, err
	}
	issuerCert, err := x509.ParseCertificate(signer.Certificate[0])
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("parse issuer certificate: %w", err)
	}
	if issuerCert.KeyUsage&x509.KeyUsageCertSign == 0 || !issuerCert.IsCA {
		return "", "", time.Time{}, fmt.Errorf("MASQUE issuer certificate is not a CA")
	}
	expires = now.Add(c.CertificateTTL)
	if expires.After(sessionExpires) {
		expires = sessionExpires
	}
	if expires.After(issuerCert.NotAfter) {
		expires = issuerCert.NotAfter
	}
	if !expires.After(now.Add(30 * time.Second)) {
		return "", "", time.Time{}, fmt.Errorf("session or issuer expires too soon")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("certificate serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "ntwire relay client"},
		NotBefore:    now.Add(-time.Minute), NotAfter: expires,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		SubjectKeyId: []byte(sessionID),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuerCert, csr.PublicKey, signer.PrivateKey)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("sign client certificate: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signer.Certificate[0]})), expires, nil
}

func loadMASQUEIssuer(certFile, keyFile string) (*tls.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load MASQUE issuer: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("MASQUE issuer has no certificate")
	}
	return &pair, nil
}
