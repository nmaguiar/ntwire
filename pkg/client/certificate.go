package client

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
)

// CertificateDetails describes the certificates presented by the peer. Chain is
// presentation order, not a verified trust chain. No CA trust is implied.
type CertificateDetails struct {
	Subject            string                  `json:"subject"`
	CommonName         string                  `json:"common_name,omitempty"`
	Issuer             string                  `json:"issuer"`
	IssuerCommonName   string                  `json:"issuer_common_name,omitempty"`
	DNSNames           []string                `json:"dns_names,omitempty"`
	IPAddresses        []string                `json:"ip_addresses,omitempty"`
	SerialNumber       string                  `json:"serial_number,omitempty"`
	NotBefore          time.Time               `json:"not_before"`
	NotAfter           time.Time               `json:"not_after"`
	SHA256Fingerprint  string                  `json:"sha256_fingerprint"`
	PublicKeyAlgorithm string                  `json:"public_key_algorithm,omitempty"`
	SignatureAlgorithm string                  `json:"signature_algorithm,omitempty"`
	IsCA               bool                    `json:"is_ca"`
	IsSelfSigned       bool                    `json:"is_self_signed"`
	ExpectedIdentity   string                  `json:"expected_identity,omitempty"`
	IdentityMismatch   bool                    `json:"identity_mismatch"`
	Chain              []CertificateChainEntry `json:"chain,omitempty"`
}

type CertificateChainEntry struct {
	Subject           string `json:"subject"`
	Issuer            string `json:"issuer"`
	SHA256Fingerprint string `json:"sha256_fingerprint"`
	IsCA              bool   `json:"is_ca"`
}

func certificateFingerprint(c *x509.Certificate) string {
	s := sha256.Sum256(c.Raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(s[:])
}

// DescribeCertificate safely handles absent entries without treating them as
// valid certificates. Self-signature verification also works for non-CA leaves.
func DescribeCertificate(cs tls.ConnectionState, hostname string) *CertificateDetails {
	if len(cs.PeerCertificates) == 0 || cs.PeerCertificates[0] == nil || len(cs.PeerCertificates[0].Raw) == 0 {
		return nil
	}
	c := cs.PeerCertificates[0]
	d := &CertificateDetails{Subject: c.Subject.String(), CommonName: c.Subject.CommonName, Issuer: c.Issuer.String(), IssuerCommonName: c.Issuer.CommonName, DNSNames: append([]string(nil), c.DNSNames...), NotBefore: c.NotBefore, NotAfter: c.NotAfter, SHA256Fingerprint: certificateFingerprint(c), PublicKeyAlgorithm: c.PublicKeyAlgorithm.String(), SignatureAlgorithm: c.SignatureAlgorithm.String(), IsCA: c.IsCA, ExpectedIdentity: hostname}
	if c.SerialNumber != nil {
		d.SerialNumber = c.SerialNumber.String()
	}
	for _, ip := range c.IPAddresses {
		d.IPAddresses = append(d.IPAddresses, ip.String())
	}
	d.IsSelfSigned = bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
	d.IdentityMismatch = hostname != "" && c.VerifyHostname(hostname) != nil
	for _, entry := range cs.PeerCertificates {
		if entry == nil || len(entry.Raw) == 0 {
			continue
		}
		d.Chain = append(d.Chain, CertificateChainEntry{Subject: entry.Subject.String(), Issuer: entry.Issuer.String(), SHA256Fingerprint: certificateFingerprint(entry), IsCA: entry.IsCA})
	}
	return d
}

type CertificateAssessment struct {
	Status     string   `json:"status"`
	Indicators []string `json:"indicators,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
}

// Issuer names are untrusted hints, never evidence of cryptographic trust or
// proof of interception. Match only issuer names, with word boundaries.
var inspectionIssuers = []string{"netskope", "zscaler", "palo alto networks", "fortinet", "forcepoint", "symantec", "broadcom"}

func inspectionIssuer(issuer string) bool {
	normalized := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToLower(r)
		}
		return ' '
	}, issuer)
	normalized = " " + strings.Join(strings.Fields(normalized), " ") + " "
	for _, name := range inspectionIssuers {
		if strings.Contains(normalized, " "+name+" ") {
			return true
		}
	}
	return false
}

func AssessCertificate(details CertificateDetails, previousFingerprint string) CertificateAssessment {
	return AssessCertificateAt(details, previousFingerprint, time.Now())
}

// AssessCertificateAt is deterministic at the supplied observation time.
// Status summarizes the most actionable condition; indicators retain all facts.
func AssessCertificateAt(d CertificateDetails, previous string, now time.Time) CertificateAssessment {
	a := CertificateAssessment{Status: "not_previously_trusted"}
	add := func(indicator, warning string) {
		a.Indicators = append(a.Indicators, indicator)
		a.Warnings = append(a.Warnings, warning)
	}
	if previous != "" && d.SHA256Fingerprint != "" {
		if previous == d.SHA256Fingerprint {
			a.Status = "previously_trusted"
		} else {
			a.Status = "certificate_changed"
			add("certificate_changed", "Server certificate changed. This may reflect legitimate renewal or rotation, or interception. Verify the new fingerprint with the server administrator.")
		}
	}
	if d.IsSelfSigned {
		add("self_signed", "Certificate is self-signed; this alone does not indicate interception or CA trust.")
	}
	if inspectionIssuer(d.Issuer) {
		a.Status = "possible_interception"
		add("enterprise_inspection_issuer", "The certificate issuer resembles an enterprise TLS-inspection authority. This connection may be intercepted by a network security product. An issuer name alone is not proof of interception.")
	}
	if d.IdentityMismatch {
		a.Status = "identity_mismatch"
		add("identity_mismatch", "Certificate cannot be validated against the expected server hostname or IP address.")
	}
	if !d.NotAfter.IsZero() && now.After(d.NotAfter) {
		add("expired", "Certificate has expired.")
	}
	if !d.NotBefore.IsZero() && now.Before(d.NotBefore) {
		add("not_yet_valid", "Certificate is not yet valid.")
	}
	if d.Subject == "" || d.Issuer == "" || d.SHA256Fingerprint == "" || d.NotBefore.IsZero() || d.NotAfter.IsZero() {
		add("incomplete_metadata", "Certificate metadata is incomplete.")
	}
	return a
}

// CertificateDisplayText removes terminal controls from peer-controlled text.
func CertificateDisplayText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return '�'
		}
		return r
	}, s)
}

// WriteCertificateSummary is shared by interactive prompts and read-only inspect.
func WriteCertificateSummary(w io.Writer, host, fingerprint, previous string, d *CertificateDetails, a *CertificateAssessment) {
	fmt.Fprintf(w, "Server: %s\n", CertificateDisplayText(host))
	if d != nil {
		fmt.Fprintf(w, "Subject: %s\nIssuer: %s\nValid from: %s\nValid until: %s\n", CertificateDisplayText(d.Subject), CertificateDisplayText(d.Issuer), d.NotBefore.UTC().Format(time.RFC3339), d.NotAfter.UTC().Format(time.RFC3339))
	}
	if previous != "" {
		fmt.Fprintf(w, "Previously trusted:\n  %s\n", CertificateDisplayText(previous))
	}
	fmt.Fprintf(w, "Current fingerprint:\n  %s\n", CertificateDisplayText(fingerprint))
	if a != nil {
		fmt.Fprintf(w, "Certificate status: %s\n", a.Status)
		for _, warning := range a.Warnings {
			fmt.Fprintf(w, "WARNING: %s\n", CertificateDisplayText(warning))
		}
	}
}
