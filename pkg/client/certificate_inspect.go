package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// CertificateInspection reports a presentation, not a trust decision.
type CertificateInspection struct {
	Host             string                `json:"host"`
	Fingerprint      string                `json:"fingerprint"`
	Previous         string                `json:"previous,omitempty"`
	PreviouslyPinned bool                  `json:"previously_pinned"`
	FingerprintMatch bool                  `json:"fingerprint_match"`
	Certificate      *CertificateDetails   `json:"certificate"`
	Assessment       CertificateAssessment `json:"assessment"`
}

// InspectCertificate reuses the connect TOFU client, including its proxy and IP
// selection. It always aborts TLS verification, even for a matching pin: no
// application request, credentials, or trust-store writes can follow. CA and
// insecure modes are deliberately unsupported because this command compares pins.
func InspectCertificate(ctx context.Context, server string, o Options) (*CertificateInspection, error) {
	target, err := url.Parse(server)
	if err != nil || target.Scheme != "https" || target.Hostname() == "" || target.User != nil {
		return nil, fmt.Errorf("certificate inspection requires an HTTPS URL without credentials")
	}
	if o.CAFile != "" || o.Insecure {
		return nil, fmt.Errorf("certificate inspection compares TOFU pins; CA and insecure modes are not supported")
	}
	hc, err := httpClient(server, o)
	if err != nil {
		return nil, err
	}
	transport := hc.Transport.(*http.Transport)
	defer transport.CloseIdleConnections()
	verifier := transport.TLSClientConfig.VerifyConnection
	// HTTPS proxies have their own TLS handshake before CONNECT. Do not
	// report that certificate as the destination's, including IP-only proxies
	// whose handshake has no SNI. Preserve the existing verifier for that hop.
	var awaitingProxyTLS atomic.Bool
	proxyFunc := transport.Proxy
	if proxyFunc != nil {
		transport.Proxy = func(req *http.Request) (*url.URL, error) {
			p, err := proxyFunc(req)
			awaitingProxyTLS.Store(p != nil && p.Scheme == "https")
			return p, err
		}
	}
	transport.OnProxyConnectResponse = func(context.Context, *url.URL, *http.Request, *http.Response) error {
		awaitingProxyTLS.Store(false)
		return nil
	}
	stopped := errors.New("certificate inspection complete; TLS connection deliberately rejected")
	var result *CertificateInspection
	var resultMu sync.Mutex
	transport.TLSClientConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		// An HTTPS proxy can have its own TLS handshake. Only inspect the
		// destination; the existing verifier still governs a proxy handshake.
		if awaitingProxyTLS.Load() {
			return verifier(cs)
		}
		d := DescribeCertificate(cs, target.Hostname())
		if d == nil {
			return fmt.Errorf("server supplied no certificate")
		}
		verificationErr := verifier(cs)
		var unknown *UnknownCertificateError
		previous := d.SHA256Fingerprint
		if errors.As(verificationErr, &unknown) {
			previous = unknown.Previous
		} else if verificationErr != nil {
			return verificationErr
		}
		resultMu.Lock()
		result = &CertificateInspection{Host: target.Host, Fingerprint: d.SHA256Fingerprint, Previous: previous, PreviouslyPinned: previous != "", FingerprintMatch: previous == d.SHA256Fingerprint, Certificate: d, Assessment: AssessCertificateAt(*d, previous, time.Now())}
		resultMu.Unlock()
		return stopped
	}
	// The root path is never sent: the verifier above unconditionally rejects
	// the TLS connection. Disallow redirects as a second boundary.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	target.Path = "/"
	target.RawPath = ""
	target.RawQuery = ""
	target.Fragment = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, target.String(), nil)
	if err != nil {
		return nil, err
	}
	response, err := hc.Do(req)
	if response != nil {
		response.Body.Close()
	}
	resultMu.Lock()
	defer resultMu.Unlock()
	if result != nil && errors.Is(err, stopped) {
		return result, nil
	}
	if err == nil {
		err = fmt.Errorf("inspection ended without observing a TLS certificate")
	}
	return nil, err
}
