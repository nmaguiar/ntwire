package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"golang.zx2c4.com/wireguard/conn"
)

func testCertificate(t *testing.T, name string, ca bool, parent *tls.Certificate) tls.Certificate {
	t.Helper()
	now := time.Now()
	return testCertificateValidity(t, name, ca, parent, now.Add(-time.Hour), now.Add(time.Hour))
}

func testCertificateValidity(t *testing.T, name string, ca bool, parent *tls.Certificate, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: name}, DNSNames: []string{"localhost", "example.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, NotBefore: notBefore, NotAfter: notAfter, BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ca {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	issuer, signer := template, key
	if parent != nil {
		issuer = parent.Leaf
		signer = parent.PrivateKey.(*ecdsa.PrivateKey)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	if parent != nil {
		cert.Certificate = append(cert.Certificate, parent.Certificate...)
	}
	return cert
}

func TestDescribeCertificate(t *testing.T) {
	root := testCertificate(t, "Root CA", true, nil)
	intermediate := testCertificate(t, "Intermediate CA", true, &root)
	leaf := testCertificate(t, "example.test", false, &intermediate)
	for _, tc := range []struct {
		name  string
		cert  tls.Certificate
		self  bool
		chain int
	}{
		{"CA-issued", leaf, false, 3}, {"self-signed", testCertificate(t, "ntwire", false, nil), true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := tls.ConnectionState{}
			for _, raw := range tc.cert.Certificate {
				c, err := x509.ParseCertificate(raw)
				if err != nil {
					t.Fatal(err)
				}
				cs.PeerCertificates = append(cs.PeerCertificates, c)
			}
			cs.PeerCertificates = append(cs.PeerCertificates, nil)
			d := DescribeCertificate(cs, "localhost")
			if d == nil || d.IsSelfSigned != tc.self || len(d.Chain) != tc.chain || d.IdentityMismatch || len(d.DNSNames) != 2 || len(d.IPAddresses) != 2 {
				t.Fatalf("details: %+v", d)
			}
			if d.SHA256Fingerprint != certificateFingerprint(tc.cert.Leaf) || d.SerialNumber == "" || d.PublicKeyAlgorithm != "ECDSA" {
				t.Fatalf("missing fields: %+v", d)
			}
			if DescribeCertificate(cs, "wrong.example").IdentityMismatch != true {
				t.Fatal("hostname mismatch not reported")
			}
		})
	}
	if DescribeCertificate(tls.ConnectionState{}, "") != nil || DescribeCertificate(tls.ConnectionState{PeerCertificates: []*x509.Certificate{nil}}, "") != nil {
		t.Fatal("missing leaf accepted")
	}
	minimal := *leaf.Leaf
	minimal.Subject = pkix.Name{}
	minimal.DNSNames = nil
	minimal.IPAddresses = nil
	minimal.SerialNumber = nil
	if d := DescribeCertificate(tls.ConnectionState{PeerCertificates: []*x509.Certificate{&minimal}}, ""); d == nil || d.SerialNumber != "" {
		t.Fatal("missing optional fields")
	}
	forged := *root.Leaf
	forged.Signature = []byte("invalid")
	if DescribeCertificate(tls.ConnectionState{PeerCertificates: []*x509.Certificate{&forged}}, "").IsSelfSigned {
		t.Fatal("names alone imply self-signed")
	}
}

func TestAssessCertificate(t *testing.T) {
	now := time.Now()
	base := CertificateDetails{Subject: "CN=ntwire", Issuer: "CN=Ordinary Public CA", SHA256Fingerprint: "SHA256:new", NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	for _, tc := range []struct{ name, issuer, previous, status, indicator string }{
		{"first", "Ordinary Public CA", "", "not_previously_trusted", ""},
		{"private", "Acme Enterprise Root CA", "", "not_previously_trusted", ""},
		{"matching", "Ordinary Public CA", "SHA256:new", "previously_trusted", ""},
		{"changed", "Ordinary Public CA", "SHA256:old", "certificate_changed", "certificate_changed"},
		{"netskope", "CN=NeTsKoPe Enterprise CA", "", "possible_interception", "enterprise_inspection_issuer"},
		{"zscaler", "CN=ZSCALER Root", "", "possible_interception", "enterprise_inspection_issuer"},
		{"fortinet changed", "Fortinet CA", "SHA256:old", "possible_interception", "certificate_changed"},
		{"palo alto", "Palo Alto Networks Enterprise CA", "", "possible_interception", "enterprise_inspection_issuer"},
		{"forcepoint", "Forcepoint Root", "", "possible_interception", "enterprise_inspection_issuer"},
		{"symantec", "Symantec CA", "", "possible_interception", "enterprise_inspection_issuer"},
		{"broadcom", "Broadcom CA", "", "possible_interception", "enterprise_inspection_issuer"},
		{"substring", "NotNetskope CA", "", "not_previously_trusted", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := base
			d.Issuer = tc.issuer
			a := AssessCertificateAt(d, tc.previous, now)
			if a.Status != tc.status {
				t.Fatalf("%+v", a)
			}
			if tc.indicator != "" && !strings.Contains(strings.Join(a.Indicators, ","), tc.indicator) {
				t.Fatalf("missing %s: %+v", tc.indicator, a)
			}
			if tc.indicator == "" && len(a.Indicators) != 0 {
				t.Fatalf("false positive: %+v", a)
			}
		})
	}
	for _, tc := range []struct {
		name      string
		change    func(*CertificateDetails)
		indicator string
	}{
		{"self signed", func(d *CertificateDetails) { d.IsSelfSigned = true }, "self_signed"},
		{"expired", func(d *CertificateDetails) { d.NotAfter = now.Add(-time.Second) }, "expired"},
		{"future", func(d *CertificateDetails) { d.NotBefore = now.Add(time.Second) }, "not_yet_valid"},
		{"identity", func(d *CertificateDetails) { d.IdentityMismatch = true }, "identity_mismatch"},
		{"missing", func(d *CertificateDetails) { d.Issuer = "" }, "incomplete_metadata"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := base
			tc.change(&d)
			a := AssessCertificateAt(d, "", now)
			if !strings.Contains(strings.Join(a.Indicators, ","), tc.indicator) {
				t.Fatalf("%+v", a)
			}
		})
	}
	d := base
	d.Subject = "CN=Netskope"
	d.CommonName = "Zscaler"
	if a := AssessCertificateAt(d, "", now); len(a.Indicators) != 0 {
		t.Fatal("matched arbitrary fields")
	}
}

func certificateServer(t *testing.T, cert *atomic.Pointer[tls.Certificate], handler http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{*cert.Load()}}, nil
	}}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func TestCertificateInspectionAndSharedPinning(t *testing.T) {
	original := testCertificate(t, "origin", false, nil)
	proxyCA := testCertificate(t, "Netskope Enterprise CA", true, nil)
	intercepted := testCertificate(t, "origin", false, &proxyCA)
	var active atomic.Pointer[tls.Certificate]
	active.Store(&original)
	var requests atomic.Int32
	s := certificateServer(t, &active, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(http.StatusOK) }))
	known := filepath.Join(t.TempDir(), "known_servers")
	opts := Options{KnownServersFile: known, NoSystemProxy: true}
	result, err := InspectCertificate(context.Background(), s.URL, opts)
	if err != nil || result.PreviouslyPinned || result.FingerprintMatch {
		t.Fatalf("first: %+v, %v", result, err)
	}
	if requests.Load() != 0 {
		t.Fatal("inspect sent HTTP request")
	}
	if _, err := os.Stat(known); !os.IsNotExist(err) {
		t.Fatal("inspect created trust store")
	}
	host := strings.TrimPrefix(s.URL, "https://")
	if err := TrustServer(known, host, result.Fingerprint); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(known)
	hc, err := httpClient(s.URL, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer hc.CloseIdleConnections()
	resp, err := hc.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	hc.CloseIdleConnections()
	result, err = InspectCertificate(context.Background(), s.URL, opts)
	if err != nil || !result.FingerprintMatch {
		t.Fatalf("matching: %+v, %v", result, err)
	}
	active.Store(&intercepted)
	_, err = hc.Get(s.URL)
	var unknown *UnknownCertificateError
	if !errors.As(err, &unknown) || unknown.Previous != certificateFingerprint(original.Leaf) || unknown.Certificate == nil || unknown.Assessment.Status != "possible_interception" {
		t.Fatalf("changed certificate: %v", err)
	}
	result, err = InspectCertificate(context.Background(), s.URL, opts)
	if err != nil || result.FingerprintMatch || result.Assessment.Status != "possible_interception" {
		t.Fatalf("inspection: %+v %v", result, err)
	}
	after, _ := os.ReadFile(known)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("inspect modified trust store")
	}
	for _, o := range []Options{{Insecure: true}, {CAFile: "unused"}} {
		if _, err := InspectCertificate(context.Background(), s.URL, o); err == nil {
			t.Fatal("unsupported inspection mode accepted")
		}
	}
}

func TestWSSRedialUsesSamePinVerifier(t *testing.T) {
	original := testCertificate(t, "ntwire", false, nil)
	replacement := testCertificate(t, "replacement", false, nil)
	var active atomic.Pointer[tls.Certificate]
	active.Store(&original)
	sockets := make(chan *websocket.Conn, 4)
	s := certificateServer(t, &active, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" {
			c, err := websocket.Accept(w, r, nil)
			if err == nil {
				sockets <- c
			}
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	known := filepath.Join(t.TempDir(), "known_servers")
	if err := TrustServer(known, strings.TrimPrefix(s.URL, "https://"), certificateFingerprint(original.Leaf)); err != nil {
		t.Fatal(err)
	}
	hc, err := httpClient(s.URL, Options{KnownServersFile: known, NoSystemProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	defer hc.CloseIdleConnections()
	// Observe the actual shared verifier, including errors raised on redial.
	transport := hc.Transport.(*secureControlTransport).Transport
	verify := transport.TLSClientConfig.VerifyConnection
	failures := make(chan error, 20)
	transport.TLSClientConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		err := verify(cs)
		if err != nil {
			select {
			case failures <- err:
			default:
			}
		}
		return err
	}
	resp, err := hc.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	bind := wstransport.NewClient("wss"+strings.TrimPrefix(s.URL, "https")+"/ws", hc, nil)
	bind.SetRedialBackoff(5*time.Millisecond, 20*time.Millisecond, time.Second)
	connected := make(chan bool, 4)
	bind.OnPeerConnected = func(string, conn.Endpoint) { connected <- true }
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	defer bind.Close()
	<-connected
	socket := <-sockets
	active.Store(&replacement)
	_ = socket.CloseNow()
	select {
	case err := <-failures:
		var unknown *UnknownCertificateError
		if !errors.As(err, &unknown) || unknown.Previous == "" || unknown.Certificate == nil {
			t.Fatalf("redial diagnostic: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("redial did not run pinned verification")
	}
	select {
	case <-connected:
		t.Fatal("reconnected despite changed pin")
	case <-time.After(75 * time.Millisecond):
	}
	// Initial WSS dial and HTTPS also fail with the same typed pin error.
	hc.CloseIdleConnections()
	_, err = hc.Get(s.URL)
	var unknown *UnknownCertificateError
	if !errors.As(err, &unknown) {
		t.Fatalf("HTTPS accepted change: %v", err)
	}
	second := wstransport.NewClient("wss"+strings.TrimPrefix(s.URL, "https")+"/ws", hc, nil)
	if _, _, err = second.Open(0); !errors.As(err, &unknown) {
		t.Fatalf("WSS accepted change: %v", err)
	}
	second.Close()
}

func TestCertificateInspectionUsesConnectProxy(t *testing.T) {
	original := testCertificate(t, "origin", false, nil)
	ca := testCertificate(t, "Zscaler Enterprise CA", true, nil)
	presented := testCertificate(t, "origin", false, &ca)
	var active atomic.Pointer[tls.Certificate]
	active.Store(&presented)
	var applicationRequests atomic.Int32
	intercepted := certificateServer(t, &active, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { applicationRequests.Add(1) }))
	destination := strings.TrimPrefix(intercepted.URL, "https://")
	var connects atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != "origin.example.test:443" {
			t.Errorf("unexpected proxy request %s %s", r.Method, r.Host)
			http.Error(w, "bad request", 400)
			return
		}
		upstream, err := net.Dial("tcp", destination)
		if err != nil {
			http.Error(w, "dial", 502)
			return
		}
		downstream, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			upstream.Close()
			return
		}
		connects.Add(1)
		_, _ = io.WriteString(downstream, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() { defer downstream.Close(); defer upstream.Close(); _, _ = io.Copy(upstream, downstream) }()
		_, _ = io.Copy(downstream, upstream)
	}))
	defer proxy.Close()
	known := filepath.Join(t.TempDir(), "known_servers")
	if err := TrustServer(known, "origin.example.test:443", certificateFingerprint(original.Leaf)); err != nil {
		t.Fatal(err)
	}
	result, err := InspectCertificate(context.Background(), "https://origin.example.test:443", Options{KnownServersFile: known, HTTPSProxy: proxy.URL, NoSystemProxy: true})
	if err != nil || result.FingerprintMatch || result.Assessment.Status != "identity_mismatch" {
		t.Fatalf("inspection: %+v %v", result, err)
	}
	if !strings.Contains(strings.Join(result.Assessment.Indicators, ","), "enterprise_inspection_issuer") || !strings.Contains(strings.Join(result.Assessment.Indicators, ","), "certificate_changed") {
		t.Fatalf("missing proxy indicators: %+v", result)
	}
	if connects.Load() != 1 || applicationRequests.Load() != 0 {
		t.Fatal("proxy path bypassed or application request sent")
	}
	// A certificate from an HTTPS proxy's outer TLS session is not the
	// destination certificate. The existing proxy verification may reject it.
	proxyResult, proxyErr := InspectCertificate(context.Background(), "https://origin.example.test:443", Options{KnownServersFile: known, HTTPSProxy: intercepted.URL})
	if proxyResult != nil || proxyErr == nil {
		t.Fatal("HTTPS proxy certificate mislabeled as origin certificate")
	}
	socks := startTestSOCKS5Server(t, "", "")
	defer socks.Close()
	result, err = InspectCertificate(context.Background(), intercepted.URL, Options{KnownServersFile: known, HTTPSProxy: "socks5h://" + socks.Addr()})
	if err != nil || result.Certificate.IssuerCommonName != "Zscaler Enterprise CA" || socks.RequestCount() != 1 {
		t.Fatalf("SOCKS inspection: %+v %v", result, err)
	}
}

func TestCertificateCustomCAPolicyUnchanged(t *testing.T) {
	root := testCertificate(t, "Private Enterprise Root", true, nil)
	leaf := testCertificate(t, "ntwire", false, &root)
	var active atomic.Pointer[tls.Certificate]
	active.Store(&leaf)
	s := certificateServer(t, &active, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	hc, err := httpClient(s.URL, Options{CAFile: path, NoSystemProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	defer hc.CloseIdleConnections()
	resp, err := hc.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	hc.CloseIdleConnections()
	// A self-signed replacement does not inherit trust from its presence in
	// a presented chain. Custom CA mode continues to fail normal PKI checks.
	replacement := testCertificate(t, "Private Enterprise Root", false, nil)
	active.Store(&replacement)
	if _, err := hc.Get(s.URL); err == nil {
		t.Fatal("custom CA accepted untrusted replacement")
	}
}

func TestDescribeCertificateValidity(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name          string
		before, after time.Time
		indicator     string
	}{
		{"expired", now.Add(-2 * time.Hour), now.Add(-time.Hour), "expired"},
		{"not yet valid", now.Add(time.Hour), now.Add(2 * time.Hour), "not_yet_valid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := testCertificateValidity(t, "ntwire", false, nil, tc.before, tc.after)
			details := DescribeCertificate(tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert.Leaf}}, "localhost")
			assessment := AssessCertificateAt(*details, "", now)
			if !strings.Contains(strings.Join(assessment.Indicators, ","), tc.indicator) {
				t.Fatalf("%+v", assessment)
			}
		})
	}
}
