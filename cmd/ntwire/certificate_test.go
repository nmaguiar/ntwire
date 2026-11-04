package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/client"
)

func TestCertificateTrustPrompts(t *testing.T) {
	for _, changed := range []bool{false, true} {
		for _, metadata := range []bool{false, true} {
			e := &client.UnknownCertificateError{Host: "server.example", Fingerprint: "SHA256:new"}
			if changed {
				e.Previous = "SHA256:old"
			}
			if metadata {
				e.Certificate = &client.CertificateDetails{Subject: "CN=server\x1b[31m", Issuer: "CN=Netskope CA", SHA256Fingerprint: e.Fingerprint, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
				a := client.AssessCertificate(*e.Certificate, e.Previous)
				e.Assessment = &a
			}
			var out bytes.Buffer
			writeTrustPrompt(&out, e)
			text := out.String()
			for _, want := range []string{e.Host, e.Fingerprint, "[y/N]", "trusted source"} {
				if !strings.Contains(text, want) {
					t.Fatalf("missing %q in %q", want, text)
				}
			}
			if changed && (!strings.Contains(text, "SERVER CERTIFICATE CHANGED") || !strings.Contains(text, e.Previous)) {
				t.Fatal(text)
			}
			if metadata && (!strings.Contains(text, "Netskope CA") || !strings.Contains(text, "Valid until:") || !strings.Contains(text, "may be intercepted")) {
				t.Fatal(text)
			}
			if strings.ContainsRune(text, '\x1b') {
				t.Fatal("terminal escape injection")
			}
		}
	}
}

func TestConfirmCertificate(t *testing.T) {
	for _, tc := range []struct {
		answer           string
		terminal, accept bool
	}{
		{"y", true, true}, {"YES", true, true}, {"n", true, false}, {"", true, false}, {"yes", false, false}, {"anything", true, false},
	} {
		t.Run(tc.answer+strings.Repeat("tty", boolInt(tc.terminal)), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "known_servers")
			e := &client.UnknownCertificateError{Host: "host", Fingerprint: "SHA256:new", Previous: "SHA256:old"}
			var out bytes.Buffer
			if got := confirmCertificate(e, path, strings.NewReader(tc.answer), &out, tc.terminal); got != tc.accept {
				t.Fatalf("got %v: %s", got, out.String())
			}
			data, err := os.ReadFile(path)
			if tc.accept {
				if err != nil || !strings.Contains(string(data), e.Fingerprint) {
					t.Fatalf("pin not written: %s %v", data, err)
				}
			} else if !os.IsNotExist(err) {
				t.Fatal("rejection wrote trust store")
			}
		})
	}
}
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func TestCertificateInspectArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}, {"inspect"}, {"inspect", "http://example.test"}, {"inspect", "https://user:pass@example.test"}, {"inspect", "--unknown"}} {
		var out bytes.Buffer
		if code := runCertInspect(args, &out, &out); code != 1 {
			t.Fatalf("%v: exit=%d", args, code)
		}
	}
}

func TestCertificateInspectOutputAndExitCodes(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("inspect sent an application request") }))
	defer s.Close()
	path := filepath.Join(t.TempDir(), "known_servers")
	args := []string{"inspect", "--no-system-proxy", "--known-servers", path, "--json", s.URL}
	var output, errors bytes.Buffer
	if code := runCertInspect(args, &output, &errors); code != 2 {
		t.Fatalf("first exit %d: %s", code, errors.String())
	}
	var result client.CertificateInspection
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.FingerprintMatch || result.Certificate == nil {
		t.Fatalf("%s", output.String())
	}
	sum := sha256.Sum256(s.Certificate().Raw)
	fp := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	if result.Fingerprint != fp {
		t.Fatal("fingerprint encoding changed")
	}
	if err := client.TrustServer(path, strings.TrimPrefix(s.URL, "https://"), fp); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if code := runCertInspect(args, &output, &errors); code != 0 {
		t.Fatalf("matching exit %d: %s", code, errors.String())
	}
	output.Reset()
	if code := runCertInspect([]string{"inspect", "--known-servers", path, "--no-system-proxy", s.URL}, &output, &errors); code != 0 || !strings.Contains(output.String(), "Fingerprint match: true") {
		t.Fatalf("text exit %d: %s", code, output.String())
	}
	if err := client.TrustServer(path, strings.TrimPrefix(s.URL, "https://"), "SHA256:old"); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if code := runCertInspect(args, &output, &errors); code != 2 {
		t.Fatalf("changed exit %d", code)
	}
	if !strings.Contains(output.String(), "certificate_changed") {
		t.Fatal(output.String())
	}
}
