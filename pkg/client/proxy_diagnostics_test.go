package client

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/net/http/httpproxy"
)

func TestValidateProxyURL(t *testing.T) {
	for _, raw := range []string{"http://proxy", "http://bücher.example", "https://user:p%40ss@proxy:8443", "socks5://[::1]:1080", "socks5h://proxy", "HTTP://proxy:80"} {
		if err := ValidateProxyURL(raw); err != nil {
			t.Errorf("valid proxy rejected: %v", err)
		}
	}
	for _, raw := range []string{"", "proxy:80", "file:///tmp/x", "http://bad!host", "http://-host", "http://host..example", "ftp://proxy", "http://", "http://host:0", "http://host:65536", "http://host:abc", "http://host:", "http://::1:80", "http://[bad]:80", "http://host/path", "http://host?x=1", "http://host/#x", "http://user:secret%zz@host"} {
		if err := ValidateProxyURL(raw); err == nil {
			t.Errorf("invalid proxy accepted: %q", raw)
		} else if strings.Contains(err.Error(), "secret") {
			t.Fatal("error contains secret")
		}
	}
}

// A fresh process avoids Go's intentionally cached process proxy environment.
func TestProxyEnvironmentDiagnostics(t *testing.T) {
	if os.Getenv("NTWIRE_PROXY_TEST_CHILD") == "1" {
		var opts Options
		if os.Getenv("NTWIRE_PROXY_TEST_CUSTOM") != "" {
			opts.HTTPSProxy = "socks5h://alice:secret@custom:1080"
			opts.NoSystemProxy = true
		}
		if os.Getenv("NTWIRE_PROXY_TEST_DIRECT") != "" {
			opts.NoSystemProxy = true
		}
		server := os.Getenv("NTWIRE_PROXY_TEST_SERVER")
		d := DiagnoseProxy(server, opts)
		if d.EffectiveSource != os.Getenv("NTWIRE_PROXY_TEST_SOURCE") || !strings.Contains(d.Status, os.Getenv("NTWIRE_PROXY_TEST_STATUS")) || (d.Error != "") != (os.Getenv("NTWIRE_PROXY_TEST_ERROR") == "1") {
			t.Fatalf("unexpected diagnostics: %+v", d)
		}
		if opts.HTTPSProxy == "" && !opts.NoSystemProxy {
			normalized, _ := NormalizeServerURL(server)
			req, _ := http.NewRequest("GET", normalized, nil)
			got, gotErr := http.ProxyFromEnvironment(req)
			want, wantErr := processProxyEnvironment().config.ProxyFunc()(req.URL)
			if (gotErr != nil) != (wantErr != nil) || (got == nil) != (want == nil) || got != nil && got.String() != want.String() {
				t.Fatal("client selector diverges from net/http")
			}
			if got != nil && d.EffectiveProxy != RedactProxyURL(got.String()) {
				t.Fatal("diagnostics diverge from client")
			}
		}
		b, _ := json.Marshal(d)
		if strings.Contains(string(b), "secret") || strings.Contains(string(b), "UNRELATED") {
			t.Fatal("diagnostics leak sensitive data")
		}
		return
	}
	cases := []struct {
		name, server, source, status string
		env                          []string
		bad                          bool
	}{
		{"https", "https://server.example", "HTTPS_PROXY", "", []string{"HTTPS_PROXY=http://upper:8080", "https_proxy=http://lower:8080"}, false},
		{"hostname shorthand", "server.example:8443", "HTTPS_PROXY", "", []string{"HTTPS_PROXY=http://proxy"}, false},
		{"http", "http://server.example", "HTTP_PROXY", "", []string{"HTTP_PROXY=http://proxy:8080"}, false},
		{"lower https", "https://server.example", "https_proxy", "", []string{"https_proxy=http://proxy:8080"}, false},
		{"lower http", "http://server.example", "http_proxy", "", []string{"http_proxy=http://proxy:8080"}, false},
		{"empty", "https://server.example", "Direct", "No environment proxy configured", nil, false},
		{"http not https", "https://server.example", "Direct", "No environment proxy configured", []string{"HTTP_PROXY=http://proxy"}, false},
		{"bypass", "https://server.example", "Direct", "NO_PROXY match", []string{"HTTPS_PROXY=http://proxy", "NO_PROXY=.example"}, false},
		{"lower bypass", "https://server.example", "Direct", "NO_PROXY match", []string{"HTTPS_PROXY=http://proxy", "no_proxy=server.example"}, false},
		{"bypass precedence", "https://server.example", "HTTPS_PROXY", "", []string{"HTTPS_PROXY=http://proxy", "NO_PROXY=other.example", "no_proxy=server.example"}, false},
		{"no bypass", "https://server.example", "HTTPS_PROXY", "", []string{"HTTPS_PROXY=http://proxy", "NO_PROXY=other.example"}, false},
		{"localhost", "https://localhost:8443", "Direct", "loopback destination", []string{"HTTPS_PROXY=http://proxy"}, false},
		{"loopback", "https://127.0.0.1", "Direct", "loopback destination", []string{"HTTPS_PROXY=http://proxy"}, false},
		{"ipv6", "https://[::1]", "Direct", "loopback destination", []string{"HTTPS_PROXY=http://proxy"}, false},
		{"custom", "https://server.example", "Custom profile setting", "", []string{"HTTPS_PROXY=http://proxy", "NTWIRE_PROXY_TEST_CUSTOM=1"}, false},
		{"direct", "https://server.example", "Direct", "system proxy ignored", []string{"HTTPS_PROXY=http://proxy", "NTWIRE_PROXY_TEST_DIRECT=1"}, false},
		{"malformed", "https://server.example", "Direct", "", []string{"HTTPS_PROXY=http://user:secret%zz@proxy"}, true},
		{"credentials", "https://server.example", "HTTPS_PROXY", "", []string{"HTTPS_PROXY=socks5://user:secret@proxy:1080"}, false},
		{"cgi", "http://server.example", "Direct", "", []string{"HTTP_PROXY=http://proxy", "REQUEST_METHOD=GET"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestProxyEnvironmentDiagnostics$")
			cmd.Env = append([]string{"NTWIRE_PROXY_TEST_CHILD=1", "NTWIRE_PROXY_TEST_SERVER=" + tc.server, "NTWIRE_PROXY_TEST_SOURCE=" + tc.source, "NTWIRE_PROXY_TEST_STATUS=" + tc.status, "UNRELATED=secret"}, tc.env...)
			if tc.bad {
				cmd.Env = append(cmd.Env, "NTWIRE_PROXY_TEST_ERROR=1")
			}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v: %s", err, out)
			}
		})
	}
}

func TestProxyEnvironmentNOProxyRules(t *testing.T) {
	for _, bypass := range []string{"10.0.0.0/8", "server.example:8443", "*", ".example"} {
		cfg := &httpproxy.Config{HTTPSProxy: "http://proxy", NoProxy: bypass}
		server := "https://server.example:8443"
		if strings.Contains(bypass, "10.") {
			server = "https://10.2.3.4"
		}
		d := diagnoseProxy(server, Options{}, cfg, map[string]string{"HTTPS_PROXY": "http://proxy"})
		if !d.Bypassed {
			t.Errorf("rule %s did not bypass", bypass)
		}
	}
	for _, raw := range []string{"http://user:secret@proxy", "user:secret@proxy:80", "http://user:secret%zz@proxy"} {
		if strings.Contains(RedactProxyURL(raw), "secret") {
			t.Fatal("redaction leaked password")
		}
	}
}
