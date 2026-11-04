package client

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/http/httpproxy"
	"golang.org/x/net/idna"
)

// Capture the environment once, like net/http.ProxyFromEnvironment. Diagnostics
// metadata uses the declared toolchain's CGI and variable precedence rules.
// Effective routing always comes directly from net/http.
type proxyEnvironmentState struct {
	config  *httpproxy.Config
	display map[string]string
}

var processProxyEnvironment = sync.OnceValue(func() proxyEnvironmentState {
	env := map[string]string{}
	for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"} {
		if v := os.Getenv(key); v != "" {
			if key == "NO_PROXY" || key == "no_proxy" {
				env[key] = v
			} else {
				env[key] = RedactProxyURL(v)
			}
		}
	}
	// net/http in the declared Go toolchain uses uppercase-first. Do not
	// call x/net's FromEnvironment: this dependency uses different precedence.
	pick := func(upper, lower string) string {
		if v := os.Getenv(upper); v != "" {
			return v
		}
		return os.Getenv(lower)
	}
	cfg := &httpproxy.Config{HTTPProxy: pick("HTTP_PROXY", "http_proxy"), HTTPSProxy: pick("HTTPS_PROXY", "https_proxy"), NoProxy: pick("NO_PROXY", "no_proxy"), CGI: os.Getenv("REQUEST_METHOD") != ""}
	// Initialize net/http's cached environment at the same time as metadata.
	_, _ = http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: "https", Host: "localhost"}})
	return proxyEnvironmentState{cfg, env}
})

// ValidateProxyURL validates an explicit proxy without echoing sensitive input.
// Omitted ports use the existing HTTP(S)/SOCKS defaults.
func ValidateProxyURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return errors.New("proxy URL requires a valid scheme and hostname")
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return errors.New("proxy scheme must be http, https, socks5, or socks5h")
	}
	if u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return errors.New("proxy URL cannot contain a path, query, or fragment")
	}
	host := u.Hostname()
	if strings.Contains(host, ":") && (net.ParseIP(host) == nil || !strings.HasPrefix(u.Host, "[")) {
		return errors.New("proxy IPv6 address must be valid and enclosed in brackets")
	}
	if strings.ContainsAny(host, " \t\r\n/?#\\") {
		return errors.New("proxy hostname is invalid")
	}
	if !strings.Contains(host, ":") && net.ParseIP(host) == nil {
		ascii, err := idna.Lookup.ToASCII(strings.TrimSuffix(host, "."))
		if err != nil || len(ascii) == 0 || len(ascii) > 253 {
			return errors.New("proxy hostname is invalid")
		}
		for _, label := range strings.Split(ascii, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return errors.New("proxy hostname is invalid")
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
					return errors.New("proxy hostname is invalid")
				}
			}
		}
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return errors.New("proxy port must be between 1 and 65535")
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return errors.New("proxy port is empty")
	}
	return nil
}

// ProxyDiagnostics describes configured routing, never a proven connection.
type ProxyDiagnostics struct {
	Mode            string            `json:"mode"`
	EffectiveSource string            `json:"effective_source"`
	EffectiveProxy  string            `json:"effective_proxy"`
	Bypassed        bool              `json:"bypassed"`
	Status          string            `json:"status"`
	Error           string            `json:"error,omitempty"`
	Environment     map[string]string `json:"environment"`
}

// DiagnoseProxy resolves against the destination using the transport's environment
// selector. Only the six proxy variables are returned, with URL passwords masked.
func DiagnoseProxy(server string, o Options) ProxyDiagnostics {
	state := processProxyEnvironment()
	return diagnoseProxyWithResolver(server, o, state.config, state.display, func(u *url.URL) (*url.URL, error) { return http.ProxyFromEnvironment(&http.Request{URL: u}) })
}

func diagnoseProxy(server string, o Options, cfg *httpproxy.Config, env map[string]string) ProxyDiagnostics {
	return diagnoseProxyWithResolver(server, o, cfg, env, cfg.ProxyFunc())
}

func diagnoseProxyWithResolver(server string, o Options, cfg *httpproxy.Config, env map[string]string, resolve func(*url.URL) (*url.URL, error)) ProxyDiagnostics {
	d := ProxyDiagnostics{Mode: "environment", EffectiveSource: "Direct", Environment: env}
	if o.HTTPSProxy != "" {
		d.Mode = "custom"
		d.EffectiveSource = "Custom profile setting"
		d.EffectiveProxy = RedactProxyURL(o.HTTPSProxy)
		if err := ValidateProxyURL(o.HTTPSProxy); err != nil {
			d.Error = err.Error()
		}
		return d
	}
	if o.NoSystemProxy {
		d.Mode = "direct"
		d.Status = "Direct connection — system proxy ignored"
		return d
	}
	normalized, err := NormalizeServerURL(server)
	if err != nil {
		d.Error = "Enter a valid HTTP or HTTPS server URL to resolve the proxy"
		return d
	}
	u, err := url.Parse(normalized)
	if err != nil || u.Hostname() == "" {
		d.Error = "Enter a valid HTTP or HTTPS server URL to resolve the proxy"
		return d
	}
	selected, key := cfg.HTTPProxy, "HTTP_PROXY"
	if u.Scheme == "https" {
		selected, key = cfg.HTTPSProxy, "HTTPS_PROXY"
	}
	if selected == "" {
		d.Status = "No environment proxy configured"
		return d
	}
	if env[key] == "" {
		key = strings.ToLower(key)
	}
	p, err := resolve(u)
	if err != nil {
		d.Error = "Environment proxy resolution failed; check proxy URL and CGI restrictions"
		return d
	}
	if p != nil {
		d.EffectiveProxy = RedactProxyURL(p.String())
		d.EffectiveSource = key
		return d
	}
	d.Status = "Direct connection — environment proxy not selected"
	withoutBypass := *cfg
	withoutBypass.NoProxy = ""
	if p, _ := withoutBypass.ProxyFunc()(u); p != nil {
		d.Bypassed = true
		d.Status = "Direct connection — NO_PROXY match"
	} else if ip := net.ParseIP(u.Hostname()); u.Hostname() == "localhost" || ip != nil && ip.IsLoopback() {
		d.Status = "Direct connection — loopback destination"
	} else {
		d.Error = "Environment proxy URL is invalid"
	}
	return d
}
