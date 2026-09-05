package browseropen

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// unsafeURLs are values a malicious or compromised server could put in a portal
// target's URL. Chromium reads a leading "-" as a switch, and macOS "open" /
// xdg-open act on local paths, so none of these may reach a process argument.
var unsafeURLs = []string{
	"--load-extension=/tmp/evil",
	"--remote-debugging-port=9222",
	"--disable-web-security",
	"-incognito",
	"file:///etc/passwd",
	"javascript:alert(1)",
	"data:text/html,<script>alert(1)</script>",
	"/Applications/Calculator.app",
	"https://example.com --load-extension=/tmp/evil",
	"",
}

func TestOpenRejectsUnsafeURLs(t *testing.T) {
	for _, u := range unsafeURLs {
		if err := Open(u); !errors.Is(err, ErrUnsafeURL) {
			t.Fatalf("Open(%q) error = %v, want ErrUnsafeURL", u, err)
		}
	}
}

func TestSocksArgsRejectsUnsafeURLs(t *testing.T) {
	for _, u := range unsafeURLs {
		if u == "" {
			continue // an empty target simply means "no URL", not an attack
		}
		if _, err := socksArgs("/tmp/profile", "127.0.0.1:1080", []string{u}); !errors.Is(err, ErrUnsafeURL) {
			t.Fatalf("socksArgs(%q) error = %v, want ErrUnsafeURL", u, err)
		}
	}
}

// TestSocksArgsTerminatesFlagsBeforeURL checks the second guard: even a URL
// that passes validation is placed after "--", so Chromium cannot read it as a
// switch under any parsing rule.
func TestSocksArgsTerminatesFlagsBeforeURL(t *testing.T) {
	args, err := socksArgs("/tmp/profile", "127.0.0.1:1080", []string{"https://example.com/x"})
	if err != nil {
		t.Fatal(err)
	}
	sep := slices.Index(args, "--")
	if sep < 0 {
		t.Fatalf("no flag terminator in %v", args)
	}
	url := slices.Index(args, "https://example.com/x")
	if url < sep {
		t.Fatalf("URL appears before the flag terminator: %v", args)
	}
	for _, a := range args[:sep] {
		if !strings.HasPrefix(a, "--") {
			t.Fatalf("unexpected positional argument %q before the terminator: %v", a, args)
		}
	}
}

func TestSocksArgsKeepsEmptyTargetPositional(t *testing.T) {
	args, err := socksArgs("/tmp/profile", "127.0.0.1:1080", nil)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(args, "--") {
		t.Fatalf("no URL means no flag terminator is needed: %v", args)
	}
}
