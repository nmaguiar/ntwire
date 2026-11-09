package client

import (
	"github.com/nmaguiar/ntwire/pkg/browseropen"
	"reflect"
	"testing"
)

func TestBrowserArgsLiveResolver(t *testing.T) {
	old := openSocksWithOptions
	t.Cleanup(func() { openSocksWithOptions = old })
	var calls int
	var got browseropen.LaunchOptions
	openSocksWithOptions = func(o browseropen.LaunchOptions, key, addr string, urls ...string) error {
		calls++
		got = o
		if key != "profile-socks" || addr != "127.0.0.1:1080" || !reflect.DeepEqual(urls, []string{"https://example.com"}) {
			t.Fatalf("unexpected launch %s %s %q", key, addr, urls)
		}
		return nil
	}
	args := []string{"--first"}
	c := &Connection{options: Options{ResolveBrowserOptions: func() (browseropen.LaunchOptions, error) { return browseropen.LaunchOptions{ExtraArgs: args}, nil }}}
	launch := func() error {
		return c.openConfiguredSocksBrowser("profile-socks", "127.0.0.1:1080", "https://example.com")
	}
	if err := launch(); err != nil {
		t.Fatal(err)
	}
	args = []string{"--second=a b"}
	if err := launch(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.ExtraArgs, args) || calls != 2 {
		t.Fatalf("stale settings: %+v calls %d", got, calls)
	}
	args = []string{"--proxy-server=bad"}
	if launch() == nil || calls != 2 {
		t.Fatal("invalid arguments reached launcher")
	}
}

func TestBrowserArgsConfigRoundTrip(t *testing.T) {
	path := t.TempDir() + "/config.yaml"
	want := []string{"--custom=a b", "--custom=a b"}
	if _, err := SaveSettings(path, Settings{BrowserArgs: want}); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSettings(path)
	if err != nil || !reflect.DeepEqual(got.BrowserArgs, want) {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := SaveSettings(path, Settings{}); err != nil {
		t.Fatal(err)
	}
	got, err = LoadSettings(path)
	if err != nil || len(got.BrowserArgs) != 0 {
		t.Fatalf("clear: %+v %v", got, err)
	}
	if _, err := SaveSettings(path, Settings{BrowserArgs: []string{"--user-data-dir=x"}}); err == nil {
		t.Fatal("accepted protected argument")
	}
}
