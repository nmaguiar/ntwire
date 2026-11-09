package browseropen

import (
	"reflect"
	"testing"
)

func TestExtraArgumentsValidation(t *testing.T) {
	for _, arg := range []string{"--disable-background-networking", "--custom=value with spaces", "--unknown-switch"} {
		if err := ValidateExtraArgs([]string{arg}); err != nil {
			t.Errorf("%q: %v", arg, err)
		}
	}
	for _, arg := range []string{"--", "https://example.com", "--proxy-server=direct://", "--user-data-dir=/tmp", "--proxy-pac-url=x", "--flag\n=value", "--profile-directory=Default", "--proxy-auto-detect", "--no-proxy-server", "--proxy-bypass-list=*", "--PROXY-SERVER=x", "--bad_name=x", "--flag\x00", "\n", "--flag\r=value"} {
		if ValidateExtraArgs([]string{arg}) == nil {
			t.Errorf("accepted %q", arg)
		}
	}
}

func TestExtraArgumentsResolution(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want []string
	}{
		{"", []string{"--global"}}, {"inherit", []string{"--global"}},
		{"append", []string{"--global", "--local"}}, {"replace", []string{"--local"}},
	} {
		got, err := ResolveExtraArgs([]string{"--global"}, []string{"--local"}, tc.mode)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %v, %v", tc.mode, got, err)
		}
	}
	got, err := ResolveExtraArgs([]string{"--global"}, nil, "replace")
	if err != nil || len(got) != 0 {
		t.Fatalf("empty replacement: %v, %v", got, err)
	}
	if _, err := ResolveExtraArgs(nil, nil, "bad"); err == nil {
		t.Fatal("accepted invalid mode")
	}
}

func TestExtraArgumentsBeforeURL(t *testing.T) {
	got := insertExtraArgs([]string{"--managed", "--", "https://example.com"}, []string{"", "--custom=a b"})
	want := []string{"--managed", "--custom=a b", "--", "https://example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}
