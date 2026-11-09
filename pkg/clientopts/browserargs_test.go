package clientopts

import (
	"reflect"
	"testing"
)

func TestBrowserArgsOverrides(t *testing.T) {
	for _, tc := range []struct {
		name       string
		argv, want []string
		bad        bool
	}{
		{name: "inherit", want: []string{"--saved"}},
		{name: "replace", argv: []string{"--browser-arg=--custom=a b", "--browser-arg=--custom=a b"}, want: []string{"--custom=a b", "--custom=a b"}},
		{name: "clear", argv: []string{"--no-browser-args"}},
		{name: "conflict", argv: []string{"--no-browser-args", "--browser-arg=--custom"}, bad: true},
		{name: "managed", argv: []string{"--browser-arg=--proxy-server=x"}, bad: true},
	} {
		for _, command := range []string{"browser", "connect"} {
			t.Run(command+"/"+tc.name, func(t *testing.T) {
				f := NewFlagSet(command, Defaults{})
				if err := f.Parse(tc.argv); err != nil {
					t.Fatal(err)
				}
				got, err := f.BrowserArgs([]string{"--saved"})
				if (err != nil) != tc.bad {
					t.Fatalf("args=%q err=%v", got, err)
				}
				if !tc.bad && !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("got %q want %q", got, tc.want)
				}
			})
		}
	}
}
