package logging

import "testing"

func TestResolvePrecedence(t *testing.T) {
	cases := []struct {
		name                  string
		flag, config, env     Options
		wantFormat, wantLevel string
	}{
		{
			name:       "default when nothing set",
			wantFormat: "text", wantLevel: "info",
		},
		{
			name:       "env only",
			env:        Options{Format: "json", Level: "debug"},
			wantFormat: "json", wantLevel: "debug",
		},
		{
			name:       "config beats env",
			config:     Options{Format: "text"},
			env:        Options{Format: "json", Level: "warn"},
			wantFormat: "text", wantLevel: "warn",
		},
		{
			name:       "flag beats config and env",
			flag:       Options{Format: "json"},
			config:     Options{Format: "text", Level: "error"},
			env:        Options{Format: "text", Level: "debug"},
			wantFormat: "json", wantLevel: "error",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Resolve(c.flag, c.config, c.env)
			if got.Format != c.wantFormat || got.Level != c.wantLevel {
				t.Errorf("Resolve() = %+v, want format=%q level=%q", got, c.wantFormat, c.wantLevel)
			}
		})
	}
}

func TestEnvOptions(t *testing.T) {
	t.Setenv("NTWIRE_LOG_FORMAT", "json")
	t.Setenv("NTWIRE_LOG_LEVEL", "debug")
	got := EnvOptions("NTWIRE")
	if got.Format != "json" || got.Level != "debug" {
		t.Errorf("EnvOptions() = %+v", got)
	}
}

func TestParseLevel(t *testing.T) {
	cases := map[string]string{
		"debug": "DEBUG", "warn": "WARN", "warning": "WARN",
		"error": "ERROR", "info": "INFO", "": "INFO", "bogus": "INFO",
	}
	for in, want := range cases {
		if got := ParseLevel(in).String(); got != want {
			t.Errorf("ParseLevel(%q) = %s, want %s", in, got, want)
		}
	}
}
