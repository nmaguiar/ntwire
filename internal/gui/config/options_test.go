package config

import (
	"os"
	"testing"
)

func TestToClientOptionsRejectsEmptyStatusFile(t *testing.T) {
	p := Profile{Name: "home-lab", Server: "https://home.example:8443"}
	if _, err := p.ToClientOptions("", ""); err == nil {
		t.Fatal("ToClientOptions(\"\", ...) = nil error, want an error -- an empty StatusFile " +
			"makes Connection.Close delete ~/.ntwire/status.json out from under a running ntwire connect")
	}
}

func TestToClientOptionsSetsNoWebUITrueAndNoBrowserFalse(t *testing.T) {
	p := Profile{Name: "home-lab"}
	o, err := p.ToClientOptions("/tmp/status.json", "")
	if err != nil {
		t.Fatalf("ToClientOptions() error = %v", err)
	}
	if !o.NoWebUI {
		t.Error("NoWebUI = false, want true (the GUI renders its own dashboard)")
	}
	if o.NoBrowser {
		t.Error("NoBrowser = true, want false (SSO login must still be able to open a browser)")
	}
}

func TestToClientOptionsIncludesHTTPSProxyControls(t *testing.T) {
	p := Profile{HTTPSProxy: "http://proxy.example:8080", NoSystemProxy: true}
	o, err := p.ToClientOptions("/tmp/status.json", "")
	if err != nil {
		t.Fatal(err)
	}
	if o.HTTPSProxy != p.HTTPSProxy || !o.NoSystemProxy {
		t.Errorf("proxy options = %+v, want profile values", o)
	}
}

func TestToClientOptionsCopiesPortsAndPassphrase(t *testing.T) {
	p := Profile{Ports: map[string]int{"web": 8080, "db": 5432}}
	o, err := p.ToClientOptions("/tmp/status.json", "hunter2")
	if err != nil {
		t.Fatalf("ToClientOptions() error = %v", err)
	}
	if o.Ports["web"] != 8080 || o.Ports["db"] != 5432 || len(o.Ports) != 2 {
		t.Errorf("Ports = %v, want a copy of the profile's ports", o.Ports)
	}
	if o.KeyPassphrase != "hunter2" {
		t.Errorf("KeyPassphrase = %q, want %q", o.KeyPassphrase, "hunter2")
	}
	// Mutating the returned map must not alias the profile's own map.
	o.Ports["web"] = 9999
	if p.Ports["web"] != 8080 {
		t.Errorf("ToClientOptions() aliased the profile's Ports map")
	}
}

func TestExpandHomeExpandsLeadingTilde(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory available in this environment")
	}
	cases := []struct{ in, want string }{
		{"~/.ntwire/id_ed25519", home + "/.ntwire/id_ed25519"},
		{"~", home},
		{"/absolute/path", "/absolute/path"},
		{"", ""},
		{"relative/path", "relative/path"},
	}
	for _, c := range cases {
		if got := ExpandHome(c.in); got != c.want {
			t.Errorf("ExpandHome(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIdentityFilePathExpandsTilde(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory available in this environment")
	}
	p := Profile{IdentityFile: "~/.ntwire/id_ed25519"}
	if got, want := p.IdentityFilePath(), home+"/.ntwire/id_ed25519"; got != want {
		t.Errorf("IdentityFilePath() = %q, want %q", got, want)
	}
}
