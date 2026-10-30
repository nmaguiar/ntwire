package server

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigNormalizesTunnelPrefix(t *testing.T) {
	for _, tc := range []struct{ cidr, want string }{
		{"10.20.30.99/24", "10.20.30.0/24"}, {"fd00::1234/120", "fd00::1200/120"},
		{"10.0.0.0/30", "10.0.0.0/30"}, {"10.0.0.0/31", ""}, {"10.0.0.1/32", ""},
		{"fd00::/127", ""}, {"fd00::/128", ""},
	} {
		t.Run(tc.cidr, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			body := fmt.Sprintf("auth:\n  authorized_keys_dir: %s\nnetwork:\n  tunnel_cidr: %s\n", dir, tc.cidr)
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(path)
			if tc.want == "" {
				if err == nil {
					t.Fatal("prefix without client capacity accepted")
				}
				return
			}
			if err != nil || cfg.Network.TunnelCIDR != tc.want {
				t.Fatalf("prefix=%s err=%v", cfg.Network.TunnelCIDR, err)
			}
		})
	}
}
