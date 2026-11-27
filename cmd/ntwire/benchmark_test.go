package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nmaguiar/ntwire/pkg/ui"
)

func TestBenchmarkRejectsUncontrolledTargetsAndInvalidOptions(t *testing.T) {
	for _, tc := range []struct {
		args      []string
		errorText string
	}{
		{[]string{"https://example.invalid"}, "no target addresses"},
		{[]string{"--fixture", "external.yaml"}, "no target addresses"},
		{[]string{"--connections", "0"}, "connections must"},
		{[]string{"--compare-transports", "--transport", "wss"}, "conflicts"},
		{[]string{"--duration", "1h"}, "duration must"},
		{[]string{"--bulk-rate-mbps", "10"}, "requires a bulk or mixed workload"},
		{[]string{"--workload", "bulk", "--bulk-rate-mbps", "10001"}, "0 to 10000 Mbit/s"},
		{[]string{"--transport", "udp-relay"}, "laboratory command"},
		{[]string{"--kernel-server"}, "flag provided but not defined"},
		{[]string{"--transport", "direct", "--workload", "socks5"}, "requires a WireGuard transport"},
	} {
		u := ui.New(&bytes.Buffer{}, &bytes.Buffer{}, true)
		if err := benchmarkCmd(tc.args, u); err == nil || !strings.Contains(err.Error(), tc.errorText) {
			t.Errorf("benchmark %v returned %v, want %q", tc.args, err, tc.errorText)
		}
	}
}
