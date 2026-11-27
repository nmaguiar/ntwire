package benchmark

import "testing"

func TestNativeWireGuardFixture(t *testing.T) {
	for _, workload := range []string{"interactive", "udp"} {
		t.Run(workload, func(t *testing.T) {
			f, err := newFixture(t.Context(), Options{
				Transport: "native-wireguard-go", Workload: workload, Connections: 1, MaxBytes: 1 << 20,
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(f.close)
			if err = f.ready(t.Context()); err != nil {
				t.Fatal(err)
			}
			if f.client != nil || f.activePath() != "native-wireguard-go" {
				t.Fatal("the baseline used ntwire client control state")
			}
		})
	}
}
