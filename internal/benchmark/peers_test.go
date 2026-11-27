package benchmark

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

func TestPeerMeasurements_BracketMeasurement(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("separate-peer fixture is Linux-only")
	}
	path := filepath.Join(t.TempDir(), "q.sock")
	var samples uint64
	stop, err := servePeerMeasurements(path, func() serverMeasurement {
		samples += 5
		return serverMeasurement{
			WSS: wssSnapshot{
				Performance: wstransport.QueuePerformance{Enabled: true, SampledBatches: samples},
			},
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	f := &fixture{peerMeasurementsSocket: path}
	client, before, err := f.measurementSnapshots(t.Context())
	if err != nil || client.Performance.Enabled || before.WSS.Performance.SampledBatches != 5 {
		t.Fatalf("unexpected starting snapshots: client %+v, server %+v, error %v", client, before, err)
	}
	_, after, err := f.measurementSnapshots(t.Context())
	if err != nil || after.WSS.Performance.SampledBatches != 10 {
		t.Fatalf("unexpected ending snapshot: %+v, error %v", after, err)
	}
	if delta := after.WSS.Performance.Delta(before.WSS.Performance); delta.SampledBatches != 5 {
		t.Fatalf("measurement includes warm-up samples: %+v", delta)
	}
	stop()
	if _, _, err := f.measurementSnapshots(t.Context()); err == nil {
		t.Fatal("snapshot socket still serves after measurement")
	}
}

func TestLoadPeerState_RestrictsEndpoint(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "ready.json")
	for _, tc := range []struct {
		name      string
		transport string
		state     fixtureState
		wantOK    bool
	}{
		{"direct", "direct", fixtureState{Target: "198.18.40.2:8080"}, true},
		{"redirected-direct", "direct", fixtureState{Target: "192.0.2.1:8080"}, false},
		{"control", "wss", fixtureState{Target: "127.0.0.1:8080", Control: "https://198.18.40.2:8443"}, true},
		{"redirected-control", "wss", fixtureState{Target: "127.0.0.1:8080", Control: "https://192.0.2.1:8443"}, false},
		{"wireguard", "native-wireguard-kernel", fixtureState{Target: "127.0.0.1:8080", WireEndpoint: "198.18.40.2:51820", WireTarget: "100.70.0.1:18080"}, true},
		{"redirected-wireguard", "native-wireguard-kernel", fixtureState{Target: "127.0.0.1:8080", WireEndpoint: "192.0.2.1:51820", WireTarget: "100.70.0.1:18080"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.state)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadPeerState(path, tc.transport); (err == nil) != tc.wantOK {
				t.Fatalf("loadPeerState error = %v, want success = %v", err, tc.wantOK)
			}
		})
	}
	t.Run("symlink", func(t *testing.T) {
		link := filepath.Join(directory, "link")
		if err := os.Symlink(path, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if _, err := loadPeerState(link, "wss"); err == nil {
			t.Fatal("accepted symlink fixture state")
		}
	})
}

func TestLinkRecovery_RecordsFirstRestoredEcho(t *testing.T) {
	recovery := &linkRecovery{dir: t.TempDir()}
	if err := recovery.begin(); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	recovery.observe(now, 1)
	if err := os.WriteFile(filepath.Join(recovery.dir, "link-restored"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	recovery.observe(now.Add(1250*time.Millisecond), 2)
	recovery.observe(now.Add(1800*time.Millisecond), 2)
	if result := recovery.report; !result.PreOutageEcho || !result.RestoredEcho || result.ResponseGapMS != 1250 || !result.SocketReplaced {
		t.Fatalf("unexpected recovery report: %+v", result)
	}
}
