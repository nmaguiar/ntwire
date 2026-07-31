package tray

import (
	"testing"

	"github.com/nmaguiar/ntwire/internal/gui/config"
	"github.com/nmaguiar/ntwire/internal/gui/manager"
	"github.com/nmaguiar/ntwire/internal/gui/tray/icons"
)

func snap(state manager.State) manager.Snapshot {
	return manager.Snapshot{Profile: config.Profile{ID: "x"}, State: state}
}

func TestAggregateState(t *testing.T) {
	cases := []struct {
		name  string
		snaps []manager.Snapshot
		want  icons.State
	}{
		{"no profiles", nil, icons.StateNone},
		{"all idle", []manager.Snapshot{snap(manager.StateIdle), snap(manager.StateIdle)}, icons.StateNone},
		{"all connected", []manager.Snapshot{snap(manager.StateConnected), snap(manager.StateConnected)}, icons.StateAll},
		{"one connected one idle", []manager.Snapshot{snap(manager.StateConnected), snap(manager.StateIdle)}, icons.StateSome},
		{"reconnecting counts as connected", []manager.Snapshot{snap(manager.StateConnected), snap(manager.StateReconnecting)}, icons.StateAll},
		{"failed wins over connected", []manager.Snapshot{snap(manager.StateConnected), snap(manager.StateFailed)}, icons.StateError},
		{"awaiting trust wins over all connected", []manager.Snapshot{snap(manager.StateConnected), snap(manager.StateAwaitingTrust)}, icons.StateError},
		{"awaiting passphrase alone", []manager.Snapshot{snap(manager.StateAwaitingPassphrase)}, icons.StateError},
		{"single connecting only", []manager.Snapshot{snap(manager.StateConnecting)}, icons.StateNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := aggregateState(tc.snaps); got != tc.want {
				t.Errorf("aggregateState(%v) = %s, want %s", tc.snaps, got, tc.want)
			}
		})
	}
}
