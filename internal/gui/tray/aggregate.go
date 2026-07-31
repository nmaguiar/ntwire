package tray

import (
	"github.com/nmaguiar/ntwire/internal/gui/manager"
	"github.com/nmaguiar/ntwire/internal/gui/tray/icons"
)

// aggregateState reduces every profile's session state to the one icon
// state the tray shows. A profile that failed or is blocked on a trust or
// passphrase decision always wins: it needs the user's attention, which
// matters more than how many other profiles happen to be connected.
// StateReconnecting counts as connected -- its tunnels are still expected
// to come back on their own -- so it does not by itself downgrade an
// all-connected icon to "some" or raise "needs attention".
func aggregateState(snaps []manager.Snapshot) icons.State {
	if len(snaps) == 0 {
		return icons.StateNone
	}

	connected, attention := 0, 0
	for _, s := range snaps {
		switch s.State {
		case manager.StateConnected, manager.StateReconnecting:
			connected++
		case manager.StateFailed, manager.StateAwaitingTrust, manager.StateAwaitingPassphrase:
			attention++
		}
	}

	switch {
	case attention > 0:
		return icons.StateError
	case connected == len(snaps):
		return icons.StateAll
	case connected > 0:
		return icons.StateSome
	default:
		return icons.StateNone
	}
}
