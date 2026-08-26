package client

// transportState is the client control boundary's view of the data-plane
// route. It deliberately describes the selected route, rather than the
// underlying sockets: a Hybrid keeps WSS alive while UDP paths are tried, so
// changing state must never imply a reconnect or listener restart.
type transportState uint8

const (
	transportStateStopped transportState = iota
	transportStateDirect
	transportStateDirectViaRelayReflector
	transportStateWSSFallback
	transportStateWSSRelay
	transportStateUDPRelay
)

// transportTransition is an input to nextTransportState. Keeping this small
// and side-effect free makes fallback and recovery policy testable without
// timers, WireGuard sockets, or a relay fixture.
type transportTransition uint8

const (
	transportUDPRelayEstablished transportTransition = iota
	transportDirectEstablished
	transportUDPRelayLost
	transportDirectLost
	transportControlReconnected
	transportShutdown
)

func initialTransportState(useWS bool, udp string) transportState {
	if !useWS {
		return transportStateDirect
	}
	if udp != "" {
		return transportStateWSSFallback
	}
	return transportStateWSSRelay
}

// nextTransportState contains the complete route-transition policy. A
// control-plane reconnect preserves the chosen data-plane route: renewing a
// session must not interrupt active TCP flows. Direct loss steps down to the
// already-warm UDP relay if one exists, otherwise to WSS.
func nextTransportState(current transportState, event transportTransition, relayAvailable bool) transportState {
	switch event {
	case transportShutdown:
		return transportStateStopped
	case transportControlReconnected:
		return current
	case transportUDPRelayEstablished:
		if current == transportStateWSSRelay {
			return transportStateUDPRelay
		}
	case transportDirectEstablished:
		if current == transportStateWSSRelay || current == transportStateUDPRelay {
			return transportStateDirectViaRelayReflector
		}
	case transportUDPRelayLost:
		if current == transportStateUDPRelay {
			return transportStateWSSRelay
		}
	case transportDirectLost:
		if current == transportStateDirect || current == transportStateDirectViaRelayReflector {
			if relayAvailable {
				return transportStateUDPRelay
			}
			return transportStateWSSRelay
		}
	}
	return current
}

func (s transportState) connectionTransport() connectionTransport {
	switch s {
	case transportStateDirect:
		return transportUDPDirect
	case transportStateDirectViaRelayReflector:
		return transportUDPRelayReflector
	case transportStateWSSFallback:
		return transportWSSFallback
	case transportStateWSSRelay:
		return transportWSSRelay
	case transportStateUDPRelay:
		return transportUDPRelay
	default:
		return transportUnknown
	}
}

func transportStateFromConnection(t connectionTransport) transportState {
	switch t {
	case transportUDPDirect:
		return transportStateDirect
	case transportUDPRelayReflector:
		return transportStateDirectViaRelayReflector
	case transportWSSFallback:
		return transportStateWSSFallback
	case transportWSSRelay:
		return transportStateWSSRelay
	case transportUDPRelay:
		return transportStateUDPRelay
	default:
		return transportStateStopped
	}
}

func (c *Connection) preserveTransportOnReconnect() {
	current := transportStateFromConnection(connectionTransport(c.transport.Load()))
	c.transitionTransport(nextTransportState(current, transportControlReconnected, current == transportStateUDPRelay), "control-plane reconnected")
}

func (c *Connection) transitionTransport(next transportState, reason string) {
	c.transitionTransportWithKind(next, reason, false)
}

// transitionTransportCandidate records a change in the upgrade ladder. In a
// multipath session that only means a candidate was established or lost: the
// scheduler may still deliberately keep a different healthy path primary.
// Keeping that distinction in the log prevents a successful relay probe from
// being mistaken for an immediate data-plane switch.
func (c *Connection) transitionTransportCandidate(next transportState, reason string) {
	c.transitionTransportWithKind(next, reason, true)
}

func (c *Connection) transitionTransportWithKind(next transportState, reason string, candidate bool) {
	nextTransport := next.connectionTransport()
	previous := connectionTransport(c.transport.Swap(uint32(nextTransport)))
	if previous == nextTransport || c.log == nil {
		return
	}
	if candidate {
		c.mu.Lock()
		multipath := c.multipath
		c.mu.Unlock()
		if multipath != nil {
			primary, _, _ := multipath.Scheduler().Select()
			c.log.Info("transport candidate state changed", "event", "transport_candidate_transition", "server", c.DisplayName(), "candidate_from", previous.String(), "candidate_to", nextTransport.String(), "primary", multipathDescription(primary), "reason", reason)
			return
		}
	}
	c.log.Info("transport state changed", "event", "transport_transition", "server", c.DisplayName(), "from", previous.String(), "to", nextTransport.String(), "reason", reason)
}
