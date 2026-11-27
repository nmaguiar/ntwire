package client

import (
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

// WSSPerformance snapshots opt-in queue diagnostics for the current bind.
func (c *Connection) WSSPerformance() wstransport.QueuePerformance {
	c.mu.Lock()
	ws := c.activeWebSocketLocked()
	c.mu.Unlock()
	if ws == nil {
		return wstransport.QueuePerformance{}
	}
	return ws.QueuePerformance()
}

// UDPRelayTraffic snapshots ciphertext counters on the client-facing relay
// leg. A new relay allocation resets the counters.
func (c *Connection) UDPRelayTraffic() protocol.ClientUDPRelayStats {
	c.mu.Lock()
	multipath := c.multipath
	c.mu.Unlock()
	return udpRelayTraffic(multipath)
}

func udpRelayTraffic(multipath *wstransport.MultipathBind) protocol.ClientUDPRelayStats {
	if multipath == nil {
		return protocol.ClientUDPRelayStats{}
	}
	sent, sentPackets, received, receivedPackets := multipath.RelayLegStats()
	return protocol.ClientUDPRelayStats{BytesSent: sent, PacketsSent: sentPackets,
		BytesReceived: received, PacketsReceived: receivedPackets}
}

func (c *Connection) activeWebSocketLocked() *wstransport.Bind {
	if c.network != nil && c.network.adaptive != nil {
		return c.network.adaptive.ws
	}
	if c.hybrid != nil {
		return c.hybrid.WebSocket
	}
	return nil
}
