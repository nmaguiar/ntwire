package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	adaptiveTunnelProbeInterval = 2 * time.Second
	adaptiveTunnelProbeTimeout  = 650 * time.Millisecond
	adaptiveTunnelProbeBytes    = 16 << 10
)

// Only the authenticated peer's virtual address is eligible. Echo traffic
// uses the installed WireGuard route and the stack's existing ICMP support.
func (n *connectionNetwork) tunnelRTT(ctx context.Context) time.Duration {
	if ctx.Err() != nil || !n.clientIP.IsValid() || !n.serverIP.IsValid() || n.clientIP.Is4() != n.serverIP.Is4() {
		return 0
	}
	var request, response icmp.Type = ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
	family := 1 // ICMPv4
	if n.serverIP.Is6() {
		request, response = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
		family = 58 // ICMPv6
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return 0
	}
	packet, err := (&icmp.Message{Type: request, Body: &icmp.Echo{Data: nonce[:]}}).Marshal(nil)
	if err != nil {
		return 0
	}
	conn, err := n.stack.Net.DialPingAddr(n.clientIP, n.serverIP)
	if err != nil {
		return 0
	}
	defer conn.Close()
	start := time.Now()
	deadline := start.Add(adaptiveTunnelProbeTimeout)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	if err := conn.SetReadDeadline(deadline); err != nil || ctx.Err() != nil {
		return 0
	}
	if written, err := conn.Write(packet); err != nil || written != len(packet) {
		return 0
	}
	var buf [128]byte
	size, from, err := conn.ReadFrom(buf[:])
	if err != nil || ctx.Err() != nil || size != len(packet) || from == nil || from.String() != n.serverIP.String() {
		return 0
	}
	reply, err := icmp.ParseMessage(family, buf[:size])
	if err != nil || reply.Type != response || reply.Code != 0 {
		return 0
	}
	if echo, ok := reply.Body.(*icmp.Echo); ok && bytes.Equal(echo.Data, nonce[:]) {
		return time.Since(start)
	}
	return 0
}
