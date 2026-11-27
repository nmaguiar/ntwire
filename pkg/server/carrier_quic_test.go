package server

import (
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

func TestConsumeQUICTicket_IsScopedAndSingleUse(t *testing.T) {
	anchor := newAdaptiveSession()
	other := newAdaptiveSession()
	ticket := &carrierTicket{secret: token(), expires: time.Now().Add(time.Minute)}
	lane := &serverCarrierLane{quicAttach: ticket}
	plane := &adaptiveServerPlane{lanes: map[string]*serverCarrierLane{anchor.LaneID: lane}}
	s := &Server{adaptive: plane}
	secret, valid := protocol.ParseCarrierTicket(ticket.secret)
	if !valid {
		t.Fatal("generated an invalid carrier ticket")
	}
	wrong := secret
	wrong[0] ^= 1
	for _, attempt := range []struct {
		plane *adaptiveServerPlane
		id    string
		key   [32]byte
	}{
		{plane, other.LaneID, secret},
		{plane, anchor.LaneID, wrong},
		{&adaptiveServerPlane{}, anchor.LaneID, secret},
	} {
		if found, _ := s.consumeQUICTicket(attempt.plane, attempt.id, attempt.key); found != nil {
			t.Fatal("ticket accepted on an invalid scope")
		}
	}
	if found, used := s.consumeQUICTicket(plane, anchor.LaneID, secret); found != lane || used != ticket {
		t.Fatal("valid ticket did not resolve its lane")
	}
	if found, _ := s.consumeQUICTicket(plane, anchor.LaneID, secret); found != nil || ticket.secret != "" {
		t.Fatal("consumed ticket remained available")
	}
	lane.quicAttach = &carrierTicket{secret: token(), expires: time.Now().Add(-time.Second)}
	stale, _ := protocol.ParseCarrierTicket(lane.quicAttach.secret)
	if found, _ := s.consumeQUICTicket(plane, anchor.LaneID, stale); found != nil {
		t.Fatal("expired ticket was accepted")
	}
}
