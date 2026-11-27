package server

import "github.com/nmaguiar/ntwire/pkg/wstransport"

// WSSPerformance snapshots opt-in queue diagnostics for the current bind.
func (s *Server) WSSPerformance() wstransport.QueuePerformance {
	s.mu.Lock()
	ws := s.performanceWebSocketLocked()
	s.mu.Unlock()
	if ws == nil {
		return wstransport.QueuePerformance{}
	}
	return ws.QueuePerformance()
}

// QUICPerformance snapshots ciphertext counts on the adaptive server bind.
func (s *Server) QUICPerformance() *wstransport.QUICStats {
	s.mu.Lock()
	p := s.adaptive
	s.mu.Unlock()
	if p == nil || p.quic == nil {
		return nil
	}
	stats := p.quic.bind.Stats()
	return &stats
}

// UDPBufferStatus reports the latest readback of the public bind's buffers.
func (s *Server) UDPBufferStatus() []wstransport.UDPBufferStatus {
	if bind := s.performanceUDPBind(); bind != nil {
		return bind.BufferStatus()
	}
	return nil
}

func (s *Server) performanceUDPBind() *wstransport.UDPBind {
	s.mu.Lock()
	data := s.data
	s.mu.Unlock()
	if data == nil || data.ws == nil {
		return nil
	}
	udp, ok := data.ws.UDP.(*wstransport.FilterBind)
	if !ok {
		return nil
	}
	bind, _ := udp.Unwrap().(*wstransport.UDPBind)
	return bind
}

func (s *Server) performanceWebSocketLocked() *wstransport.Bind {
	if s.adaptive != nil {
		return s.adaptive.ws
	}
	if s.data != nil && s.data.ws != nil {
		return s.data.ws.WebSocket
	}
	return nil
}
