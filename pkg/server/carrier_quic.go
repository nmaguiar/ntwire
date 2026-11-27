package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"github.com/quic-go/quic-go"
	"golang.zx2c4.com/wireguard/conn"
)

const quicAttachLimit = 16

type adaptiveQUICServer struct {
	packet    net.PacketConn
	transport *quic.Transport
	listener  *quic.Listener
	bind      *wstransport.QUICBind
}

func (s *Server) startAdaptiveQUIC(bind *wstransport.QUICBind, listen, alpn string) (*adaptiveQUICServer, error) {
	if s.tlsManager == nil {
		return nil, errors.New("QUIC carrier requires the server TLS certificate manager")
	}
	packet, err := net.ListenPacket("udp", listen)
	if err != nil {
		return nil, err
	}
	total := make(chan struct{}, adaptiveLaneLimit+quicAttachLimit)
	transport := &quic.Transport{
		Conn:                packet,
		VerifySourceAddress: func(net.Addr) bool { return true },
		ConnContext: func(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
			select {
			case total <- struct{}{}:
				context.AfterFunc(ctx, func() { <-total })
				return ctx, nil
			default:
				return nil, errors.New("QUIC connection budget exhausted")
			}
		},
	}
	tlsConfig := s.tlsManager.Config()
	tlsConfig.NextProtos = []string{alpn}
	config := wstransport.QUICConfig(true)
	if alpn != protocol.CarrierQUICALPN {
		config = wstransport.HTTP3QUICConfig(true)
	}
	listener, err := transport.Listen(tlsConfig, config)
	if err != nil {
		_ = transport.Close()
		return nil, errors.Join(err, packet.Close())
	}
	return &adaptiveQUICServer{packet: packet, transport: transport, listener: listener, bind: bind}, nil
}

func (q *adaptiveQUICServer) close() error {
	if q == nil {
		return nil
	}
	return errors.Join(q.listener.Close(), q.transport.Close(), q.packet.Close())
}

func (s *Server) adaptiveQUICAdvertisement() string {
	if s.adaptive == nil || s.adaptive.quic == nil {
		return ""
	}
	port := s.adaptive.quic.packet.LocalAddr().(*net.UDPAddr).Port
	return s.adaptiveDatagramAdvertisement(uint16(port))
}

func (s *Server) acceptAdaptiveQUIC(p *adaptiveServerPlane) {
	pending := make(chan struct{}, quicAttachLimit)
	for {
		c, err := p.quic.listener.Accept(context.Background())
		if err != nil {
			return
		}
		select {
		case pending <- struct{}{}:
			go func() {
				defer func() { <-pending }()
				if !s.attachAdaptiveQUIC(p, c) {
					_ = c.CloseWithError(0, "carrier unavailable")
				}
			}()
		default:
			_ = c.CloseWithError(0, "carrier unavailable")
		}
	}
}

func (s *Server) attachAdaptiveQUIC(p *adaptiveServerPlane, c *quic.Conn) bool {
	state := c.ConnectionState()
	if state.Used0RTT || !state.SupportsDatagrams.Local || !state.SupportsDatagrams.Remote {
		return false
	}
	ctx, cancel := context.WithTimeout(c.Context(), 10*time.Second)
	defer cancel()
	stream, err := c.AcceptStream(ctx)
	if err != nil {
		return false
	}
	return s.qualifyAdaptiveQUIC(ctx, p, c, stream)
}

func (s *Server) qualifyAdaptiveQUIC(ctx context.Context, p *adaptiveServerPlane, c *quic.Conn, stream *quic.Stream) bool {
	deadline, _ := ctx.Deadline()
	_ = stream.SetDeadline(deadline)
	hello, err := protocol.ReadCarrierQUICHello(stream)
	if err != nil {
		return false
	}
	id := base64.RawURLEncoding.EncodeToString(hello.Lane[:])
	lane, ticket := s.consumeQUICTicket(p, id, hello.Ticket)
	if lane == nil {
		return false
	}

	maxDatagram := wstransport.MaxWireGuardDatagram(p.mtu)
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return false
	}
	var ready [35]byte
	ready[0] = protocol.CarrierQUICReady
	binary.BigEndian.PutUint16(ready[1:3], uint16(maxDatagram))
	copy(ready[3:], nonce[:])
	if _, err := stream.Write(ready[:]); err != nil {
		return false
	}
	probe, err := c.ReceiveDatagram(ctx)
	if err != nil || !protocol.ValidCarrierQUICProbe(probe, maxDatagram, hello.Nonce) {
		return false
	}
	if err := wstransport.SendQUICProof(ctx, c, protocol.CarrierQUICProbe(maxDatagram, nonce)); err != nil {
		return false
	}
	var confirm [32]byte
	if _, err := io.ReadFull(stream, confirm[:]); err != nil || subtle.ConstantTimeCompare(confirm[:], nonce[:]) != 1 {
		return false
	}
	var trailing [1]byte
	if n, err := stream.Read(trailing[:]); n != 0 || err != io.EOF {
		return false
	}
	result := s.publishAdaptiveQUIC(p, c, id, lane, ticket, maxDatagram)
	if result == 0 {
		return false
	}
	if _, err := stream.Write([]byte{result}); err != nil {
		return false
	}
	// Closing the write side flushes the final control record without
	// releasing the connection's single application stream credit.
	return stream.Close() == nil
}

func (s *Server) consumeQUICTicket(p *adaptiveServerPlane, id string, secret [32]byte) (*serverCarrierLane, *carrierTicket) {
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	if s.adaptive != p {
		return nil, nil
	}
	lane := p.lanes[id]
	if lane == nil || lane.quicAttach == nil {
		return nil, nil
	}
	ticket := lane.quicAttach
	want, valid := protocol.ParseCarrierTicket(ticket.secret)
	if ticket.consumed || !valid || !time.Now().Before(ticket.expires) || subtle.ConstantTimeCompare(want[:], secret[:]) != 1 {
		return nil, nil
	}
	ticket.consumed, ticket.secret = true, ""
	return lane, ticket
}

func (s *Server) publishAdaptiveQUIC(p *adaptiveServerPlane, c *quic.Conn, id string, lane *serverCarrierLane, ticket *carrierTicket, size int) byte {
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	if s.adaptive != p || p.lanes[id] != lane || lane.quicAttach != ticket || !time.Now().Before(ticket.expires) {
		return 0
	}
	parent, valid := s.sessions.Get(ticket.bearer)
	if !valid {
		return 0
	}
	v, valid := parent.carrierView(id)
	if !valid || v.Adaptive.AuthGeneration != ticket.request.Generation || v.Adaptive.QUIC == "" {
		return 0
	}
	if lane.quicConnection != nil && lane.quicConnection.Context().Err() == nil {
		return 0
	}
	primary, epoch, _ := p.bind.LaneState(lane.endpoint)
	if epoch != ticket.request.ExpectedEpoch {
		return 0
	}
	published := make(chan struct{})
	defer close(published)
	endpoint, err := p.quic.bind.Adopt(id, c, size, func(ep conn.Endpoint) {
		<-published
		p.bind.FailPath(lane.endpoint, protocol.CarrierQUIC, ep, protocol.CarrierWSS)
	})
	if err != nil {
		return 0
	}
	if err := p.bind.InstallQualifiedPath(lane.endpoint, epoch, wstransport.QualifiedPath{
		ID: protocol.CarrierQUIC, Carrier: protocol.CarrierQUIC, Endpoint: endpoint,
		SendMax: size, ReceiveMax: size, ValidUntil: v.Expires,
	}); err != nil {
		return 0
	}
	result := protocol.CarrierQUICQualified
	if !v.Adaptive.PathSelect || primary == "" {
		if _, err := p.bind.CommitPath(lane.endpoint, protocol.CarrierQUIC, epoch); err != nil {
			p.bind.FailPath(lane.endpoint, protocol.CarrierQUIC, endpoint, protocol.CarrierWSS)
			return 0
		}
		result = protocol.CarrierQUICCommitted
	}
	ticket.bearer = ""
	lane.quicConnection = c
	return result
}
