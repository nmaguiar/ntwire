package wstransport

import (
	"context"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
)

type HTTP3Datagrams interface {
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
}

// HTTP3Link carries CONNECT-UDP context zero and one complete encrypted
// WireGuard datagram. The dedicated QUIC connection belongs to this lane.
type HTTP3Link struct {
	*quic.Conn
	stream HTTP3Datagrams
	once   sync.Once
	ready  chan struct{}
}

// HTTP3QUICConfig gives HTTP/3 its bounded control and QPACK stream credit.
func HTTP3QUICConfig(server bool) *quic.Config {
	config := QUICConfig(server)
	config.MaxIncomingUniStreams = 3
	config.InitialConnectionReceiveWindow = 32768
	config.MaxConnectionReceiveWindow = 32768
	config.InitialStreamReceiveWindow = 16384
	config.MaxStreamReceiveWindow = 16384
	return config
}

func NewHTTP3Link(c *quic.Conn, stream HTTP3Datagrams) *HTTP3Link {
	return &HTTP3Link{Conn: c, stream: stream, ready: make(chan struct{})}
}

func (l *HTTP3Link) Ready() { close(l.ready) }

func (l *HTTP3Link) Close() error {
	l.once.Do(func() { _ = l.CloseWithError(0, "carrier closed") })
	return nil
}

func (l *HTTP3Link) SendDatagram(p []byte) error {
	select {
	case <-l.ready:
	case <-l.Context().Done():
		return l.Context().Err()
	}
	return l.SendProbe(p)
}

func (l *HTTP3Link) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-l.ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return l.ReceiveProbe(ctx)
}

func (l *HTTP3Link) SendProbe(p []byte) error {
	data := make([]byte, 1+len(p))
	copy(data[1:], p) // Context ID 0, encoded as the shortest QUIC varint.
	return l.stream.SendDatagram(data)
}

func (l *HTTP3Link) ReceiveProbe(ctx context.Context) ([]byte, error) {
	for {
		data, err := l.stream.ReceiveDatagram(ctx)
		if err != nil {
			return nil, err
		}
		if payload, err := parseHTTP3Datagram(data); err == nil {
			return payload, nil
		}
		// Unregistered contexts are dropped without buffering.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
}

func parseHTTP3Datagram(data []byte) ([]byte, error) {
	id, n, err := quicvarint.Parse(data)
	if err != nil || id != 0 || n == len(data) {
		return nil, ErrCarrierDatagram
	}
	return data[n:], nil
}
