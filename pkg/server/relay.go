package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
)

// relayListener is a net.Listener whose connections all arrive through a
// RelayAgent's dial-back data connections instead of a normal accept loop.
// It lets cmd/ntwire-server pass an unchanged Handler() to
// http.Server.ServeTLS regardless of whether the server is listening
// directly or relaying.
type relayListener struct {
	ch     chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newRelayListener() *relayListener {
	return &relayListener{ch: make(chan net.Conn), closed: make(chan struct{})}
}

// push delivers c to a pending Accept, or closes c if the listener has
// already been closed.
func (l *relayListener) push(c net.Conn) {
	select {
	case l.ch <- c:
	case <-l.closed:
		_ = c.Close()
	}
}
func (l *relayListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *relayListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}
func (l *relayListener) Addr() net.Addr { return relayAddr{} }

type relayAddr struct{}

func (relayAddr) Network() string { return "relay" }
func (relayAddr) String() string  { return "relay" }

// relayConn substitutes RemoteAddr with the real client address the relay
// reported in RelayOpen. This is the detail that keeps allowSource's
// per-source-IP rate limiting and audit logging correct across a relay hop
// instead of collapsing every relayed client into one bucket keyed by the
// relay itself (see docs/SECURITY.md).
type relayConn struct {
	net.Conn
	remoteAddr net.Addr
}

func (c *relayConn) RemoteAddr() net.Addr { return c.remoteAddr }

type stringAddr string

func (a stringAddr) Network() string { return "tcp" }
func (a stringAddr) String() string  { return string(a) }

// RelayAgent maintains the outbound control connection to an ntwire-relay
// and feeds inbound data connections into a relayListener for
// http.Server.ServeTLS to consume exactly as it would connections from a
// normal net.Listener.
type RelayAgent struct {
	cfg      RelayConfig
	listener *relayListener
	log      *slog.Logger
	client   *http.Client

	mu     sync.Mutex
	closed bool
}

func NewRelayAgent(cfg RelayConfig, log *slog.Logger) (*RelayAgent, error) {
	if log == nil {
		log = slog.Default()
	}
	client, err := relayHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	return &RelayAgent{cfg: cfg, listener: newRelayListener(), log: log, client: client}, nil
}

// Listener returns the net.Listener to pass to http.Server.ServeTLS.
func (a *RelayAgent) Listener() net.Listener { return a.listener }

// Run dials, registers, and maintains the control connection until ctx is
// canceled, reconnecting with exponential backoff between
// cfg.ReconnectMin and cfg.ReconnectMax. A connection that completed
// registration resets the backoff, so a brief outage does not leave the
// server waiting at cfg.ReconnectMax indefinitely.
func (a *RelayAgent) Run(ctx context.Context) {
	delay := a.cfg.ReconnectMin
	for {
		a.log.Debug("relay control connection dialing", "url", a.cfg.URL)
		registered, err := a.runOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			a.log.Warn("relay control connection error; reconnecting", "error", err, "retry_in", delay)
		}
		if registered {
			delay = a.cfg.ReconnectMin
		} else {
			delay = min(delay*2, a.cfg.ReconnectMax)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

func (a *RelayAgent) runOnce(ctx context.Context) (registered bool, err error) {
	controlURL, err := relayEndpointURL(a.cfg.URL, "/v1/relay/control")
	if err != nil {
		return false, err
	}
	ws, _, err := websocket.Dial(ctx, controlURL, &websocket.DialOptions{HTTPClient: a.client})
	if err != nil {
		return false, fmt.Errorf("dial control: %w", err)
	}
	defer ws.Close(websocket.StatusNormalClosure, "")

	req, err := a.registerRequest()
	if err != nil {
		return false, err
	}
	b, err := json.Marshal(req)
	if err != nil {
		return false, err
	}
	if err := ws.Write(ctx, websocket.MessageText, b); err != nil {
		return false, fmt.Errorf("write registration: %w", err)
	}
	_, data, err := ws.Read(ctx)
	if err != nil {
		return false, fmt.Errorf("read registration response: %w", err)
	}
	var resp protocol.RelayRegisterResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return false, fmt.Errorf("unmarshal registration response: %w", err)
	}
	if resp.Error != "" {
		return false, fmt.Errorf("relay registration rejected: %s (%s)", resp.Error, resp.Code)
	}
	a.log.Info("relay registered", "name", resp.Name, "domain", resp.Domain)

	// Mirror the relay's own keepalive (pkg/relay/agent.go): without a ping
	// of our own, a dead path (relay process gone, NAT rebinding) is only
	// ever caught by whatever the OS's default TCP keepalive happens to
	// notice, rather than promptly triggering Run's reconnect.
	var writeMu sync.Mutex
	readErr := make(chan error, 1)
	go func() {
		for {
			_, data, err := ws.Read(ctx)
			if err != nil {
				readErr <- err
				return
			}
			var open protocol.RelayOpen
			if json.Unmarshal(data, &open) != nil {
				continue
			}
			a.log.Debug("relay open received", "conn_id", open.ConnID, "client_addr", open.ClientAddr)
			go a.handleOpen(ctx, open)
		}
	}()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			writeMu.Lock()
			err := ws.Ping(pctx)
			writeMu.Unlock()
			cancel()
			if err != nil {
				return true, fmt.Errorf("ping: %w", err)
			}
		case err := <-readErr:
			return true, err
		case <-ctx.Done():
			return true, ctx.Err()
		}
	}
}

// handleOpen dials the relay's data endpoint for one RelayOpen and pushes
// the resulting connection into the listener that http.Server.ServeTLS is
// Accept-ing from.
func (a *RelayAgent) handleOpen(ctx context.Context, open protocol.RelayOpen) {
	dataURL, err := relayEndpointURL(a.cfg.URL, "/v1/relay/data")
	if err != nil {
		a.log.Warn("relay data endpoint URL invalid", "error", err)
		return
	}
	u, err := url.Parse(dataURL)
	if err != nil {
		a.log.Warn("relay data endpoint URL invalid", "error", err)
		return
	}
	q := u.Query()
	q.Set("conn_id", open.ConnID)
	u.RawQuery = q.Encode()

	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(dctx, u.String(), &websocket.DialOptions{HTTPClient: a.client})
	if err != nil {
		a.log.Warn("relay data dial failed", "error", err)
		return
	}
	conn := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
	a.log.Debug("relay data connection opened", "conn_id", open.ConnID, "client_addr", open.ClientAddr)
	a.listener.push(&relayConn{Conn: conn, remoteAddr: stringAddr(open.ClientAddr)})
}

func (a *RelayAgent) registerRequest() (protocol.RelayRegisterRequest, error) {
	pub, err := sshkey.PublicFromPrivate(a.cfg.IdentityFile)
	if err != nil {
		return protocol.RelayRegisterRequest{}, err
	}
	n := make([]byte, 32)
	if _, err := rand.Read(n); err != nil {
		return protocol.RelayRegisterRequest{}, err
	}
	req := protocol.RelayRegisterRequest{
		Version: protocol.Version, PublicKey: pub, Name: a.cfg.Name,
		Timestamp: time.Now().UTC().Format(time.RFC3339), Nonce: base64.RawURLEncoding.EncodeToString(n),
	}
	payload, err := protocol.RelayRegisterPayload(req)
	if err != nil {
		return protocol.RelayRegisterRequest{}, err
	}
	req.Signature, err = sshkey.SignFile(a.cfg.IdentityFile, payload)
	if err != nil {
		return protocol.RelayRegisterRequest{}, err
	}
	return req, nil
}

// Close shuts down the relay listener; an in-progress or future control
// connection will fail to push further data connections and Run will keep
// retrying until ctx (passed to Run) is itself canceled by the caller.
func (a *RelayAgent) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	return a.listener.Close()
}

// relayHTTPClient builds the HTTP client used for both the control and data
// connections to the relay, pinning its TLS certificate by SHA256
// fingerprint (the identical representation as TLSManager.Fingerprint and
// pkg/client's VerifyConnection hook) when relay.fingerprint is configured,
// or falling back to normal PKI verification when it is empty.
func relayHTTPClient(cfg RelayConfig) (*http.Client, error) {
	if cfg.Fingerprint == "" {
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}, nil
	}
	fp := cfg.Fingerprint
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{ // #nosec G402 -- verification is the pin below
		InsecureSkipVerify: true, MinVersion: tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("relay presented no certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			got := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
			if got != fp {
				return fmt.Errorf("relay certificate fingerprint mismatch: got %s want %s", got, fp)
			}
			return nil
		},
	}}}, nil
}

func relayEndpointURL(base, path string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	return u.String(), nil
}
