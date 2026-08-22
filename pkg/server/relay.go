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
	"github.com/nmaguiar/ntwire/pkg/buildinfo"
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

func (c *relayConn) SetReadDeadline(t time.Time) error {
	// net/http uses time.Unix(1, 0) internally while hijacking a connection
	// to abort a possible background read. websocket.NetConn implements a
	// deadline by cancelling its read context permanently, so forwarding that
	// sentinel makes the WebSocket that was just upgraded unusable. There is
	// no background read for a request being upgraded, so it is safe to leave
	// this sentinel unforwarded; normal deadlines still reach the transport.
	if t.Equal(time.Unix(1, 0)) {
		return nil
	}
	return c.Conn.SetReadDeadline(t)
}

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

	// OnReflectAddr, if set, is called with RelayRegisterResponse.ReflectAddr
	// after each successful registration (including re-registration after a
	// reconnect), and with "" if the relay reports none. Set only when the
	// caller wants the opportunistic direct-UDP upgrade (relay.advertise_direct);
	// see EnableDirectUpgrade for why that gate matters.
	OnReflectAddr func(addr string)
	// OnUDPRelayAddr, if set, is called with
	// RelayRegisterResponse.UDPRelayAddr after each successful registration,
	// and with "" if the relay reports none. Unlike OnReflectAddr this is
	// wired unconditionally by cmd/ntwire-server: the UDP-relay tier never
	// reveals the server's real address, so it carries no advertise_direct-
	// style trust step-change to opt into. See pkg/server/udprelay.go.
	OnUDPRelayAddr func(addr string)
	// OnRegistration/OnDisconnected expose control-plane membership to
	// RelayPool. They must not block; both run from the agent's Run goroutine.
	OnRegistration func(protocol.RelayRegisterResponse)
	OnDisconnected func()

	mu     sync.Mutex
	closed bool

	// wsMu guards ws (the live control connection, nil while disconnected)
	// and serializes every write to it -- registration, the keepalive ping,
	// and now AllocateUDPSession/ReleaseUDPSession calls originating from
	// concurrent /v1/udp-relay HTTP handler goroutines, not just runOnce's
	// own loop.
	wsMu sync.Mutex
	ws   *websocket.Conn

	pendingMu     sync.Mutex
	pendingAllocs map[string]chan protocol.RelayUDPAllocateResponse
}

func NewRelayAgent(cfg RelayConfig, log *slog.Logger) (*RelayAgent, error) {
	return newRelayAgent(cfg, log, nil)
}

// newRelayAgent optionally attaches an agent to a shared listener. RelayPool
// uses this so several independent relays feed the one http.Server instance.
func newRelayAgent(cfg RelayConfig, log *slog.Logger, listener *relayListener) (*RelayAgent, error) {
	if log == nil {
		log = slog.Default()
	}
	client, err := relayHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	if listener == nil {
		listener = newRelayListener()
	}
	return &RelayAgent{cfg: cfg, listener: listener, log: log, client: client, pendingAllocs: map[string]chan protocol.RelayUDPAllocateResponse{}}, nil
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
	if resp.Version != protocol.Version {
		return false, fmt.Errorf("relay uses unsupported protocol version %d", resp.Version)
	}
	if err := protocol.ValidateRequiredCapabilities([]string{protocol.CapabilityMultipathV1}, resp.RequiredCapabilities); err != nil {
		return false, fmt.Errorf("relay requires an unsupported capability: %w", err)
	}
	a.log.Info("relay registered", "name", resp.Name, "domain", resp.Domain)
	if a.OnReflectAddr != nil {
		a.OnReflectAddr(resp.ReflectAddr)
	}
	if a.OnUDPRelayAddr != nil {
		a.OnUDPRelayAddr(resp.UDPRelayAddr)
	}

	// Publish ws for AllocateUDPSession/ReleaseUDPSession to use, and clear
	// it (and fail anything still waiting on a reply) on the way out --
	// those calls can originate from concurrent /v1/udp-relay HTTP handler
	// goroutines with no other way to know a reconnect is in progress.
	a.wsMu.Lock()
	a.ws = ws
	a.wsMu.Unlock()
	// Publish only after ws is available: a RelayPool callback can enable the
	// UDP-relay tier immediately, and its first allocation must not observe a
	// transient nil control connection.
	if a.OnRegistration != nil {
		a.OnRegistration(resp)
	}
	defer func() {
		a.wsMu.Lock()
		a.ws = nil
		a.wsMu.Unlock()
		a.failPendingAllocs()
		if a.OnDisconnected != nil {
			a.OnDisconnected()
		}
	}()

	// Mirror the relay's own keepalive (pkg/relay/agent.go): without a ping
	// of our own, a dead path (relay process gone, NAT rebinding) is only
	// ever caught by whatever the OS's default TCP keepalive happens to
	// notice, rather than promptly triggering Run's reconnect.
	readErr := make(chan error, 1)
	go func() {
		for {
			_, data, err := ws.Read(ctx)
			if err != nil {
				readErr <- err
				return
			}
			a.handleControlMessage(ctx, data)
		}
	}()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			a.wsMu.Lock()
			err := ws.Ping(pctx)
			a.wsMu.Unlock()
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

// handleControlMessage dispatches one message read from the relay's control
// connection. A typed "udp_allocate_reply" is delivered to the matching
// AllocateUDPSession call; anything else is dispatched as an untyped
// RelayOpen push, exactly as before this feature existed -- RelayOpen
// carries no "type" field by design, see docs/PROTOCOL.md.
func (a *RelayAgent) handleControlMessage(ctx context.Context, data []byte) {
	var msg struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(data, &msg) == nil && msg.Type == "udp_allocate_reply" {
		var resp protocol.RelayUDPAllocateResponse
		if json.Unmarshal(data, &resp) != nil {
			return
		}
		a.pendingMu.Lock()
		ch := a.pendingAllocs[resp.RequestID]
		delete(a.pendingAllocs, resp.RequestID)
		a.pendingMu.Unlock()
		if ch != nil {
			ch <- resp
		}
		return
	}
	var open protocol.RelayOpen
	if json.Unmarshal(data, &open) != nil {
		return
	}
	a.log.Debug("relay open received", "conn_id", open.ConnID, "client_addr", open.ClientAddr)
	go a.handleOpen(ctx, open)
}

// failPendingAllocs unblocks every AllocateUDPSession call still waiting on
// a reply when the control connection drops, so a reconnect in progress
// doesn't leave an HTTP handler goroutine hanging until its own timeout. A
// closed channel delivers a zero-value RelayUDPAllocateResponse to the
// waiting call, which -- empty Token, empty ServerAddr, empty Error --
// AllocateUDPSession reports the same way it would report the tier being
// simply unavailable, not a hard error.
func (a *RelayAgent) failPendingAllocs() {
	a.pendingMu.Lock()
	pending := a.pendingAllocs
	a.pendingAllocs = map[string]chan protocol.RelayUDPAllocateResponse{}
	a.pendingMu.Unlock()
	for _, ch := range pending {
		close(ch)
	}
}

// AllocateUDPSession requests a new UDP-relay session from the relay over
// the live control connection, blocking until the relay replies or ctx is
// canceled. An empty token/serverAddr with a nil error means the tier is
// unavailable right now (no live control connection, the relay declined, or
// the connection dropped mid-request) -- the caller (the server's
// /v1/udp-relay HTTP handler, via udpRelay.sessionFor) treats that exactly
// like PunchResponse's empty case, not a hard failure.
func (a *RelayAgent) AllocateUDPSession(ctx context.Context) (token, serverAddr string, err error) {
	a.wsMu.Lock()
	ws := a.ws
	a.wsMu.Unlock()
	if ws == nil {
		return "", "", nil
	}

	reqID, err := randomRequestID()
	if err != nil {
		return "", "", err
	}
	ch := make(chan protocol.RelayUDPAllocateResponse, 1)
	a.pendingMu.Lock()
	a.pendingAllocs[reqID] = ch
	a.pendingMu.Unlock()
	defer func() {
		a.pendingMu.Lock()
		delete(a.pendingAllocs, reqID)
		a.pendingMu.Unlock()
	}()

	b, err := json.Marshal(protocol.RelayUDPAllocateRequest{Type: "udp_allocate", RequestID: reqID})
	if err != nil {
		return "", "", err
	}
	a.wsMu.Lock()
	writeErr := ws.Write(ctx, websocket.MessageText, b)
	a.wsMu.Unlock()
	if writeErr != nil {
		return "", "", nil
	}

	select {
	case resp, ok := <-ch:
		if !ok || resp.Error != "" {
			return "", "", nil
		}
		return resp.Token, resp.ServerAddr, nil
	case <-ctx.Done():
		return "", "", ctx.Err()
	}
}

// ReleaseUDPSession sends a best-effort, fire-and-forget hint that a
// UDP-relay session is done. If there is no live control connection, this is
// a silent no-op: the relay's own idle timeout is the backstop.
func (a *RelayAgent) ReleaseUDPSession(token string) {
	a.wsMu.Lock()
	ws := a.ws
	a.wsMu.Unlock()
	if ws == nil {
		return
	}
	b, err := json.Marshal(protocol.RelayUDPRelease{Type: "udp_release", Token: token})
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a.wsMu.Lock()
	_ = ws.Write(ctx, websocket.MessageText, b)
	a.wsMu.Unlock()
}

func randomRequestID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
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

	// A WebSocket keeps using the context supplied to its HTTP upgrade after
	// Dial returns. A short-lived dial context would therefore tear down this
	// long-lived data connection as soon as handleOpen returned, breaking the
	// WebSocket WireGuard transport used by relayed clients.
	ws, _, err := websocket.Dial(context.Background(), u.String(), &websocket.DialOptions{HTTPClient: a.client})
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
		ServerVersion: buildinfo.String(), Capabilities: []string{protocol.CapabilityMultipathV1, protocol.CapabilityNativeWireGuardRelay},
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
