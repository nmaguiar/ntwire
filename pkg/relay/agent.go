package relay

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/nmaguiar/ntwire/pkg/protocol"
)

// agentServer implements the relay's agents-facing HTTP endpoints: the
// long-lived control connection ntwire-servers register on, and the
// on-demand data connections that carry spliced client TLS bytes.
type agentServer struct {
	registry *Registry
	domain   string
	limits   Limits
	log      *slog.Logger

	mu          sync.Mutex
	reflectAddr string
}

// setReflectAddr records the relay's bound UDP reflector address (or ""),
// echoed back to each server as it registers over its control connection.
func (a *agentServer) setReflectAddr(addr string) {
	a.mu.Lock()
	a.reflectAddr = addr
	a.mu.Unlock()
}

func (a *agentServer) getReflectAddr() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.reflectAddr
}

// handoffConn lets handleData keep its hijacked HTTP handler alive until the
// public relay side finishes splicing the connection. Returning immediately
// after websocket.Accept can let net/http clean up request state underneath a
// still-live WebSocket-backed net.Conn.
type handoffConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *handoffConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}

func newAgentServer(registry *Registry, domain string, limits Limits, log *slog.Logger) *agentServer {
	if log == nil {
		log = slog.Default()
	}
	return &agentServer{registry: registry, domain: domain, limits: limits, log: log}
}

func (a *agentServer) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /v1/relay/control", a.handleControl)
	m.HandleFunc("GET /v1/relay/data", a.handleData)
	return m
}

// handleControl upgrades to a WebSocket, expects exactly one
// RelayRegisterRequest as the first message, and — on success — keeps the
// connection open as the tenant's live agent, pushing RelayOpen messages and
// pinging for NAT keepalive until the connection drops.
func (a *agentServer) handleControl(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	// The ping-failure, read-error, and ctx.Done exits below all return
	// without closing ws explicitly, leaking its fd on every agent
	// disconnect and reconnect. CloseNow is a no-op after an explicit Close
	// (registration failure, or agent.Close on eviction/Push failure), so
	// this is safe to defer unconditionally.
	defer ws.CloseNow()
	ctx := r.Context()

	remote := r.RemoteAddr
	_, data, err := ws.Read(ctx)
	if err != nil {
		ws.Close(websocket.StatusPolicyViolation, "expected registration message")
		return
	}
	var req protocol.RelayRegisterRequest
	if json.Unmarshal(data, &req) != nil {
		// Reachable by anyone who can open a TCP connection to listen.agents,
		// authenticated or not -- Debug, not Warn, so an internet-facing
		// relay doesn't fill its logs from arbitrary scanners.
		a.log.Debug("relay registration rejected", "code", "invalid_message", "remote", remote)
		ws.Close(websocket.StatusPolicyViolation, "invalid registration message")
		return
	}
	name, fingerprint, regErr := a.registry.Register(req)
	if regErr != nil {
		// ErrorReplayedNonce and ErrorRelayNameNotAllowed are only reachable
		// with a valid signature over a known key -- an authenticated client
		// misbehaving or misconfigured, worth Warn. Everything else (bad
		// signature, unknown key, clock skew, wrong protocol version) needs
		// no authentication to trigger and gets the same Debug treatment as
		// invalid_message above.
		level := slog.LevelDebug
		if regErr.Code == protocol.ErrorReplayedNonce || regErr.Code == protocol.ErrorRelayNameNotAllowed {
			level = slog.LevelWarn
		}
		a.log.Log(ctx, level, "relay registration rejected", "name", req.Name, "code", regErr.Code, "remote", remote)
		b, _ := json.Marshal(protocol.RelayRegisterResponse{Version: protocol.Version, Error: regErr.Message, Code: regErr.Code})
		_ = ws.Write(ctx, websocket.MessageText, b)
		ws.Close(websocket.StatusPolicyViolation, regErr.Code)
		return
	}

	var writeMu sync.Mutex
	var closeOnce sync.Once
	agent := &Agent{Name: name, Fingerprint: fingerprint}
	agent.Push = func(open protocol.RelayOpen) error {
		b, err := json.Marshal(open)
		if err != nil {
			return err
		}
		// Bound the write so a stalled agent socket cannot block the
		// public-listener goroutine calling Push, nor hold writeMu long
		// enough to starve the keepalive ping below. Released before Close
		// is invoked on failure, since Close itself writes a close frame.
		pctx, cancel := context.WithTimeout(context.Background(), a.limits.DialBackTimeout)
		defer cancel()
		writeMu.Lock()
		err = ws.Write(pctx, websocket.MessageText, b)
		writeMu.Unlock()
		if err != nil {
			agent.Close()
		}
		return err
	}
	agent.Close = func() {
		closeOnce.Do(func() { ws.Close(websocket.StatusNormalClosure, "replaced") })
	}

	a.registry.RegisterAgent(name, agent)
	defer a.registry.DeregisterAgent(name, agent)
	reflectAddr := a.getReflectAddr()
	// reflect_addr records this tenant's wss-vs-direct-UDP posture at
	// registration time: "" means every client of this tenant rides the wss
	// tunnel exclusively; non-empty means the server also has the option to
	// offer clients the opportunistic direct-UDP upgrade (see docs/RELAY.md).
	a.log.Info("server registered", "name", name, "fingerprint", fingerprint, "remote", remote, "reflect_addr", reflectAddr)
	defer a.log.Info("server disconnected", "name", name, "fingerprint", fingerprint)

	b, _ := json.Marshal(protocol.RelayRegisterResponse{Version: protocol.Version, Name: name, Domain: a.domain, ReflectAddr: reflectAddr})
	writeMu.Lock()
	err = ws.Write(ctx, websocket.MessageText, b)
	writeMu.Unlock()
	if err != nil {
		return
	}

	readErr := make(chan error, 1)
	go func() {
		for {
			if _, _, err := ws.Read(ctx); err != nil {
				readErr <- err
				return
			}
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
				return
			}
		case <-readErr:
			return
		case <-ctx.Done():
			return
		}
	}
}

// handleData redeems a conn_id minted by Registry.Open and, on success,
// delivers the newly accepted WebSocket (wrapped as a net.Conn) to the
// public-listener goroutine awaiting it. conn_id is a bearer capability
// handed out only over an already-authenticated control connection, so no
// further authentication happens here.
func (a *agentServer) handleData(w http.ResponseWriter, r *http.Request) {
	connID := r.URL.Query().Get("conn_id")
	if connID == "" {
		a.log.Debug("relay data request missing conn_id", "remote", r.RemoteAddr)
		http.Error(w, "missing conn_id", http.StatusBadRequest)
		return
	}
	handoff, ok := a.registry.Redeem(connID)
	if !ok {
		a.log.Debug("relay data request: unknown or expired conn_id", "conn_id", connID, "remote", r.RemoteAddr)
		http.Error(w, "unknown or expired conn_id", http.StatusNotFound)
		return
	}
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	a.log.Debug("relay data connection established", "conn_id", connID, "remote", r.RemoteAddr)
	conn := &handoffConn{Conn: websocket.NetConn(context.Background(), ws, websocket.MessageBinary), done: make(chan struct{})}

	// Open may have already abandoned this conn_id (dial-back timeout or a
	// canceled context) while the handshake above was in flight. Check
	// first, non-blocking: Deliver's one-slot buffer would otherwise accept
	// the send even with nobody left to ever read and close it, leaking the
	// connection's fd for the life of the process.
	select {
	case <-handoff.Done:
		conn.Close()
		return
	default:
	}
	select {
	case handoff.Deliver <- conn:
	case <-handoff.Done:
		conn.Close()
		return
	}

	// websocket.Accept hijacks the HTTP connection. Keep this handler alive
	// for that connection's lifetime; its peer calls conn.Close when the
	// public splice ends, which releases this goroutine too.
	<-conn.done
}
