package relay

import (
	"context"
	"encoding/json"
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
}

func newAgentServer(registry *Registry, domain string, limits Limits) *agentServer {
	return &agentServer{registry: registry, domain: domain, limits: limits}
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
	ctx := r.Context()

	_, data, err := ws.Read(ctx)
	if err != nil {
		ws.Close(websocket.StatusPolicyViolation, "expected registration message")
		return
	}
	var req protocol.RelayRegisterRequest
	if json.Unmarshal(data, &req) != nil {
		ws.Close(websocket.StatusPolicyViolation, "invalid registration message")
		return
	}
	name, regErr := a.registry.Register(req)
	if regErr != nil {
		b, _ := json.Marshal(protocol.RelayRegisterResponse{Version: protocol.Version, Error: regErr.Message, Code: regErr.Code})
		_ = ws.Write(ctx, websocket.MessageText, b)
		ws.Close(websocket.StatusPolicyViolation, regErr.Code)
		return
	}

	var writeMu sync.Mutex
	var closeOnce sync.Once
	agent := &Agent{Name: name}
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

	b, _ := json.Marshal(protocol.RelayRegisterResponse{Version: protocol.Version, Name: name, Domain: a.domain})
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
		http.Error(w, "missing conn_id", http.StatusBadRequest)
		return
	}
	handoff, ok := a.registry.Redeem(connID)
	if !ok {
		http.Error(w, "unknown or expired conn_id", http.StatusNotFound)
		return
	}
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	conn := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)

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
	}
}
