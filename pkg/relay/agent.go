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
}

func newAgentServer(registry *Registry, domain string) *agentServer {
	return &agentServer{registry: registry, domain: domain}
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
	b, _ := json.Marshal(protocol.RelayRegisterResponse{Version: protocol.Version, Name: name, Domain: a.domain})
	writeMu.Lock()
	err = ws.Write(ctx, websocket.MessageText, b)
	writeMu.Unlock()
	if err != nil {
		return
	}

	var closeOnce sync.Once
	agent := &Agent{Name: name}
	agent.Push = func(open protocol.RelayOpen) error {
		b, err := json.Marshal(open)
		if err != nil {
			return err
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		return ws.Write(context.Background(), websocket.MessageText, b)
	}
	agent.Close = func() {
		closeOnce.Do(func() { ws.Close(websocket.StatusNormalClosure, "replaced") })
	}

	a.registry.RegisterAgent(name, agent)
	defer a.registry.DeregisterAgent(name, agent)

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
	deliver, ok := a.registry.Redeem(connID)
	if !ok {
		http.Error(w, "unknown or expired conn_id", http.StatusNotFound)
		return
	}
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	conn := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
	deliver <- conn
}
