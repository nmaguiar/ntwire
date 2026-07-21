package relay

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/nmaguiar/ntwire/pkg/protocol"
)

// dialControl connects to the agent server's control endpoint over the given
// test server, mirroring what pkg/server/relay.go's real control-conn dialer
// will do.
func dialControl(t *testing.T, srv *httptest.Server) *websocket.Conn {
	t.Helper()
	url := "wss" + strings.TrimPrefix(srv.URL, "https") + "/v1/relay/control"
	ws, _, err := websocket.Dial(context.Background(), url, &websocket.DialOptions{HTTPClient: srv.Client()})
	if err != nil {
		t.Fatalf("dial control: %v", err)
	}
	return ws
}

func registerOverControl(t *testing.T, ws *websocket.Conn, req protocol.RelayRegisterRequest) protocol.RelayRegisterResponse {
	t.Helper()
	ctx := context.Background()
	b, _ := json.Marshal(req)
	if err := ws.Write(ctx, websocket.MessageText, b); err != nil {
		t.Fatalf("write registration: %v", err)
	}
	_, data, err := ws.Read(ctx)
	if err != nil {
		t.Fatalf("read registration response: %v", err)
	}
	var resp protocol.RelayRegisterResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("unmarshal registration response: %v", err)
	}
	return resp
}

func TestAgentServer_RegisterSuccess(t *testing.T) {
	k := generateTestKey(t)
	reg := NewRegistry([]Registration{{Name: "home", PublicKey: k.pub}}, testLimits())
	srv := httptest.NewTLSServer(newAgentServer(reg, "relay.example.com").Handler())
	defer srv.Close()

	ws := dialControl(t, srv)
	defer ws.Close(websocket.StatusNormalClosure, "")

	resp := registerOverControl(t, ws, signedRegisterRequest(t, k, "home", "n1"))
	if resp.Error != "" {
		t.Fatalf("registration failed: %s (%s)", resp.Error, resp.Code)
	}
	if resp.Name != "home" || resp.Domain != "relay.example.com" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestAgentServer_RegisterUnknownKeyClosesConnection(t *testing.T) {
	k := generateTestKey(t)
	other := generateTestKey(t)
	reg := NewRegistry([]Registration{{Name: "home", PublicKey: k.pub}}, testLimits())
	srv := httptest.NewTLSServer(newAgentServer(reg, "relay.example.com").Handler())
	defer srv.Close()

	ws := dialControl(t, srv)
	defer ws.Close(websocket.StatusNormalClosure, "")

	resp := registerOverControl(t, ws, signedRegisterRequest(t, other, "home", "n1"))
	if resp.Code != protocol.ErrorUnknownKey {
		t.Fatalf("code = %q, want unknown_key", resp.Code)
	}
}

func TestAgentServer_RegisterBadSignature(t *testing.T) {
	k := generateTestKey(t)
	reg := NewRegistry([]Registration{{Name: "home", PublicKey: k.pub}}, testLimits())
	srv := httptest.NewTLSServer(newAgentServer(reg, "relay.example.com").Handler())
	defer srv.Close()

	ws := dialControl(t, srv)
	defer ws.Close(websocket.StatusNormalClosure, "")

	req := signedRegisterRequest(t, k, "home", "n1")
	req.Signature = req.Signature[:len(req.Signature)-4] + "abcd"
	resp := registerOverControl(t, ws, req)
	if resp.Code != protocol.ErrorBadSignature {
		t.Fatalf("code = %q, want bad_signature", resp.Code)
	}
}

func TestAgentServer_RegisterNameMismatch(t *testing.T) {
	k := generateTestKey(t)
	reg := NewRegistry([]Registration{{Name: "home", PublicKey: k.pub}}, testLimits())
	srv := httptest.NewTLSServer(newAgentServer(reg, "relay.example.com").Handler())
	defer srv.Close()

	ws := dialControl(t, srv)
	defer ws.Close(websocket.StatusNormalClosure, "")

	resp := registerOverControl(t, ws, signedRegisterRequest(t, k, "someone-elses-name", "n1"))
	if resp.Code != protocol.ErrorRelayNameNotAllowed {
		t.Fatalf("code = %q, want relay_name_not_allowed", resp.Code)
	}
}

func TestAgentServer_LastWriterWinsEviction(t *testing.T) {
	k := generateTestKey(t)
	reg := NewRegistry([]Registration{{Name: "home", PublicKey: k.pub}}, testLimits())
	srv := httptest.NewTLSServer(newAgentServer(reg, "relay.example.com").Handler())
	defer srv.Close()

	first := dialControl(t, srv)
	defer first.Close(websocket.StatusNormalClosure, "")
	if resp := registerOverControl(t, first, signedRegisterRequest(t, k, "home", "n1")); resp.Error != "" {
		t.Fatalf("first registration failed: %+v", resp)
	}

	second := dialControl(t, srv)
	defer second.Close(websocket.StatusNormalClosure, "")
	if resp := registerOverControl(t, second, signedRegisterRequest(t, k, "home", "n2")); resp.Error != "" {
		t.Fatalf("second registration failed: %+v", resp)
	}

	// The first control connection must have been closed by the eviction.
	first.SetReadLimit(1 << 10)
	readCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, _, err := first.Read(readCtx); err == nil {
		t.Fatal("expected the evicted first control connection to be closed")
	}
}

func TestAgentServer_DataConnRoundTrip(t *testing.T) {
	k := generateTestKey(t)
	reg := NewRegistry([]Registration{{Name: "home", PublicKey: k.pub}}, testLimits())
	srv := httptest.NewTLSServer(newAgentServer(reg, "relay.example.com").Handler())
	defer srv.Close()

	control := dialControl(t, srv)
	defer control.Close(websocket.StatusNormalClosure, "")
	if resp := registerOverControl(t, control, signedRegisterRequest(t, k, "home", "n1")); resp.Error != "" {
		t.Fatalf("registration failed: %+v", resp)
	}

	openCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := reg.Open(context.Background(), "home", "203.0.113.9:4444", "home.relay.example.com")
		openCh <- c
		errCh <- err
	}()

	// Read the pushed RelayOpen off the control conn, as the real
	// pkg/server/relay.go agent loop would.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, data, err := control.Read(ctx)
	if err != nil {
		t.Fatalf("reading RelayOpen: %v", err)
	}
	var open protocol.RelayOpen
	if err := json.Unmarshal(data, &open); err != nil {
		t.Fatalf("unmarshal RelayOpen: %v", err)
	}
	if open.ClientAddr != "203.0.113.9:4444" || open.SNI != "home.relay.example.com" {
		t.Fatalf("unexpected RelayOpen: %+v", open)
	}

	// Dial the data endpoint with the conn_id, as the server's data-conn
	// dialer would, and confirm bytes flow through to the awaiting Open().
	dataURL := "wss" + strings.TrimPrefix(srv.URL, "https") + "/v1/relay/data?conn_id=" + open.ConnID
	dataWS, _, err := websocket.Dial(context.Background(), dataURL, &websocket.DialOptions{HTTPClient: srv.Client()})
	if err != nil {
		t.Fatalf("dial data: %v", err)
	}
	defer dataWS.Close(websocket.StatusNormalClosure, "")
	dataConn := websocket.NetConn(context.Background(), dataWS, websocket.MessageBinary)
	defer dataConn.Close()

	if err := <-errCh; err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	serverSideConn := <-openCh
	defer serverSideConn.Close()

	payload := []byte("hello through the relay")
	if _, err := dataConn.Write(payload); err != nil {
		t.Fatalf("write to data conn: %v", err)
	}
	buf := make([]byte, len(payload))
	serverSideConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(serverSideConn, buf); err != nil {
		t.Fatalf("read from server side: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("got %q, want %q", buf, payload)
	}
}

func TestAgentServer_DataConnUnknownConnID(t *testing.T) {
	reg := NewRegistry(nil, testLimits())
	srv := httptest.NewTLSServer(newAgentServer(reg, "relay.example.com").Handler())
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/v1/relay/data?conn_id=does-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}
