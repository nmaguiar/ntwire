package manager

import (
	"sync"

	"github.com/nmaguiar/ntwire/pkg/client"
	"github.com/nmaguiar/ntwire/pkg/protocol"
)

// fakeHandle is a Handle that never touches the network, so the state
// machine can be driven and asserted on synchronously.
type fakeHandle struct {
	mu     sync.Mutex
	closed bool
	state  client.ConnectionState
}

func (h *fakeHandle) State() client.ConnectionState { h.mu.Lock(); defer h.mu.Unlock(); return h.state }
func (h *fakeHandle) ReplaceListener(name, host string, port int) (string, error) {
	return "127.0.0.1:0", nil
}
func (h *fakeHandle) DashboardURL() string { return "http://127.0.0.1:0/?token=fake" }
func (h *fakeHandle) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
}

// fakeConnector is a Connector whose Connect/Authenticate behavior a test
// configures per server URL, so different profiles in the same test can
// take different paths (succeed, fail with an *client.UnknownCertificateError,
// fail outright).
type fakeConnector struct {
	mu    sync.Mutex
	calls int

	// connectFunc, when set, overrides the default (always succeed with a
	// fresh fakeHandle) for every call.
	connectFunc func(server, keyPath string, opts client.Options) (Handle, error)

	// authenticateFunc, when set, overrides the default (always succeed
	// with an empty AuthResponse) for every Authenticate call.
	authenticateFunc func(server, keyPath string, opts client.Options) (protocol.AuthResponse, error)
}

func (f *fakeConnector) Connect(server, keyPath string, info protocol.ClientInfo, opts client.Options) (Handle, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.connectFunc != nil {
		return f.connectFunc(server, keyPath, opts)
	}
	return &fakeHandle{}, nil
}

func (f *fakeConnector) Authenticate(server, keyPath string, info protocol.ClientInfo, opts client.Options) (protocol.AuthResponse, error) {
	if f.authenticateFunc != nil {
		return f.authenticateFunc(server, keyPath, opts)
	}
	return protocol.AuthResponse{}, nil
}

func (f *fakeConnector) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}
