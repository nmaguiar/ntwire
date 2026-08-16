// Package manager drives ntwire-gui's server profiles: it owns one
// *client.Connection per connected profile, runs each through the
// idle/connecting/awaitingTrust/awaitingPassphrase/connected/reconnecting/
// failed state machine, and publishes state changes for the tray and
// settings window to render.
package manager

import (
	"github.com/nmaguiar/ntwire/pkg/client"
	"github.com/nmaguiar/ntwire/pkg/protocol"
)

// Handle is the subset of *client.Connection the manager depends on. It
// exists so the state machine can be driven, in tests, against a fake
// instead of a live ntwire-server. Every method here is already exported on
// *client.Connection -- especially State, the single race-free typed snapshot
// the GUI consumes -- so *client.Connection satisfies Handle with no adapter
// needed.
type Handle interface {
	State() client.ConnectionState
	ReplaceListener(name, host string, port int) (string, error)
	DashboardURL() string
	Close()
}

// Connector opens a connection or performs a query-only authentication. The
// real implementation wraps client.ConnectWithOptions/
// AuthenticateWithOptions; tests use a fake that never touches the network.
type Connector interface {
	Connect(server, keyPath string, info protocol.ClientInfo, opts client.Options) (Handle, error)
	Authenticate(server, keyPath string, info protocol.ClientInfo, opts client.Options) (protocol.AuthResponse, error)
}

// realConnector is the production Connector, backed by pkg/client.
type realConnector struct{}

// NewConnector returns the production Connector, backed by pkg/client.
func NewConnector() Connector { return realConnector{} }

func (realConnector) Connect(server, keyPath string, info protocol.ClientInfo, opts client.Options) (Handle, error) {
	return client.ConnectWithOptions(server, keyPath, info, opts)
}

func (realConnector) Authenticate(server, keyPath string, info protocol.ClientInfo, opts client.Options) (protocol.AuthResponse, error) {
	return client.AuthenticateWithOptions(server, keyPath, info, opts)
}
