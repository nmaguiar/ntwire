package manager

import (
	"github.com/nmaguiar/ntwire/internal/gui/config"
	"github.com/nmaguiar/ntwire/pkg/client"
)

// State is one point in a profile's connection lifecycle.
//
//	idle -> connecting -> awaitingTrust      (*client.UnknownCertificateError)
//	                   -> awaitingPassphrase (encrypted key, no passphrase yet)
//	                   -> connected -> reconnecting -> connected
//	                   -> failed
//
// awaitingPassphrase precedes connecting (not the reverse) because
// client.Options.KeyPassphrase must be resolved before ConnectWithOptions is
// called: it has to survive into the connection's own background reconnect
// loop, which cannot prompt (see pkg/client's KeyPassphrase doc comment).
type State string

const (
	StateIdle               State = "idle"
	StateConnecting         State = "connecting"
	StateAwaitingTrust      State = "awaiting_trust"
	StateAwaitingPassphrase State = "awaiting_passphrase"
	StateConnected          State = "connected"
	StateReconnecting       State = "reconnecting"
	StateFailed             State = "failed"
)

// PromptKind identifies which interactive decision a Prompt is asking for.
type PromptKind string

const (
	PromptTrust      PromptKind = "trust"
	PromptPassphrase PromptKind = "passphrase"
)

// Prompt is a question the manager cannot answer itself; the settings
// window (or, if none is open, one the manager causes to open) must render
// it and reply via Manager.AnswerTrust or Manager.AnswerPassphrase.
type Prompt struct {
	Kind PromptKind `json:"kind"`

	// Set for PromptTrust, mirroring client.UnknownCertificateError.
	Host        string `json:"host,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	// Previous is set only when the server's pinned fingerprint CHANGED --
	// the dangerous case a caller must render distinctly from a first
	// connection (see client.UnknownCertificateError.Previous).
	Previous string `json:"previous,omitempty"`

	// Set for PromptPassphrase.
	KeyPath string `json:"key_path,omitempty"`
}

// Snapshot is a session's state, safe to read from any goroutine and safe
// to serialize as JSON for the settings API.
type Snapshot struct {
	Profile config.Profile `json:"profile"`
	State   State          `json:"state"`
	Err     string         `json:"error,omitempty"`
	Prompt  *Prompt        `json:"prompt,omitempty"`
	// Connection comes directly from client.Connection.State. It is the GUI's
	// sole connected-state input; it never derives state from client logs or
	// reaches into Connection's mutable fields.
	Connection *client.ConnectionState `json:"connection,omitempty"`
}

// session is one profile's live connection state, owned by exactly one
// goroutine at a time (the one running runConnect), with reads/writes
// elsewhere going through mu. handle is non-nil only in StateConnected and
// StateReconnecting.
type session struct {
	profile config.Profile
	state   State
	err     error
	handle  Handle
	prompt  *Prompt

	trustReply      chan bool
	passphraseReply chan passphraseAnswer

	// cancel is closed by RemoveProfile to unblock a runConnect goroutine
	// that is parked waiting for a prompt answer on a session about to be
	// deleted from the sessions map -- without it, removing a profile while
	// it is StateAwaitingTrust/StateAwaitingPassphrase would leak that
	// goroutine forever, since nothing else could ever find its way back to
	// send on trustReply/passphraseReply.
	cancel chan struct{}
}

type passphraseAnswer struct {
	passphrase string
	cancel     bool
}

func newSession(p config.Profile) *session {
	return &session{profile: p, state: StateIdle, cancel: make(chan struct{})}
}
