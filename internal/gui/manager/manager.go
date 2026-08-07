package manager

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/nmaguiar/ntwire/internal/gui/config"
	"github.com/nmaguiar/ntwire/pkg/client"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
)

// promptTimeout bounds how long a connect attempt waits for a trust or
// passphrase prompt to be answered before failing the attempt. It is a
// package variable, not a constant, so tests can shorten it rather than
// waiting for the real duration.
var promptTimeout = 5 * time.Minute

// Update is published to every subscriber whenever a session's state
// changes.
type Update struct {
	ProfileID string
	Snapshot  Snapshot
}

// Manager owns every profile's connection lifecycle: it holds one session
// per profile, drives each through connect/reconnect/disconnect, enforces
// that no two connected profiles claim the same explicit local port, and
// fans out state changes to subscribers (the tray, the settings window's
// SSE stream). All exported methods are safe for concurrent use.
type Manager struct {
	connector  Connector
	configPath string

	mu       sync.Mutex
	settings config.Settings
	sessions map[string]*session
	// reservations holds each profile's explicitly-configured local
	// listener addresses ("host:port"), keyed by profile ID then tunnel
	// name. It starts as what was requested (reservePorts, before
	// authenticating) and is corrected to what was actually bound once
	// known (reconcileAllPortReservations/reconcilePortReservation), since
	// the per-tunnel loopback fallback in pkg/client's listenLocal can
	// silently move a listener off its requested address.
	reservations map[string]map[string]string

	subMu   sync.Mutex
	subs    map[int]chan Update
	nextSub int
}

// New loads gui.yaml from configPath (config.DefaultPath() when empty),
// importing a profile from the CLI's config.yaml on first run, and returns
// a Manager ready to connect profiles. cliConfigPath is passed through to
// config.ImportFromCLI; pass "" for the CLI's default location
// (~/.ntwire/config.yaml).
func New(connector Connector, configPath, cliConfigPath string) (*Manager, error) {
	if configPath == "" {
		configPath = config.DefaultPath()
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("gui: loading %s: %w", configPath, err)
	}

	// ImportFromCLI is a documented no-op whenever cfg already has profiles
	// or was already marked imported (see its doc comment); in every other
	// case it always mutates cfg (setting ImportedCLIConfig, and possibly
	// adding a profile), so capture "was it already a no-op" up front
	// rather than trust ImportFromCLI's return value, which reports "was a
	// profile added", not "was cfg changed".
	alreadyImported := cfg.Settings.ImportedCLIConfig || len(cfg.Profiles) > 0
	if _, err := config.ImportFromCLI(&cfg, cliConfigPath); err != nil {
		return nil, fmt.Errorf("gui: importing CLI config: %w", err)
	}
	if !alreadyImported {
		if err := config.Save(configPath, cfg); err != nil {
			return nil, fmt.Errorf("gui: saving %s: %w", configPath, err)
		}
	}

	m := &Manager{
		connector:    connector,
		configPath:   configPath,
		settings:     cfg.Settings,
		sessions:     map[string]*session{},
		reservations: map[string]map[string]string{},
		subs:         map[int]chan Update{},
	}
	for _, p := range cfg.Profiles {
		m.sessions[p.ID] = newSession(p)
	}
	return m, nil
}

// Close disconnects every connected profile. It does not remove profiles
// from gui.yaml.
func (m *Manager) Close() {
	m.mu.Lock()
	ids := make([]string, 0, len(m.sessions))
	for id, s := range m.sessions {
		if s.handle != nil {
			ids = append(ids, id)
		}
	}
	m.mu.Unlock()
	for _, id := range ids {
		_ = m.Disconnect(id)
	}
}

// Settings returns ntwire-gui's app-wide preferences.
func (m *Manager) Settings() config.Settings {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.settings
}

// SetSettings replaces ntwire-gui's app-wide preferences and persists them.
func (m *Manager) SetSettings(s config.Settings) error {
	m.mu.Lock()
	m.settings = s
	m.mu.Unlock()
	return m.persist()
}

// Profiles returns every profile, sorted by name.
func (m *Manager) Profiles() []config.Profile {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.profilesLocked()
}

func (m *Manager) profilesLocked() []config.Profile {
	out := make([]config.Profile, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s.profile)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// AddProfile saves a new profile, assigning it an ID if p.ID is empty.
func (m *Manager) AddProfile(p config.Profile) (config.Profile, error) {
	if p.ID == "" {
		p.ID = config.NewID()
	}
	m.mu.Lock()
	if _, exists := m.sessions[p.ID]; exists {
		m.mu.Unlock()
		return config.Profile{}, fmt.Errorf("gui: profile %q already exists", p.ID)
	}
	m.sessions[p.ID] = newSession(p)
	m.mu.Unlock()
	if err := m.persist(); err != nil {
		return config.Profile{}, err
	}
	return p, nil
}

// UpdateProfile replaces an existing profile's settings. It does not affect
// an in-progress or established connection; reconnect to pick up changes.
func (m *Manager) UpdateProfile(p config.Profile) error {
	m.mu.Lock()
	s, ok := m.sessions[p.ID]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("gui: no such profile %q", p.ID)
	}
	s.profile = p
	m.mu.Unlock()
	return m.persist()
}

// RemoveProfile deletes a profile. It refuses while the profile is
// connected -- disconnect first -- so a removal can never orphan a running
// *client.Connection. A profile that is mid-connect (including one parked
// awaiting a trust or passphrase prompt) can be removed; closing s.cancel
// unblocks its runConnect goroutine, which then exits without touching the
// now-deleted session.
func (m *Manager) RemoveProfile(id string) error {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("gui: no such profile %q", id)
	}
	if s.handle != nil {
		m.mu.Unlock()
		return fmt.Errorf("gui: profile %q is connected; disconnect first", id)
	}
	delete(m.sessions, id)
	close(s.cancel)
	m.mu.Unlock()
	return m.persist()
}

func (m *Manager) persist() error {
	m.mu.Lock()
	cfg := config.Config{Version: config.CurrentVersion, Settings: m.settings, Profiles: m.profilesLocked()}
	m.mu.Unlock()
	return config.Save(m.configPath, cfg)
}

// Snapshot returns one profile's current state.
func (m *Manager) Snapshot(id string) (Snapshot, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return Snapshot{}, false
	}
	return snapshotOf(s), true
}

// Snapshots returns every profile's current state, sorted by name.
func (m *Manager) Snapshots() []Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Snapshot, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, snapshotOf(s))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Profile.Name < out[j].Profile.Name })
	return out
}

func snapshotOf(s *session) Snapshot {
	snap := Snapshot{Profile: s.profile, State: s.state, Prompt: s.prompt}
	if s.err != nil {
		snap.Err = s.err.Error()
	}
	if s.handle != nil {
		st := s.handle.Status()
		snap.Status = &st
	}
	return snap
}

// Connect starts connecting a profile in the background. It returns once
// the attempt has started, not once it completes -- follow Subscribe or
// poll Snapshot for the outcome.
func (m *Manager) Connect(id string) error {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("gui: no such profile %q", id)
	}
	if s.state != StateIdle && s.state != StateFailed {
		st := s.state
		m.mu.Unlock()
		return fmt.Errorf("gui: profile %q is already %s", id, st)
	}
	s.state = StateConnecting
	s.err = nil
	s.prompt = nil
	profile := s.profile
	m.mu.Unlock()
	m.publish(id)

	go m.runConnect(id, profile)
	return nil
}

// Disconnect closes a connected profile's connection.
func (m *Manager) Disconnect(id string) error {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("gui: no such profile %q", id)
	}
	handle := s.handle
	m.mu.Unlock()
	if handle == nil {
		return fmt.Errorf("gui: profile %q is not connected", id)
	}
	handle.Close()
	m.mu.Lock()
	if s := m.sessions[id]; s != nil {
		s.state = StateIdle
		s.handle = nil
		s.err = nil
	}
	m.mu.Unlock()
	m.releasePorts(id)
	m.publish(id)
	return nil
}

// AnswerTrust answers a pending PromptTrust for id, raised when the
// server's certificate is unpinned or its pin changed. trust=true trusts
// and pins it (client.TrustServer) and retries the connection; trust=false
// fails the connection attempt.
func (m *Manager) AnswerTrust(id string, trust bool) error {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if !ok || s.state != StateAwaitingTrust || s.trustReply == nil {
		m.mu.Unlock()
		return fmt.Errorf("gui: profile %q is not awaiting a trust decision", id)
	}
	reply := s.trustReply
	m.mu.Unlock()
	select {
	case reply <- trust:
	default:
	}
	return nil
}

// AnswerPassphrase answers a pending PromptPassphrase for id. cancel=true
// abandons the connection attempt instead of supplying a passphrase.
func (m *Manager) AnswerPassphrase(id, passphrase string, cancel bool) error {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if !ok || s.state != StateAwaitingPassphrase || s.passphraseReply == nil {
		m.mu.Unlock()
		return fmt.Errorf("gui: profile %q is not awaiting a passphrase", id)
	}
	reply := s.passphraseReply
	m.mu.Unlock()
	select {
	case reply <- passphraseAnswer{passphrase: passphrase, cancel: cancel}:
	default:
	}
	return nil
}

// ReplaceListener changes a connected profile's local listener for one
// tunnel, as `ntwire port` does against a CLI session's local status UI --
// except this calls the already-exported client.Connection.ReplaceListener
// directly, with no HTTP round trip needed. An empty host keeps the
// tunnel's currently bound host unchanged.
func (m *Manager) ReplaceListener(id, tunnelName, host string, port int) (string, error) {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if !ok || s.handle == nil {
		m.mu.Unlock()
		return "", fmt.Errorf("gui: profile %q is not connected", id)
	}
	handle := s.handle
	m.mu.Unlock()
	addr, err := handle.ReplaceListener(tunnelName, host, port)
	if err == nil {
		m.reconcilePortReservation(id, tunnelName, addr)
		m.publish(id)
	}
	return addr, err
}

// DashboardURL returns a connected profile's local status UI address, for
// a tray "Open dashboard…" action -- ToClientOptions always sets NoWebUI,
// so the GUI never auto-opens it itself, but the loopback server behind it
// still runs (see Connection.DashboardURL's doc comment) and this is the
// only way to find its URL.
func (m *Manager) DashboardURL(id string) (string, error) {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if !ok || s.handle == nil {
		m.mu.Unlock()
		return "", fmt.Errorf("gui: profile %q is not connected", id)
	}
	handle := s.handle
	m.mu.Unlock()
	return handle.DashboardURL(), nil
}

// Probe previews the tunnels a profile is allowed, without establishing a
// tunnel session -- the GUI equivalent of `ntwire list`. Because
// client.Options.QueryOnly is set, this never occupies a
// max_sessions_per_key slot, so it is safe to call repeatedly (e.g. while a
// user edits a profile's port-mapping form).
//
// It does not prompt for an encrypted key's passphrase; a profile whose
// identity key needs one must be connected at least once (which does
// prompt) before Probe can succeed for it.
func (m *Manager) Probe(id string) ([]protocol.Tunnel, error) {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if !ok {
		m.mu.Unlock()
		return nil, fmt.Errorf("gui: no such profile %q", id)
	}
	p := s.profile
	m.mu.Unlock()

	keyPath := p.IdentityFilePath()
	if keyPath == "" && !p.SSO {
		keyPath = client.DefaultIdentityFile()
	}
	opts, err := p.ToClientOptions(config.StatusFilePath(p.ID), "")
	if err != nil {
		return nil, err
	}
	opts.QueryOnly = true
	resp, err := m.connector.Authenticate(p.Server, keyPath, client.BuiltinInfo(), opts)
	if err != nil {
		return nil, err
	}
	return resp.Tunnels, nil
}

// GenerateIdentity creates a new SSH identity at path, the GUI equivalent
// of `ntwire keygen`. It returns the key's fingerprint and its OpenSSH
// public key line.
func (m *Manager) GenerateIdentity(path string) (fingerprint, publicKey string, err error) {
	fingerprint, err = client.GenerateIdentity(path)
	if err != nil {
		return "", "", err
	}
	pub, err := os.ReadFile(path + ".pub")
	if err != nil {
		return fingerprint, "", err
	}
	return fingerprint, string(pub), nil
}

// Logout clears a profile's cached SSO tokens, the GUI equivalent of
// `ntwire logout`, so its next SSO login reopens the browser (or device
// flow) instead of silently refreshing.
func (m *Manager) Logout(id string) error {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("gui: no such profile %q", id)
	}
	p := s.profile
	m.mu.Unlock()
	return client.Logout(config.ExpandHome(p.TokenCacheFile), p.Server)
}

// Subscribe registers for state-change notifications. The returned channel
// is buffered and best-effort: a subscriber that falls behind misses
// intermediate updates rather than stalling the manager (in particular,
// rather than stalling a connection's own background renewal goroutine,
// which publishes updates through Options.OnEvent). Call the returned
// function to unsubscribe.
func (m *Manager) Subscribe() (<-chan Update, func()) {
	ch := make(chan Update, 16)
	m.subMu.Lock()
	id := m.nextSub
	m.nextSub++
	m.subs[id] = ch
	m.subMu.Unlock()
	return ch, func() {
		m.subMu.Lock()
		delete(m.subs, id)
		m.subMu.Unlock()
	}
}

func (m *Manager) publish(id string) {
	snap, ok := m.Snapshot(id)
	if !ok {
		return
	}
	u := Update{ProfileID: id, Snapshot: snap}
	m.subMu.Lock()
	defer m.subMu.Unlock()
	for _, ch := range m.subs {
		select {
		case ch <- u:
		default:
		}
	}
}

// reservePorts refuses to hand out a profile's explicit local ports when
// another connected profile already holds a conflicting address, and
// otherwise claims them. Checking before authenticating means a collision
// never wastes a max_sessions_per_key slot.
//
// The address reserved per tunnel is the best guess available before
// authenticating: an explicit per-tunnel hosts[name], else the profile's
// BindAddress, else 127.0.0.1 -- the eventual default when neither is set
// and the server offers no local_host, or the fallback address when it
// does but the client can't bind it. A server-supplied local_host is
// unknown at this point, so a profile relying on one for its only
// collision avoidance is not guarded here; reconcileAllPortReservations
// corrects the guess once the real address is known.
func (m *Manager) reservePorts(id string, ports map[string]int, hosts map[string]string, bindAddress string) error {
	requested := make(map[string]string, len(ports))
	for name, port := range ports {
		host := hosts[name]
		if host == "" {
			host = bindAddress
		}
		if host == "" {
			host = "127.0.0.1"
		}
		requested[name] = net.JoinHostPort(host, fmt.Sprint(port))
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, addr := range requested {
		for otherID, res := range m.reservations {
			if otherID == id {
				continue
			}
			for otherName, otherAddr := range res {
				if addressesConflict(addr, otherAddr) {
					ownerName := otherID
					if s, ok := m.sessions[otherID]; ok {
						ownerName = s.profile.Name
					}
					return fmt.Errorf("gui: local address %s (tunnel %q) conflicts with tunnel %q already used by profile %q", addr, name, otherName, ownerName)
				}
			}
		}
	}
	m.reservations[id] = requested
	return nil
}

func (m *Manager) releasePorts(id string) {
	m.mu.Lock()
	delete(m.reservations, id)
	m.mu.Unlock()
}

// reconcileAllPortReservations records every one of id's tunnels at the
// address it actually bound, once a connect attempt finishes -- not just
// the ones already tracked from an explicit client-side Ports entry. This
// also catches a tunnel with no explicit override at all: one profile
// relying purely on a server-suggested local_host/local_port can still
// fall back (e.g. on macOS, without a lo0 alias) to an address a second
// profile's own guess collides with, and only a real post-connect address
// on both sides makes that collision visible to reservePorts. See the
// Manager.reservations doc comment.
func (m *Manager) reconcileAllPortReservations(id string, status client.WebStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	res, ok := m.reservations[id]
	if !ok {
		return
	}
	for _, t := range status.Tunnels {
		res[t.Name] = t.LocalAddress
	}
}

// reconcilePortReservation is reconcileAllPortReservations for a single
// tunnel, used after a runtime ReplaceListener rebinds it.
func (m *Manager) reconcilePortReservation(id, tunnelName, actualAddr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if res, ok := m.reservations[id]; ok {
		if _, tracked := res[tunnelName]; tracked {
			res[tunnelName] = actualAddr
		}
	}
}

// addressesConflict reports whether two "host:port" addresses would
// collide if both were bound: same port, and either the same host or one
// of them is a wildcard (0.0.0.0 or ::), which claims every host on that
// port.
func addressesConflict(a, b string) bool {
	ah, ap, aerr := net.SplitHostPort(a)
	bh, bp, berr := net.SplitHostPort(b)
	if aerr != nil || berr != nil || ap != bp {
		return false
	}
	if ah == bh {
		return true
	}
	aip, aerr2 := netip.ParseAddr(ah)
	bip, berr2 := netip.ParseAddr(bh)
	return (aerr2 == nil && aip.IsUnspecified()) || (berr2 == nil && bip.IsUnspecified())
}

func (m *Manager) setFailed(id string, err error) {
	m.releasePorts(id)
	m.mu.Lock()
	if s := m.sessions[id]; s != nil {
		s.state = StateFailed
		s.err = err
		s.prompt = nil
		s.handle = nil
		s.trustReply = nil
		s.passphraseReply = nil
	}
	m.mu.Unlock()
	m.publish(id)
}

// runConnect drives one profile from StateConnecting through to
// StateConnected or StateFailed, prompting for a passphrase or a trust
// decision along the way when needed. It owns id's session for its
// duration: nothing else transitions a session out of StateConnecting,
// StateAwaitingPassphrase or StateAwaitingTrust.
func (m *Manager) runConnect(id string, p config.Profile) {
	keyPath := p.IdentityFilePath()
	if keyPath == "" && !p.SSO {
		keyPath = client.DefaultIdentityFile()
	}

	passphrase, ok := m.resolvePassphrase(id, keyPath)
	if !ok {
		return // setFailed or cancellation already handled
	}

	opts, err := p.ToClientOptions(config.StatusFilePath(p.ID), passphrase)
	if err != nil {
		m.setFailed(id, err)
		return
	}
	opts.OnEvent = func(e client.Event) { m.handleEvent(id, e) }

	if err := m.reservePorts(id, p.Ports, p.Hosts, p.BindAddress); err != nil {
		m.setFailed(id, err)
		return
	}

	info := client.BuiltinInfo()
	handle, err := m.connector.Connect(p.Server, keyPath, info, opts)
	var unknown *client.UnknownCertificateError
	if errors.As(err, &unknown) {
		m.releasePorts(id)
		if !m.resolveTrust(id, unknown) {
			return
		}
		if err := client.TrustServer(p.KnownServersFile, unknown.Host, unknown.Fingerprint); err != nil {
			m.setFailed(id, err)
			return
		}
		if err := m.reservePorts(id, p.Ports, p.Hosts, p.BindAddress); err != nil {
			m.setFailed(id, err)
			return
		}
		handle, err = m.connector.Connect(p.Server, keyPath, info, opts)
	}
	if err != nil {
		m.releasePorts(id)
		m.setFailed(id, err)
		return
	}

	m.mu.Lock()
	s := m.sessions[id]
	if s == nil {
		m.mu.Unlock()
		handle.Close()
		m.releasePorts(id)
		return
	}
	s.state = StateConnected
	s.err = nil
	s.prompt = nil
	s.handle = handle
	m.mu.Unlock()
	// A tunnel's real bound address can differ from what was requested (the
	// per-tunnel loopback fallback in pkg/client's listenLocal is exactly
	// for that), so the provisional reservation above is corrected to the
	// truth now that it's known -- otherwise a later profile's reservePorts
	// check compares against a request that never actually came true.
	m.reconcileAllPortReservations(id, handle.Status())
	m.publish(id)
}

// resolvePassphrase returns (passphrase, true) once ready to connect --
// immediately with an empty passphrase for an unencrypted or absent key,
// after a prompt round-trip for an encrypted one. It returns (_, false)
// after already resolving the session to StateFailed, on cancellation,
// timeout, or a disappeared session.
func (m *Manager) resolvePassphrase(id, keyPath string) (string, bool) {
	if keyPath == "" {
		return "", true
	}
	needs, err := sshkey.NeedsPassphrase(keyPath)
	if err != nil || !needs {
		return "", true
	}

	reply := make(chan passphraseAnswer, 1)
	m.mu.Lock()
	s := m.sessions[id]
	if s == nil {
		m.mu.Unlock()
		return "", false
	}
	s.state = StateAwaitingPassphrase
	s.prompt = &Prompt{Kind: PromptPassphrase, KeyPath: keyPath}
	s.passphraseReply = reply
	cancel := s.cancel
	m.mu.Unlock()
	m.publish(id)

	var ans passphraseAnswer
	select {
	case ans = <-reply:
	case <-cancel:
		// The session was removed while awaiting an answer; it is already
		// gone from m.sessions, so setFailed's nil-session guard makes this
		// a safe no-op rather than resurrecting a deleted profile.
		m.setFailed(id, errors.New("profile was removed while awaiting a passphrase"))
		return "", false
	case <-time.After(promptTimeout):
		m.setFailed(id, errors.New("timed out waiting for a passphrase"))
		return "", false
	}
	if ans.cancel {
		m.setFailed(id, errors.New("passphrase entry canceled"))
		return "", false
	}

	m.mu.Lock()
	if s := m.sessions[id]; s != nil {
		s.state = StateConnecting
		s.prompt = nil
		s.passphraseReply = nil
	}
	m.mu.Unlock()
	m.publish(id)
	return ans.passphrase, true
}

// resolveTrust prompts for a TOFU decision on an *client.UnknownCertificateError
// and reports whether the caller should retry the connection. On refusal,
// timeout, or a disappeared session it resolves the session to StateFailed
// itself and returns false.
func (m *Manager) resolveTrust(id string, unknown *client.UnknownCertificateError) bool {
	reply := make(chan bool, 1)
	m.mu.Lock()
	s := m.sessions[id]
	if s == nil {
		m.mu.Unlock()
		return false
	}
	s.state = StateAwaitingTrust
	s.prompt = &Prompt{Kind: PromptTrust, Host: unknown.Host, Fingerprint: unknown.Fingerprint, Previous: unknown.Previous}
	s.trustReply = reply
	cancel := s.cancel
	m.mu.Unlock()
	m.publish(id)

	var trust bool
	select {
	case trust = <-reply:
	case <-cancel:
		m.setFailed(id, errors.New("profile was removed while awaiting a trust decision"))
		return false
	case <-time.After(promptTimeout):
		m.setFailed(id, errors.New("timed out waiting for a trust decision"))
		return false
	}
	if !trust {
		m.setFailed(id, errors.New("server certificate was not trusted"))
		return false
	}

	m.mu.Lock()
	if s := m.sessions[id]; s != nil {
		s.state = StateConnecting
		s.prompt = nil
		s.trustReply = nil
	}
	m.mu.Unlock()
	m.publish(id)
	return true
}

// handleEvent is Options.OnEvent for every connection this manager owns. It
// runs on the connection's own background renewal goroutine, so per that
// contract it must not block and must not call back into the Connection --
// it only ever touches this session's own fields under m.mu and does a
// best-effort publish.
// handleEvent gates on state, not on s.handle being set: client.
// ConnectWithOptions starts the connection's renewal goroutine -- and so can
// start firing OnEvent -- before it returns, which is before runConnect
// stores the resulting handle on the session. Gating on s.handle == nil
// would silently drop an event that arrives in that window (observable as a
// connection that starts failing immediately, whose first
// EventReconnecting never reaches the session). Checking state instead
// accepts the event throughout StateConnecting/StateConnected/
// StateReconnecting and correctly ignores a stray event that arrives after
// Disconnect has already reset the session to StateIdle -- m.mu serializes
// the two regardless of which happens first.
func (m *Manager) handleEvent(id string, e client.Event) {
	m.mu.Lock()
	s := m.sessions[id]
	if s == nil {
		m.mu.Unlock()
		return
	}
	switch s.state {
	case StateConnecting, StateConnected, StateReconnecting:
	default:
		m.mu.Unlock()
		return
	}
	switch e.Kind {
	case client.EventReconnecting, client.EventReconnectFailed:
		s.state = StateReconnecting
		s.err = e.Err
	case client.EventReconnected, client.EventRenewed:
		s.state = StateConnected
		s.err = nil
	}
	m.mu.Unlock()
	m.publish(id)
}
