// Package egressattach connects processes running under the same OS account.
package egressattach

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nmaguiar/ntwire/internal/localproxy"
	"github.com/nmaguiar/ntwire/internal/privatepath"
	"github.com/nmaguiar/ntwire/pkg/egressrouter"
)

const (
	version    = 1
	frameLimit = 4096
	maxStreams = egressrouter.MaxConnections + 32 // Leave room for discovery and control requests.
)

type record struct {
	Version     int    `json:"version"`
	Address     string `json:"address"`
	Certificate []byte `json:"certificate"`
	Credential  string `json:"credential"`
	Instance    string `json:"instance"`
}
type request struct {
	Enrollment  egressrouter.Enrollment  `json:"enrollment"`
	Version     int                      `json:"version"`
	Credential  string                   `json:"credential"`
	Operation   string                   `json:"operation"`
	Member      egressrouter.Member      `json:"member"`
	Generation  string                   `json:"generation"`
	Destination egressrouter.Destination `json:"destination"`
	Timeout     time.Duration            `json:"timeout"`
}
type response struct {
	Addresses    []netip.Addr              `json:"addresses,omitempty"`
	Timing       *egressrouter.SetupTiming `json:"timing,omitempty"`
	Candidate    egressrouter.Candidate    `json:"candidate"`
	ControlProxy string                    `json:"control_proxy,omitempty"`
	Failure      *egressrouter.Failure     `json:"failure,omitempty"`
}
type Control func(string) (any, error)

func Root() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ntwire", "egress"), nil
}
func ControlID(path string) string {
	sum := sha256.Sum256([]byte(path))
	return "router-" + hex.EncodeToString(sum[:16])
}
func ProfilePath(root, id string) (string, error) {
	if !egressrouter.ValidProfileID(id) {
		return "", errors.New("invalid egress profile ID")
	}
	return filepath.Join(root, "profiles", id), nil
}

type Service struct {
	streams  atomic.Int64
	listener net.Listener
	lock     *os.File
	path     string
	info     record
	cancel   context.CancelFunc
	done     chan struct{}
	once     sync.Once
}

func openPrivateDirectory(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return privatepath.Verify(path, true)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	if err := privatepath.Restrict(path, true); err != nil {
		return err
	}
	return privatepath.Verify(path, true)
}

// Start publishes a new authenticated local instance. A second instance for
// this directory cannot replace the discovery record while the owner is live.
func Start(path string, source egressrouter.Source, control Control) (*Service, error) {
	return StartWithDiscovery(path, source, control, nil)
}

// StartWithDiscovery advertises only grants selected by the authenticated owner.
func StartWithDiscovery(path string, source egressrouter.Source, control Control, discover egressrouter.Discover) (*Service, error) {
	if err := openPrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := openPrivateDirectory(path); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(path, "owner.lock")
	if _, err := os.Lstat(lockPath); err == nil {
		if err := privatepath.Verify(lockPath, false); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = lockFile(lock); err != nil {
		lock.Close()
		return nil, fmt.Errorf("egress attachment is already owned or cannot be locked: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = lock.Close()
		}
	}()
	if err = privatepath.Restrict(lockPath, false); err != nil {
		return nil, err
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer func() {
		if !committed {
			_ = raw.Close()
		}
	}()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var id [32]byte
	rand.Read(id[:])
	var secret [32]byte
	rand.Read(secret[:])
	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(id[:]), NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		return nil, err
	}
	info := record{Version: version, Address: raw.Addr().String(), Certificate: der,
		Credential: hex.EncodeToString(secret[:]), Instance: hex.EncodeToString(id[:])}
	if err = writeRecord(path, info); err != nil {
		return nil, err
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	ctx, cancel := context.WithCancel(context.Background())
	service := &Service{listener: tls.NewListener(raw, tc), lock: lock, path: path, info: info, cancel: cancel, done: make(chan struct{})}
	committed = true
	go service.serve(ctx, source, control, discover)
	return service, nil
}

func writeRecord(path string, info record) error {
	f, err := os.CreateTemp(path, "discovery-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	err = privatepath.Restrict(f.Name(), false)
	if err == nil {
		err = json.NewEncoder(f).Encode(info)
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), filepath.Join(path, "discovery.json"))
}

func (s *Service) Close() {
	s.once.Do(func() {
		s.cancel()
		_ = s.listener.Close()
		<-s.done
		if current, err := readRecord(s.path); err == nil && current.Instance == s.info.Instance {
			_ = os.Remove(filepath.Join(s.path, "discovery.json"))
		}
		_ = s.lock.Close()
	})
}

func (s *Service) serve(ctx context.Context, source egressrouter.Source, control Control, discover egressrouter.Discover) {
	defer close(s.done)
	var wg sync.WaitGroup
	defer wg.Wait()
	slots := make(chan struct{}, maxStreams)
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		select {
		case slots <- struct{}{}:
			wg.Go(func() {
				defer func() { <-slots }()
				defer conn.Close()
				stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
				defer stop()
				s.handle(ctx, conn, source, control, discover)
			})
		default:
			_ = conn.Close()
		}
	}
}

func readFrame(reader *bufio.Reader, value any) error {
	line, err := reader.ReadSlice('\n')
	if err != nil {
		return err
	}
	return json.Unmarshal(line, value)
}
func writeFrame(w net.Conn, value any) error { return json.NewEncoder(w).Encode(value) }

func (s *Service) handle(ctx context.Context, conn net.Conn, source egressrouter.Source, control Control, discover egressrouter.Discover) {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReaderSize(conn, frameLimit)
	var req request
	if readFrame(reader, &req) != nil || req.Version != version ||
		subtle.ConstantTimeCompare([]byte(req.Credential), []byte(s.info.Credential)) != 1 {
		return
	}
	if req.Operation == "status" || req.Operation == "reload" || strings.HasPrefix(req.Operation, "pac:") || strings.HasPrefix(req.Operation, "preference:") {
		if control == nil {
			return
		}
		value, err := control(req.Operation)
		if err != nil {
			_ = writeFrame(conn, map[string]string{"error": err.Error()})
			return
		}
		_ = writeFrame(conn, map[string]any{"result": value})
		return
	}
	if req.Operation == "discover" {
		if discover != nil {
			names := discover(req.Enrollment)
			_ = writeFrame(conn, names[:min(len(names), 64)])
		}
		return
	}
	if source == nil {
		return
	}
	candidate := source(req.Member)
	if req.Operation == "snapshot" {
		_ = writeFrame(conn, response{Candidate: candidate, ControlProxy: candidate.ControlProxy})
		return
	}
	if (req.Operation != "dial" && req.Operation != "udp" && req.Operation != "prepare" && req.Operation != "offer_destination") || req.Timeout <= 0 || req.Timeout > time.Minute {
		return
	}
	if candidate.Dialer == nil || candidate.Generation != req.Generation {
		f := &egressrouter.Failure{Class: "grant_revoked", Code: 2}
		if candidate.Reason == "transport" || candidate.Reason == "expired" {
			f = &egressrouter.Failure{Class: candidate.Reason, Retry: true}
		}
		_ = writeFrame(conn, response{Failure: f})
		return
	}
	if s.streams.Add(1) > egressrouter.MaxConnections {
		s.streams.Add(-1)
		_ = writeFrame(conn, response{Failure: &egressrouter.Failure{Class: "capacity", Retry: true}})
		return
	}
	defer s.streams.Add(-1)
	setup, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()
	deadline, _ := setup.Deadline()
	_ = conn.SetDeadline(deadline)
	if req.Operation == "offer_destination" {
		serveDestinationOffer(ctx, setup, &localproxy.BufferedConn{Conn: conn, Reader: reader}, candidate, req.Destination)
		return
	}
	if req.Operation == "prepare" {
		s.servePreparation(ctx, setup, &localproxy.BufferedConn{Conn: conn, Reader: reader}, candidate)
		return
	}
	if err := egressrouter.CheckNumericDomain(req.Destination, candidate.NumericDomain); err != nil {
		writeFailure(conn, err)
		return
	}
	_ = conn.SetWriteDeadline(deadline.Add(100 * time.Millisecond))
	// Until handoff the consumer may send no bytes. Watch for disconnect so
	// abandoned attempts stop at the owner as well as at the aggregator.
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		if _, err := reader.Peek(1); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return
			}
		}
		cancel()
	}()
	var out net.Conn
	var err error
	if req.Operation == "udp" {
		backend, ok := candidate.Dialer.(egressrouter.UDPEgress)
		if ok && candidate.UDP {
			out, err = backend.AssociateUDP(setup)
		} else {
			err = &egressrouter.Failure{Class: "udp_unavailable", Code: 7}
		}
	} else {
		out, err = candidate.Dialer.DialDestination(setup, req.Destination)
	}
	_ = conn.SetReadDeadline(time.Now())
	<-watchDone
	if err != nil {
		var f *egressrouter.Failure
		if !errors.As(err, &f) {
			f = &egressrouter.Failure{Class: "ambiguous"}
		}
		_ = writeFrame(conn, response{Failure: f})
		return
	}
	defer out.Close()
	stop := context.AfterFunc(ctx, func() { _ = out.Close() })
	defer stop()
	if setup.Err() != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	reply := response{}
	if c, ok := out.(egressrouter.TimedConn); ok {
		timing := c.SetupTiming()
		reply.Timing = &timing
	}
	if writeFrame(conn, reply) != nil {
		return
	}
	in := &localproxy.BufferedConn{Conn: conn, Reader: reader}
	if req.Operation == "udp" {
		relayPackets(out, &framedPackets{Conn: in})
		return
	}
	localproxy.Relay(out, in)
}

// servePreparation keeps the destination outside the initial request. A
// losing racer closes the TLS stream and never sends the continuation.
func (s *Service) servePreparation(ctx, setup context.Context, in *localproxy.BufferedConn, candidate egressrouter.Candidate) {
	backend, ok := candidate.Dialer.(egressrouter.PreparableEgress)
	if !ok || !candidate.Preparation {
		_ = writeFrame(in, response{Failure: &egressrouter.Failure{Class: "preparation_unavailable", Retry: true}})
		return
	}
	prepCtx, cancel := context.WithCancel(setup)
	stopWatch := localproxy.WatchSetupDisconnect(in, cancel)
	prepared, err := backend.Prepare(prepCtx)
	stopWatch()
	cancel()
	deadline, _ := setup.Deadline()
	_ = in.SetDeadline(deadline)
	if err != nil {
		writeFailure(in, err)
		return
	}
	defer prepared.Close()
	if setup.Err() != nil || writeFrame(in, response{}) != nil {
		return
	}
	var destination egressrouter.Destination
	if err = readFrame(in.Reader, &destination); err != nil {
		return
	}
	if err = egressrouter.CheckNumericDomain(destination, candidate.NumericDomain); err != nil {
		writeFailure(in, err)
		return
	}
	dialCtx, cancelDial := context.WithCancel(setup)
	watchDial := localproxy.WatchSetupDisconnect(in, cancelDial)
	out, err := prepared.DialDestination(dialCtx, destination)
	watchDial()
	cancelDial()
	if err != nil {
		writeFailure(in, err)
		return
	}
	defer out.Close()
	stop := context.AfterFunc(ctx, func() { _ = out.Close() })
	defer stop()
	if setup.Err() != nil {
		return
	}
	_ = in.SetDeadline(time.Time{})
	reply := response{}
	if c, ok := out.(egressrouter.TimedConn); ok {
		timing := c.SetupTiming()
		reply.Timing = &timing
	}
	if writeFrame(in, reply) == nil {
		localproxy.Relay(out, in)
	}
}

func writeFailure(conn net.Conn, err error) {
	var failure *egressrouter.Failure
	if !errors.As(err, &failure) {
		failure = &egressrouter.Failure{Class: "ambiguous"}
	}
	_ = writeFrame(conn, response{Failure: failure})
}
