package egressattach

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/nmaguiar/ntwire/internal/localproxy"
	"github.com/nmaguiar/ntwire/pkg/egressrouter"
)

func readRecord(path string) (record, error) {
	if err := verifyPrivate(path, true); err != nil {
		return record{}, err
	}
	file := filepath.Join(path, "discovery.json")
	if err := verifyPrivate(file, false); err != nil {
		return record{}, err
	}
	f, err := os.Open(file)
	if err != nil {
		return record{}, err
	}
	defer f.Close()
	var info record
	err = json.NewDecoder(io.LimitReader(f, frameLimit)).Decode(&info)
	addr, parseErr := netip.ParseAddrPort(info.Address)
	if err != nil || parseErr != nil || !addr.Addr().IsLoopback() || info.Version != version ||
		len(info.Credential) != 64 || len(info.Instance) != 64 {
		return record{}, errors.New("invalid egress discovery record")
	}
	return info, nil
}

func (info record) dial(ctx context.Context) (net.Conn, error) {
	cert, err := x509.ParseCertificate(info.Certificate)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	cfg := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 || !bytes.Equal(state.PeerCertificates[0].Raw, info.Certificate) {
				return errors.New("egress attachment identity changed")
			}
			return nil
		}}
	dialer := &tls.Dialer{Config: cfg}
	return dialer.DialContext(ctx, "tcp", info.Address)
}
func (info record) exchange(ctx context.Context, req request) (net.Conn, *bufio.Reader, error) {
	conn, err := info.dial(ctx)
	if err != nil {
		return nil, nil, err
	}
	req.Version, req.Credential = version, info.Credential
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err = writeFrame(conn, req); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return conn, bufio.NewReaderSize(conn, frameLimit), nil
}

type attached struct {
	info       record
	member     egressrouter.Member
	generation string
}

func (a attached) DialDestination(ctx context.Context, dst egressrouter.Destination) (net.Conn, error) {
	return a.open(ctx, "dial", dst)
}
func (a attached) AssociateUDP(ctx context.Context) (net.Conn, error) {
	conn, err := a.open(ctx, "udp", egressrouter.Destination{})
	if err != nil {
		return nil, err
	}
	return &framedPackets{Conn: conn}, nil
}
func (a attached) open(ctx context.Context, operation string, dst egressrouter.Destination) (net.Conn, error) {
	conn, err := a.info.dial(ctx)
	if err != nil {
		var op *net.OpError
		if errors.As(err, &op) && op.Op == "dial" {
			return nil, &egressrouter.Failure{Class: "transport", Retry: true}
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, &egressrouter.Failure{Class: "timeout", Code: 6, Retry: true}
		}
		return nil, &egressrouter.Failure{Class: "attachment_identity"}
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	timeout := 3 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
		timeout = time.Until(deadline)
		timeout -= min(timeout/10, 100*time.Millisecond)
	}
	req := request{Version: version, Credential: a.info.Credential, Operation: operation, Member: a.member, Generation: a.generation, Destination: dst, Timeout: timeout}
	reader := bufio.NewReaderSize(conn, frameLimit)
	var reply response
	if err = writeFrame(conn, req); err == nil {
		err = readFrame(reader, &reply)
	}
	if err != nil || ctx.Err() != nil {
		_ = conn.Close()
		var ne net.Error
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout() {
			return nil, &egressrouter.Failure{Class: "timeout", Code: 6}
		}
		return nil, &egressrouter.Failure{Class: "ambiguous"}
	}
	if reply.Failure != nil {
		_ = conn.Close()
		return nil, reply.Failure
	}
	_ = conn.SetDeadline(time.Time{})
	buffered := &localproxy.BufferedConn{Conn: conn, Reader: reader}
	if reply.Timing != nil {
		return &remoteConn{BufferedConn: buffered, timing: *reply.Timing}, nil
	}
	return buffered, nil
}

type Registry struct {
	enrolled   map[egressrouter.Enrollment][]string
	root       string
	mu         sync.RWMutex
	candidates map[egressrouter.Member]egressrouter.Candidate
}

func NewRegistry(root string) *Registry {
	return &Registry{root: root, candidates: map[egressrouter.Member]egressrouter.Candidate{}}
}
func (r *Registry) Candidate(member egressrouter.Member) egressrouter.Candidate {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if c, ok := r.candidates[member]; ok {
		return c
	}
	return egressrouter.Candidate{Reason: "publisher_unavailable"}
}
func (r *Registry) Discover(enrollment egressrouter.Enrollment) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Clone(r.enrolled[enrollment])
}
func (r *Registry) Refresh(ctx context.Context, members []egressrouter.Member, enroll ...egressrouter.Enrollment) {
	enrolled := make(map[egressrouter.Enrollment][]string, len(enroll))
	members = slices.Clone(members)
	var discoveryWG sync.WaitGroup
	var discoveryMu sync.Mutex
	discoverySlots := make(chan struct{}, 8)
	for _, entry := range enroll {
		if ctx.Err() != nil {
			break
		}
		discoverySlots <- struct{}{}
		discoveryWG.Go(func() {
			defer func() { <-discoverySlots }()
			names := r.fetchDiscovery(ctx, entry)
			discoveryMu.Lock()
			enrolled[entry] = names
			discoveryMu.Unlock()
		})
	}
	discoveryWG.Wait()
	for _, entry := range enroll {
		for _, name := range enrolled[entry] {
			m := entry.Member(name)
			if !slices.Contains(members, m) {
				members = append(members, m)
			}
			if len(members) >= 1088 {
				break
			}
		}
		if len(members) >= 1088 {
			break
		}
	}
	next := make(map[egressrouter.Member]egressrouter.Candidate, len(members))
	var mu sync.Mutex
	var wg sync.WaitGroup
	slots := make(chan struct{}, 8)
	for _, member := range members {
		if ctx.Err() != nil {
			break
		}
		slots <- struct{}{}
		wg.Go(func() {
			defer func() { <-slots }()
			c := r.fetch(ctx, member)
			mu.Lock()
			next[member] = c
			mu.Unlock()
		})
	}
	wg.Wait()
	r.mu.Lock()
	r.candidates = next
	r.enrolled = enrolled
	r.mu.Unlock()
}
func (r *Registry) fetch(ctx context.Context, member egressrouter.Member) egressrouter.Candidate {
	path, err := ProfilePath(r.root, member.ProfileID)
	if err != nil {
		return egressrouter.Candidate{Reason: "invalid_profile"}
	}
	info, err := readRecord(path)
	if err != nil {
		return egressrouter.Candidate{Reason: "publisher_unavailable"}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, reader, err := info.exchange(ctx, request{Operation: "snapshot", Member: member})
	if err != nil {
		return egressrouter.Candidate{Reason: "publisher_unavailable"}
	}
	defer conn.Close()
	var reply response
	if readFrame(reader, &reply) != nil {
		return egressrouter.Candidate{Reason: "publisher_unavailable"}
	}
	c := reply.Candidate
	c.ControlProxy = reply.ControlProxy
	if c.Reason == "" && c.Generation != "" {
		c.Dialer = attached{info: info, member: member, generation: c.Generation}
		c.Generation = info.Instance + "/" + c.Generation
	}
	return c
}

func Call(ctx context.Context, path, operation string) (json.RawMessage, error) {
	info, err := readRecord(path)
	if err != nil {
		return nil, err
	}
	conn, _, err := info.exchange(ctx, request{Operation: operation})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	var reply struct {
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	if err = json.NewDecoder(io.LimitReader(conn, 256<<10)).Decode(&reply); err != nil {
		return nil, err
	}
	if reply.Error != "" {
		return nil, errors.New(reply.Error)
	}
	return reply.Result, nil
}

type remoteConn struct {
	*localproxy.BufferedConn
	timing egressrouter.SetupTiming
}

func (c *remoteConn) SetupTiming() egressrouter.SetupTiming { return c.timing }

func (a attached) Prepare(ctx context.Context) (egressrouter.PreparedEgress, error) {
	conn, err := a.open(ctx, "prepare", egressrouter.Destination{})
	if err != nil {
		return nil, err
	}
	buffered, ok := conn.(*localproxy.BufferedConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("invalid prepared attachment")
	}
	return &preparedAttachment{conn: buffered}, nil
}

type preparedAttachment struct{ conn *localproxy.BufferedConn }

func (p *preparedAttachment) Close() error {
	if p.conn == nil {
		return nil
	}
	return p.conn.Close()
}
func (p *preparedAttachment) DialDestination(ctx context.Context, dst egressrouter.Destination) (net.Conn, error) {
	if p.conn == nil {
		return nil, net.ErrClosed
	}
	conn := p.conn
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	cancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer cancel()
	var reply response
	err := writeFrame(conn, dst)
	if err == nil {
		err = readFrame(conn.Reader, &reply)
	}
	if err != nil || ctx.Err() != nil {
		var timeout net.Error
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout() {
			return nil, &egressrouter.Failure{Class: "timeout", Code: 6}
		}
		return nil, &egressrouter.Failure{Class: "ambiguous"}
	}
	if reply.Failure != nil {
		return nil, reply.Failure
	}
	_ = conn.SetDeadline(time.Time{})
	p.conn = nil
	if reply.Timing == nil {
		return conn, nil
	}
	return &remoteConn{BufferedConn: conn, timing: *reply.Timing}, nil
}

func (r *Registry) fetchDiscovery(ctx context.Context, entry egressrouter.Enrollment) []string {
	path, err := ProfilePath(r.root, entry.ProfileID)
	if err != nil {
		return nil
	}
	info, err := readRecord(path)
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, _, err := info.exchange(ctx, request{Operation: "discover", Enrollment: entry})
	if err != nil {
		return nil
	}
	defer conn.Close()
	var names []string
	if err = json.NewDecoder(io.LimitReader(conn, 32<<10)).Decode(&names); err != nil || len(names) > 64 {
		return nil
	}
	return names
}
