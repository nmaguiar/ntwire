package server

import (
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/nmaguiar/ntwire/pkg/wgnet"
)

type AccelerationConfig struct {
	// Mode selects auto, off or required at startup.
	Mode string `yaml:"mode"`
	// AllowAuto permits Linux kernel setup in auto mode.
	AllowAuto bool `yaml:"allow_auto"`
	// EBPF enables best-effort packet-size counters on the kernel interface.
	EBPF     bool `yaml:"ebpf"`
	override string
}

// OverrideMode applies the command-line mode without editing the YAML value.
func (c *AccelerationConfig) OverrideMode(mode string) error {
	if mode == "" {
		return nil
	}
	var override AccelerationConfig
	if err := override.SetMode(mode); err != nil {
		return err
	}
	c.override = override.Mode
	return nil
}

func (c *AccelerationConfig) SetMode(mode string) error {
	mode = strings.TrimSpace(mode)
	if mode == "" {
		mode = "auto"
	}
	switch mode {
	case "auto", "off", "required":
		c.Mode = mode
		return nil
	default:
		return fmt.Errorf("acceleration.mode must be auto, off, or required, got %q", mode)
	}
}

func (c AccelerationConfig) effective() AccelerationConfig {
	if c.override != "" {
		c.Mode = c.override
	}
	if c.Mode == "" {
		c.Mode = "auto"
	}
	return c
}

type serverStack interface {
	PublicKey() string
	AddPeer(wgnet.Endpoint) error
	UpdateEndpoint(string, string) error
	RemovePeer(string) error
	LastHandshakes() (map[string]time.Time, error)
	LastHandshake(string) (time.Time, bool, error)
	PeerEndpoint(string) (string, bool, error)
	Listen(string, string) (net.Listener, error)
	ListenUDP(string, string) (net.PacketConn, error)
	Close() error
}

type accelerationStatus struct {
	mode, backend, reason string
}

// Linux builds can try the kernel backend. Startup verifies runtime support.
const kernelQualifiedForAuto = runtime.GOOS == "linux"

var errAccelerationCleanup = errors.New("accelerated data plane could not be cleaned up")

func dataPlaneStartupError(startErr, cleanupErr error) error {
	if cleanupErr != nil {
		return errors.Join(startErr, errAccelerationCleanup, cleanupErr)
	}
	return startErr
}

// StartDataPlane selects and starts a backend. Call once before serving clients.
func (s *Server) StartDataPlane() error {
	return s.startSelectedDataPlane(kernelQualifiedForAuto, s.newKernelStack)
}

// StartUserspaceDataPlane starts the portable backend directly. In-process
// fixtures use it to keep benchmark setup independent of host privileges.
// Like StartDataPlane, it must be called once before serving clients.
func (s *Server) StartUserspaceDataPlane() error {
	return s.startDataPlane(func(c wgnet.Config) (serverStack, error) { return wgnet.New(c) })
}

func (s *Server) startSelectedDataPlane(eligibleForAuto bool, newKernel func(wgnet.Config, AccelerationConfig) (serverStack, error)) error {
	config := s.Config.Acceleration.effective()
	if err := config.SetMode(config.Mode); err != nil {
		return err
	}
	status := accelerationStatus{mode: config.Mode, backend: "userspace"}
	switch config.Mode {
	case "off":
		status.reason = "disabled"
	case "auto":
		switch {
		case !config.AllowAuto:
			status.reason = "operator_consent_required"
		case !eligibleForAuto:
			status.reason = "unsupported_platform"
		}
	}
	if status.reason == "" {
		err := s.startDataPlane(func(c wgnet.Config) (serverStack, error) {
			return newKernel(c, config)
		})
		if err == nil {
			status.backend = "kernel"
			s.reportAcceleration(status)
			return nil
		}
		if config.Mode == "required" || errors.Is(err, errAccelerationCleanup) {
			return fmt.Errorf("start accelerated data plane: %w", err)
		}
		status.reason = "kernel_setup_failed"
		s.log.Warn("kernel data plane unavailable", "error", err)
	}
	if err := s.StartUserspaceDataPlane(); err != nil {
		return err
	}
	s.reportAcceleration(status)
	return nil
}

func (s *Server) reportAcceleration(status accelerationStatus) {
	s.acceleration.Store(&status)
	s.log.Info("WireGuard data plane started", "acceleration_mode", status.mode, "backend", status.backend, "reason", status.reason)
}

func (s *Server) writeAccelerationMetrics(w io.Writer) {
	if status := s.acceleration.Load(); status != nil {
		fmt.Fprintf(w, "ntwire_acceleration_info{mode=%q,backend=%q,reason=%q} 1\n", status.mode, status.backend, status.reason)
	}
	s.mu.Lock()
	d, adaptive := s.data, s.adaptive != nil
	s.mu.Unlock()
	if adaptive {
		// The adaptive bind owns pinned endpoint identity and uses wireguard-go.
		fmt.Fprintln(w, `ntwire_acceleration_plane_info{plane="adaptive",backend="userspace"} 1`)
	}
	if d != nil {
		if backend, ok := d.stack.(interface{ writeMetrics(io.Writer) }); ok {
			backend.writeMetrics(w)
		}
	}
}
