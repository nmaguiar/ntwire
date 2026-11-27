package server

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/nmaguiar/ntwire/pkg/wgnet"
)

func startTransportFixture(s *Server) error {
	if os.Getenv("NTWIRE_TEST_KERNEL") == "1" {
		s.Config.Acceleration.Mode = "required"
	}
	return s.StartDataPlane()
}

func TestAccelerationAutoRequiresConsent(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		config       AccelerationConfig
		override     string
	}{
		{name: "omitted", reason: "operator_consent_required"},
		{name: "explicit auto is portable", reason: "operator_consent_required", config: AccelerationConfig{Mode: "auto", EBPF: true}},
		{name: "auto CLI is portable", reason: "operator_consent_required", config: AccelerationConfig{Mode: "required"}, override: "auto"},
		{name: "off overrides opt-in", reason: "disabled", config: AccelerationConfig{Mode: "required", AllowAuto: true}, override: "off"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.config.OverrideMode(tc.override); err != nil {
				t.Fatal(err)
			}
			s := New(Config{Acceleration: tc.config}, nil)
			s.Config.Network.TunnelCIDR = "100.64.0.0/24"
			s.Config.Listen.WireGuard = "127.0.0.1:0"
			t.Cleanup(s.Close)
			if err := s.startSelectedDataPlane(true, func(wgnet.Config, AccelerationConfig) (serverStack, error) {
				t.Fatal("kernel startup should not be attempted")
				return nil, nil
			}); err != nil {
				t.Fatal(err)
			}
			if got := s.acceleration.Load(); got == nil || got.backend != "userspace" || got.reason != tc.reason {
				t.Fatalf("acceleration status = %+v, want userspace with %s", got, tc.reason)
			}
		})
	}
}

func TestAccelerationAutoSkipsKernelOnOtherPlatforms(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux is eligible for kernel setup")
	}
	s := New(Config{Acceleration: AccelerationConfig{AllowAuto: true}}, nil)
	s.Config.Network.TunnelCIDR = "100.64.0.0/24"
	s.Config.Listen.WireGuard = "127.0.0.1:0"
	defer s.Close()
	if err := s.StartDataPlane(); err != nil {
		t.Fatal(err)
	}
	if got := s.acceleration.Load(); got == nil || got.backend != "userspace" || got.reason != "unsupported_platform" {
		t.Fatalf("unexpected acceleration status: %+v", got)
	}
}

type failedActivationStack struct {
	serverStack
	startErr, closeErr error
}

func (s *failedActivationStack) activate() error { return s.startErr }
func (s *failedActivationStack) Close() error {
	return errors.Join(s.serverStack.Close(), s.closeErr)
}

func TestAccelerationAutoFallsBackAfterCleanTeardown(t *testing.T) {
	startErr := errors.New("activate kernel backend")
	for _, tc := range []struct {
		name, mode string
		closeErr   error
	}{
		{name: "clean", mode: "auto"},
		{name: "failed cleanup", mode: "auto", closeErr: errors.New("cleanup failed")},
		{name: "required", mode: "required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := New(Config{Acceleration: AccelerationConfig{Mode: tc.mode, AllowAuto: true}}, nil)
			s.Config.Network.TunnelCIDR = "100.64.0.0/24"
			s.Config.Listen.WireGuard = fmt.Sprintf("127.0.0.1:%d", findFreeUDPPortForTest(t))
			defer s.Close()
			err := s.startSelectedDataPlane(true, func(c wgnet.Config, _ AccelerationConfig) (serverStack, error) {
				stack, err := wgnet.New(c)
				if err != nil {
					t.Fatal(err)
				}
				return &failedActivationStack{stack, startErr, tc.closeErr}, nil
			})
			if tc.closeErr != nil || tc.mode == "required" {
				if !errors.Is(err, startErr) || (tc.closeErr != nil && !errors.Is(err, errAccelerationCleanup)) ||
					s.data != nil || s.acceleration.Load() != nil {
					t.Fatalf("unexpected fallback after startup failure: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("fallback could not reuse the public socket: %v", err)
			}
			if got := s.acceleration.Load(); got == nil || got.backend != "userspace" || got.reason != "kernel_setup_failed" {
				t.Fatalf("unexpected fallback status: %+v", got)
			}
		})
	}
}

func TestDataPlaneStartupErrorPreservesCleanupFailure(t *testing.T) {
	setup, cleanup := errors.New("setup"), errors.New("cleanup")
	if got := dataPlaneStartupError(setup, nil); got != setup {
		t.Fatalf("successful cleanup changed the startup error: %v", got)
	}
	got := dataPlaneStartupError(setup, cleanup)
	for _, want := range []error{setup, cleanup, errAccelerationCleanup} {
		if !errors.Is(got, want) {
			t.Errorf("%v does not preserve %v", got, want)
		}
	}
}

func TestAccelerationChangesRequireRestart(t *testing.T) {
	s := New(Config{}, nil)
	s.Config.Network.TunnelCIDR = "100.64.0.0/24"
	s.Config.Listen.WireGuard = "127.0.0.1:0"
	if err := s.StartDataPlane(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	before := s.data.stack
	next := s.Config
	next.Acceleration = AccelerationConfig{Mode: "required", AllowAuto: true, EBPF: true}
	s.Reload(next)
	if s.data.stack != before || s.Config.Acceleration != (AccelerationConfig{}) {
		t.Fatal("configuration reload changed the running acceleration mode")
	}
}

func TestAccelerationConfigAndCLIOverride(t *testing.T) {
	config := SampleConfig()
	for _, mode := range []string{"auto", "off", "required", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			raw := strings.Replace(config, "mode: auto ", "mode: "+mode+" ", 1)
			raw = strings.Replace(raw, "allow_auto: false", "allow_auto: true", 1)
			c, err := ParseConfig([]byte(raw), t.TempDir())
			if mode == "invalid" {
				if err == nil || !strings.Contains(err.Error(), "acceleration.mode") {
					t.Fatalf("invalid mode error = %v", err)
				}
				return
			}
			if err != nil || c.Acceleration.Mode != mode {
				t.Fatalf("mode = %q, error = %v", c.Acceleration.Mode, err)
			}
			if !c.Acceleration.AllowAuto {
				t.Fatal("YAML consent was not loaded")
			}
			if err := c.Acceleration.OverrideMode("off"); err != nil || c.Acceleration.effective().Mode != "off" {
				t.Fatalf("CLI override failed: %v", err)
			}
		})
	}
}
