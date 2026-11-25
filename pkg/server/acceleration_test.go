package server

import (
	"os"
	"strings"
	"testing"
)

func startTransportFixture(s *Server) error {
	if os.Getenv("NTWIRE_TEST_KERNEL") == "1" {
		s.Config.Acceleration.Mode = "required"
	}
	return s.StartDataPlane()
}

func TestAccelerationConfigAndCLIOverride(t *testing.T) {
	config := SampleConfig()
	for _, mode := range []string{"auto", "off", "required", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			raw := strings.Replace(config, "mode: auto ", "mode: "+mode+" ", 1)
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
			if err := c.Acceleration.OverrideMode("off"); err != nil || c.Acceleration.effective().Mode != "off" {
				t.Fatalf("CLI override failed: %v", err)
			}
		})
	}
}
