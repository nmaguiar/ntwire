package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/nmaguiar/ntwire/pkg/ui"
)

// Config is the "log:" section shape shared by ntwire-server's and
// ntwire-relay's YAML config structs.
type Config struct {
	Format string `yaml:"format"`
	Level  string `yaml:"level"`
}

// Options converts a config-file Config into Options for Resolve.
func (c Config) Options() Options {
	return Options{Format: c.Format, Level: c.Level}
}

// Options holds a log format ("text" or "json") and level ("debug",
// "info", "warn", "error"). An empty field means "unresolved" -- Resolve
// treats it as "this source didn't specify a value," distinct from an
// explicit choice, which lets a --log-format flag with an empty
// zero-value default be told apart from one the user actually passed.
type Options struct {
	Format string
	Level  string
}

// Resolve merges flag, config-file, and env values in precedence order
// flag > config > env > built-in default ("text", "info"), taking the
// first non-empty value per field. Flag wins because it's explicit and
// matches how -config already behaves; config beats env so a mounted
// config file can override a container image's baked-in
// NTWIRE_LOG_FORMAT=json default while `docker run -e` still works
// against the built-in default when no config value is set.
func Resolve(flagOpts, configOpts, envOpts Options) Options {
	return Options{
		Format: firstNonEmpty(flagOpts.Format, configOpts.Format, envOpts.Format, "text"),
		Level:  firstNonEmpty(flagOpts.Level, configOpts.Level, envOpts.Level, "info"),
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// EnvOptions reads "<prefix>_LOG_FORMAT" and "<prefix>_LOG_LEVEL", e.g.
// EnvOptions("NTWIRE") reads NTWIRE_LOG_FORMAT and NTWIRE_LOG_LEVEL.
func EnvOptions(prefix string) Options {
	return Options{
		Format: os.Getenv(prefix + "_LOG_FORMAT"),
		Level:  os.Getenv(prefix + "_LOG_LEVEL"),
	}
}

// ParseLevel maps a level string to a slog.Level, defaulting to Info for
// an empty or unrecognized value.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// NewHandler builds a Logstash JSON handler when opts.Format is "json",
// otherwise a text handler (colorized when caps.Color is true).
func NewHandler(w io.Writer, opts Options, caps ui.Capabilities) slog.Handler {
	level := ParseLevel(opts.Level)
	if strings.EqualFold(opts.Format, "json") {
		return NewLogstashHandler(w, level)
	}
	return NewColorTextHandler(w, caps, level)
}
