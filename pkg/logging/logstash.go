// Package logging provides slog handlers for ntwire, ntwire-relay, and
// ntwire-server: a Logstash-format JSON handler suitable for fluent-bit,
// and a colorized text handler for interactive terminal use.
package logging

import (
	"io"
	"log/slog"
	"strings"
	"time"
)

// NewLogstashHandler returns a slog.Handler that emits one strict
// Logstash-format JSON object per record: "@timestamp" (RFC3339Nano,
// preserving sub-second precision Logstash/ELK use for ordering),
// "@version": "1", "message", a lowercased "level", plus any structured
// attrs unchanged.
func NewLogstashHandler(w io.Writer, level slog.Leveler) slog.Handler {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level:       level,
		ReplaceAttr: replaceLogstashAttr,
	})
	return h.WithAttrs([]slog.Attr{slog.String("@version", "1")})
}

func replaceLogstashAttr(groups []string, a slog.Attr) slog.Attr {
	if len(groups) > 0 {
		return a
	}
	switch a.Key {
	case slog.TimeKey:
		return slog.String("@timestamp", a.Value.Time().Format(time.RFC3339Nano))
	case slog.MessageKey:
		a.Key = "message"
		return a
	case slog.LevelKey:
		return slog.String("level", strings.ToLower(a.Value.String()))
	}
	return a
}
