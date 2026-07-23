package logging

import (
	"bytes"
	"log/slog"
	"testing"
)

func TestMultiHandlerWritesToEachSink(t *testing.T) {
	var main, audit bytes.Buffer
	h := NewMultiHandler(
		NewLogstashHandler(&main, slog.LevelInfo),
		NewLogstashHandler(&audit, slog.LevelInfo),
	)
	slog.New(h).Info("session revoked", "session_id", "abc123")

	if main.Len() == 0 {
		t.Errorf("expected record in main sink")
	}
	if audit.Len() == 0 {
		t.Errorf("expected record in audit sink")
	}
}

func TestMultiHandlerRespectsPerHandlerLevel(t *testing.T) {
	var main, audit bytes.Buffer
	h := NewMultiHandler(
		NewLogstashHandler(&main, slog.LevelDebug),
		NewLogstashHandler(&audit, slog.LevelWarn),
	)
	slog.New(h).Info("informational, not an audit event")

	if main.Len() == 0 {
		t.Errorf("expected record in main sink at debug level")
	}
	if audit.Len() != 0 {
		t.Errorf("did not expect record in audit sink below its warn level, got %q", audit.String())
	}
}

func TestMultiHandlerWithAttrsAppliesToAllSinks(t *testing.T) {
	var main, audit bytes.Buffer
	h := NewMultiHandler(
		NewLogstashHandler(&main, slog.LevelInfo),
		NewLogstashHandler(&audit, slog.LevelInfo),
	).WithAttrs([]slog.Attr{slog.String("component", "server")})
	slog.New(h).Info("started")

	for name, buf := range map[string]*bytes.Buffer{"main": &main, "audit": &audit} {
		if !bytes.Contains(buf.Bytes(), []byte(`"component":"server"`)) {
			t.Errorf("%s sink missing WithAttrs attribute, got %q", name, buf.String())
		}
	}
}
