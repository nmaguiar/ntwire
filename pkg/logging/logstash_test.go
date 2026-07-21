package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestLogstashHandlerShape(t *testing.T) {
	var buf bytes.Buffer
	h := NewLogstashHandler(&buf, slog.LevelInfo)
	logger := slog.New(h)
	logger.Info("ntwire server listening", "https", ":8443")

	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("output is not valid JSON: %v (%s)", err, buf.String())
	}

	if record["@version"] != "1" {
		t.Errorf("@version = %v, want \"1\"", record["@version"])
	}
	if record["level"] != "info" {
		t.Errorf("level = %v, want \"info\" (lowercase)", record["level"])
	}
	if record["message"] != "ntwire server listening" {
		t.Errorf("message = %v", record["message"])
	}
	if _, ok := record["@timestamp"]; !ok {
		t.Errorf("missing @timestamp field")
	}
	if _, ok := record["msg"]; ok {
		t.Errorf("stock slog \"msg\" key should have been renamed to \"message\"")
	}
	if _, ok := record["time"]; ok {
		t.Errorf("stock slog \"time\" key should have been renamed to \"@timestamp\"")
	}
	if record["https"] != ":8443" {
		t.Errorf("https attr = %v, want \":8443\"", record["https"])
	}
}

func TestLogstashHandlerRespectsLevel(t *testing.T) {
	var buf bytes.Buffer
	h := NewLogstashHandler(&buf, slog.LevelWarn)
	logger := slog.New(h)
	logger.Info("should be filtered")
	if buf.Len() != 0 {
		t.Errorf("expected info record to be filtered at warn level, got %q", buf.String())
	}
	logger.Warn("should appear")
	if buf.Len() == 0 {
		t.Errorf("expected warn record to be emitted")
	}
}
