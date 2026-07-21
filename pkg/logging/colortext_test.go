package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/nmaguiar/ntwire/pkg/ui"
)

func TestColorTextHandlerFallsBackWhenColorDisabled(t *testing.T) {
	var buf bytes.Buffer
	h := NewColorTextHandler(&buf, ui.Capabilities{Color: false}, slog.LevelInfo)
	slog.New(h).Info("hello")
	if strings.Contains(buf.String(), "\x1b[") {
		t.Errorf("expected no ANSI escapes when color is disabled, got %q", buf.String())
	}
}

func TestColorTextHandlerColorsWhenEnabled(t *testing.T) {
	var buf bytes.Buffer
	h := NewColorTextHandler(&buf, ui.Capabilities{Color: true}, slog.LevelInfo)
	slog.New(h).Info("hello", "key", "value")
	out := buf.String()
	if !strings.Contains(out, "\x1b[") {
		t.Errorf("expected ANSI escapes when color is enabled, got %q", out)
	}
	if !strings.Contains(out, "hello") || !strings.Contains(out, "key=") || !strings.Contains(out, "value") {
		t.Errorf("expected message and attr in output, got %q", out)
	}
}

// TestColorTextHandlerConcurrentWrites guards against interleaved/corrupted
// lines: the handler is shared by daemon goroutines (signal handlers,
// watchers, request handlers) logging concurrently, so Handle must format
// each record into a local buffer and serialize the single Write call.
func TestColorTextHandlerConcurrentWrites(t *testing.T) {
	var buf bytes.Buffer
	syncBuf := &syncWriter{w: &buf}
	h := NewColorTextHandler(syncBuf, ui.Capabilities{Color: true}, slog.LevelInfo)
	logger := slog.New(h)

	const goroutines = 20
	const perGoroutine = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				logger.Info("concurrent message", "n", i)
			}
		}()
	}
	wg.Wait()

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != goroutines*perGoroutine {
		t.Fatalf("got %d lines, want %d (interleaved/corrupted write)", len(lines), goroutines*perGoroutine)
	}
	for _, line := range lines {
		if !strings.Contains(line, "concurrent message") || !strings.Contains(line, "\x1b[38;5;145mn=\x1b[0m") {
			t.Fatalf("corrupted line: %q", line)
		}
	}
}

// syncWriter additionally races bytes.Buffer's own internal state under
// -race if two goroutines call Write concurrently without the handler's
// own mutex working correctly, making the test meaningful under `go test
// -race`.
type syncWriter struct{ w *bytes.Buffer }

func (s *syncWriter) Write(p []byte) (int, error) { return s.w.Write(p) }
