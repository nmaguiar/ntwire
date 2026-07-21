package logging

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/nmaguiar/ntwire/pkg/ui"
)

// NewColorTextHandler renders slog records for a terminal: a dimmed
// timestamp, a level-coded color (debug=muted, info=brand blue,
// warn=amber, error=bold amber), the message, then key=value attrs. When
// caps.Color is false it returns a plain slog.NewTextHandler instead, so
// piped/redirected output matches slog's stock text format exactly.
func NewColorTextHandler(w io.Writer, caps ui.Capabilities, level slog.Leveler) slog.Handler {
	if !caps.Color {
		return slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})
	}
	return &colorTextHandler{
		mu:    &sync.Mutex{},
		w:     w,
		level: level,
		pal:   ui.DefaultPalette(true),
	}
}

// colorTextHandler implements slog.Handler directly (rather than wrapping
// TextHandler's ReplaceAttr, which quotes non-printable bytes and would
// mangle raw ANSI escapes into literal text). It must be safe for
// concurrent use, since ntwire-server/ntwire-relay log from multiple
// goroutines (signal handlers, config watchers, request handlers); each
// record is formatted into a local buffer and the shared writer is
// protected by mu, matching the concurrency guarantee stdlib handlers make.
type colorTextHandler struct {
	mu     *sync.Mutex
	w      io.Writer
	level  slog.Leveler
	pal    ui.Palette
	attrs  []slog.Attr
	groups []string
}

func (h *colorTextHandler) Enabled(_ context.Context, level slog.Level) bool {
	min := slog.LevelInfo
	if h.level != nil {
		min = h.level.Level()
	}
	return level >= min
}

func (h *colorTextHandler) Handle(_ context.Context, r slog.Record) error {
	var buf bytes.Buffer
	ts := r.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	buf.WriteString(h.pal.Muted.Sprint(ts.Format("2006-01-02T15:04:05.000Z07:00")))
	buf.WriteByte(' ')
	buf.WriteString(h.levelStyle(r.Level).Sprint(levelText(r.Level)))
	buf.WriteByte(' ')
	buf.WriteString(r.Message)

	for _, a := range h.attrs {
		writeAttr(&buf, h.pal, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		writeAttr(&buf, h.pal, a)
		return true
	})
	buf.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.w.Write(buf.Bytes())
	return err
}

func (h *colorTextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	n := *h
	n.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &n
}

// WithGroup records the group name but Handle does not prefix attrs with
// it; neither daemon this handler serves currently uses slog groups, so
// flat attrs are the only case that needs to render correctly.
func (h *colorTextHandler) WithGroup(name string) slog.Handler {
	n := *h
	n.groups = append(append([]string{}, h.groups...), name)
	return &n
}

func writeAttr(buf *bytes.Buffer, pal ui.Palette, a slog.Attr) {
	if a.Equal(slog.Attr{}) {
		return
	}
	buf.WriteByte(' ')
	buf.WriteString(pal.Muted.Sprint(a.Key + "="))
	fmt.Fprint(buf, a.Value)
}

func levelText(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "ERROR"
	case l >= slog.LevelWarn:
		return "WARN"
	case l >= slog.LevelInfo:
		return "INFO"
	default:
		return "DEBUG"
	}
}

func (h *colorTextHandler) levelStyle(l slog.Level) ui.Style {
	switch {
	case l >= slog.LevelError:
		return h.pal.Danger
	case l >= slog.LevelWarn:
		return h.pal.Warn
	case l >= slog.LevelInfo:
		return h.pal.Info
	default:
		return h.pal.Muted
	}
}
