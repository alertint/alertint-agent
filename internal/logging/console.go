// SPDX-License-Identifier: FSL-1.1-ALv2

package logging

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
)

// consoleHandler is a slog.Handler that renders each record as one
// human-readable line for live watching:
//
//	HH:MM:SS LEVEL  <message padded to a column> · key1=val1 key2=val2 ...
//
// It is deliberately generic: it renders whatever record it is given and does
// not decide which records matter (curation happens by call-site level
// assignment, not here). Time is HH:MM:SS only; the level label is fixed-width
// and colored; the message is right-padded to a modest column so attrs align;
// attributes render as dimmed ` key=value` in the order supplied, with
// space-containing values quoted and WithGroup keys prefixed `group.key`.
//
// Color is applied only when color is true (the constructor sets this from a
// TTY check plus NO_COLOR); otherwise output is plain uncolored text, so a
// console stream redirected to a file is clean.
type consoleHandler struct {
	mu    *sync.Mutex
	w     io.Writer
	level slog.Leveler
	color bool

	groups []string // open groups, for prefixing keys (group.key=value)
	pre    string   // attrs accumulated via WithAttrs, pre-rendered as " key=value" (no color)
}

// ANSI escape sequences. Used only when color is enabled.
const (
	ansiReset  = "\x1b[0m"
	ansiDim    = "\x1b[2m"
	ansiGray   = "\x1b[90m" // bright black — DEBUG
	ansiYellow = "\x1b[33m" // WARN
	ansiRed    = "\x1b[31m" // ERROR
)

// msgColWidth is the column the message is padded to so attrs line up across
// lines. Messages longer than this simply get a single space before the
// separator (no truncation).
const msgColWidth = 20

func newConsoleHandler(w io.Writer, level slog.Leveler, color bool) *consoleHandler {
	if level == nil {
		level = slog.LevelInfo
	}
	return &consoleHandler{
		mu:    &sync.Mutex{},
		w:     w,
		level: level,
		color: color,
	}
}

func (h *consoleHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

func (h *consoleHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	h2 := *h
	h2.groups = append(append([]string(nil), h.groups...), name)
	return &h2
}

func (h *consoleHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	var b strings.Builder
	prefix := h.groupPrefix()
	for _, a := range attrs {
		appendAttr(&b, prefix, a)
	}
	h2 := *h
	h2.pre = h.pre + b.String()
	return &h2
}

func (h *consoleHandler) Handle(_ context.Context, rec slog.Record) error {
	var line bytes.Buffer

	// Time: HH:MM:SS only.
	t := rec.Time
	if t.IsZero() {
		t = time.Now()
	}
	line.WriteString(t.Format("15:04:05"))
	line.WriteByte(' ')

	// Level: fixed-width (5), colored.
	h.writeLevel(&line, rec.Level)
	line.WriteByte(' ')

	// Attributes: pre-rendered (WithAttrs) plus this record's own, in order.
	var attrs strings.Builder
	attrs.WriteString(h.pre)
	prefix := h.groupPrefix()
	rec.Attrs(func(a slog.Attr) bool {
		appendAttr(&attrs, prefix, a)
		return true
	})

	if attrs.Len() == 0 {
		line.WriteString(rec.Message)
	} else {
		// Pad the message so the separator/attrs align across lines.
		line.WriteString(rec.Message)
		for i := len(rec.Message); i < msgColWidth; i++ {
			line.WriteByte(' ')
		}
		if h.color {
			line.WriteString(ansiDim)
		}
		line.WriteString(" ·")
		line.WriteString(attrs.String())
		if h.color {
			line.WriteString(ansiReset)
		}
	}
	line.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.w.Write(line.Bytes())
	return err
}

func (h *consoleHandler) groupPrefix() string {
	if len(h.groups) == 0 {
		return ""
	}
	return strings.Join(h.groups, ".") + "."
}

func (h *consoleHandler) writeLevel(buf *bytes.Buffer, level slog.Level) {
	label := levelLabel(level)
	if h.color {
		if c := levelColor(level); c != "" {
			buf.WriteString(c)
			buf.WriteString(label)
			buf.WriteString(ansiReset)
		} else {
			buf.WriteString(label)
		}
	} else {
		buf.WriteString(label)
	}
	for i := len(label); i < 5; i++ {
		buf.WriteByte(' ')
	}
}

// appendAttr renders a single attr as " key=value", recursing into groups so a
// KindGroup attr renders its children as " group.key=value". The rendered token
// carries no color; the caller dims the whole attrs section once.
func appendAttr(b *strings.Builder, prefix string, a slog.Attr) {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return // empty attr — slog convention is to drop it
	}
	if a.Value.Kind() == slog.KindGroup {
		group := a.Value.Group()
		if len(group) == 0 {
			return
		}
		np := prefix
		if a.Key != "" {
			np = prefix + a.Key + "."
		}
		for _, ga := range group {
			appendAttr(b, np, ga)
		}
		return
	}
	b.WriteByte(' ')
	b.WriteString(prefix)
	b.WriteString(a.Key)
	b.WriteByte('=')
	b.WriteString(maybeQuote(a.Value.String()))
}

// maybeQuote wraps a value in double quotes when it is empty or contains
// whitespace, so space-separated attrs stay parseable by eye. Values with no
// whitespace (e.g. a LogQL selector `{app="api"}`) are rendered bare even when
// they contain quotes.
func maybeQuote(s string) string {
	if s == "" {
		return `""`
	}
	if strings.ContainsAny(s, " \t\n\r") {
		return strconv.Quote(s)
	}
	return s
}

func levelLabel(l slog.Level) string {
	switch {
	case l < slog.LevelInfo:
		return "DEBUG"
	case l < slog.LevelWarn:
		return "INFO"
	case l < slog.LevelError:
		return "WARN"
	default:
		return "ERROR"
	}
}

func levelColor(l slog.Level) string {
	switch {
	case l < slog.LevelInfo:
		return ansiGray
	case l < slog.LevelWarn:
		return "" // INFO: default terminal color
	case l < slog.LevelError:
		return ansiYellow
	default:
		return ansiRed
	}
}
