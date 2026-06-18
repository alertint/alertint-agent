// SPDX-License-Identifier: FSL-1.1-ALv2

package logging

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"
)

// fixedTime is used so golden lines are deterministic.
var fixedTime = time.Date(2026, 6, 18, 15, 4, 5, 0, time.UTC)

// renderConsole builds a console logger over buf with color forced on/off and
// returns it. Time is not controllable through slog's public API, so tests that
// assert the full line use newConsoleHandler + a hand-built record instead.
func renderRecord(t *testing.T, color bool, level slog.Level, msg string, build func(r *slog.Record), with func(h slog.Handler) slog.Handler) string {
	t.Helper()
	var buf bytes.Buffer
	var h slog.Handler = newConsoleHandler(&buf, slog.LevelDebug, color)
	if with != nil {
		h = with(h)
	}
	rec := slog.NewRecord(fixedTime, level, msg, 0)
	if build != nil {
		build(&rec)
	}
	if err := h.Handle(nil, rec); err != nil { //nolint:staticcheck // nil ctx is fine for this handler
		t.Fatalf("Handle: %v", err)
	}
	return buf.String()
}

func TestConsole_FullLineShape(t *testing.T) {
	got := renderRecord(t, false, slog.LevelInfo, "webhook listening", func(r *slog.Record) {
		r.AddAttrs(slog.String("addr", "0.0.0.0:9911"), slog.String("path", "/webhook/alertmanager"))
	}, nil)
	want := "15:04:05 INFO  webhook listening    · addr=0.0.0.0:9911 path=/webhook/alertmanager\n"
	if got != want {
		t.Errorf("line shape mismatch:\n got=%q\nwant=%q", got, want)
	}
}

func TestConsole_NoAttrsNoSeparator(t *testing.T) {
	got := renderRecord(t, false, slog.LevelInfo, "alertint starting", nil, nil)
	want := "15:04:05 INFO  alertint starting\n"
	if got != want {
		t.Errorf("no-attr line mismatch:\n got=%q\nwant=%q", got, want)
	}
}

func TestConsole_LevelLabelsAndColors(t *testing.T) {
	cases := []struct {
		level    slog.Level
		label    string
		colorSeq string // "" means INFO (no color)
	}{
		{slog.LevelDebug, "DEBUG", ansiGray},
		{slog.LevelInfo, "INFO", ""},
		{slog.LevelWarn, "WARN", ansiYellow},
		{slog.LevelError, "ERROR", ansiRed},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			// Plain: label present, fixed-width padded, no ANSI.
			plain := renderRecord(t, false, tc.level, "m", nil, nil)
			if !strings.Contains(plain, " "+tc.label) {
				t.Errorf("plain output missing label %q: %q", tc.label, plain)
			}
			if strings.Contains(plain, "\x1b[") {
				t.Errorf("plain output must contain no ANSI: %q", plain)
			}
			// Fixed-width: label padded to 5 chars before the message.
			if !strings.Contains(plain, tc.label+strings.Repeat(" ", 5-len(tc.label))+" m") {
				t.Errorf("label not fixed-width padded to 5: %q", plain)
			}

			// Colored: WARN/ERROR/DEBUG carry their sequence; INFO does not.
			colored := renderRecord(t, true, tc.level, "m", nil, nil)
			if tc.colorSeq == "" {
				if strings.Contains(colored, ansiGray) || strings.Contains(colored, ansiYellow) || strings.Contains(colored, ansiRed) {
					t.Errorf("INFO must not carry a level color: %q", colored)
				}
			} else if !strings.Contains(colored, tc.colorSeq+tc.label+ansiReset) {
				t.Errorf("level %s missing color sequence: %q", tc.label, colored)
			}
		})
	}
}

func TestConsole_AttrSpaceQuoting(t *testing.T) {
	got := renderRecord(t, false, slog.LevelError, "llm failed", func(r *slog.Record) {
		r.AddAttrs(slog.String("err", "context deadline exceeded"))
	}, nil)
	if !strings.Contains(got, `err="context deadline exceeded"`) {
		t.Errorf("space-containing value should be quoted: %q", got)
	}
}

func TestConsole_AttrWithQuotesButNoSpaceIsBare(t *testing.T) {
	// A LogQL selector contains quotes but no spaces — it must render bare so
	// the value reads naturally.
	got := renderRecord(t, false, slog.LevelInfo, "loki fetched", func(r *slog.Record) {
		r.AddAttrs(slog.String("selector", `{app="api",env="prod"}`))
	}, nil)
	if !strings.Contains(got, `selector={app="api",env="prod"}`) {
		t.Errorf("quote-but-no-space value should be bare: %q", got)
	}
}

func TestConsole_AttrOrderPreserved(t *testing.T) {
	got := renderRecord(t, false, slog.LevelInfo, "m", func(r *slog.Record) {
		r.AddAttrs(
			slog.String("z", "1"),
			slog.String("a", "2"),
			slog.String("m", "3"),
		)
	}, nil)
	zi := strings.Index(got, "z=1")
	ai := strings.Index(got, "a=2")
	mi := strings.Index(got, "m=3")
	if zi >= ai || ai >= mi {
		t.Errorf("attrs not in supplied order: %q", got)
	}
}

func TestConsole_WithGroupPrefixesKeys(t *testing.T) {
	got := renderRecord(t, false, slog.LevelInfo, "m", func(r *slog.Record) {
		r.AddAttrs(slog.String("key", "value"))
	}, func(h slog.Handler) slog.Handler {
		return h.WithGroup("grp")
	})
	if !strings.Contains(got, "grp.key=value") {
		t.Errorf("WithGroup should prefix keys: %q", got)
	}
}

func TestConsole_InlineGroupAttrPrefixesKeys(t *testing.T) {
	got := renderRecord(t, false, slog.LevelInfo, "m", func(r *slog.Record) {
		r.AddAttrs(slog.Group("req", slog.String("method", "POST"), slog.Int("size", 12)))
	}, nil)
	if !strings.Contains(got, "req.method=POST") || !strings.Contains(got, "req.size=12") {
		t.Errorf("inline group attr should prefix keys: %q", got)
	}
}

func TestConsole_WithAttrsRenderedBeforeRecordAttrs(t *testing.T) {
	got := renderRecord(t, false, slog.LevelInfo, "m", func(r *slog.Record) {
		r.AddAttrs(slog.String("rec", "B"))
	}, func(h slog.Handler) slog.Handler {
		return h.WithAttrs([]slog.Attr{slog.String("pre", "A")})
	})
	pi := strings.Index(got, "pre=A")
	ri := strings.Index(got, "rec=B")
	if pi < 0 || ri < 0 || pi > ri {
		t.Errorf("WithAttrs should render before record attrs: %q", got)
	}
}

// TestNew_ConsoleColorGating verifies the public constructor honors the
// injected TTY detector and NO_COLOR for color decisions.
func TestNew_ConsoleColorGating(t *testing.T) {
	t.Run("tty true emits color", func(t *testing.T) {
		unsetNoColor(t)
		got := newViaNew(t, func(io.Writer) bool { return true })
		if !strings.Contains(got, "\x1b[") {
			t.Errorf("TTY=true, NO_COLOR unset should color: %q", got)
		}
	})

	t.Run("tty false is plain", func(t *testing.T) {
		unsetNoColor(t)
		got := newViaNew(t, func(io.Writer) bool { return false })
		if strings.Contains(got, "\x1b[") {
			t.Errorf("TTY=false should be plain: %q", got)
		}
	})

	t.Run("NO_COLOR set is plain even on tty", func(t *testing.T) {
		t.Setenv("NO_COLOR", "1")
		got := newViaNew(t, func(io.Writer) bool { return true })
		if strings.Contains(got, "\x1b[") {
			t.Errorf("NO_COLOR set should be plain: %q", got)
		}
	})
}

// newViaNew builds a console logger through the public New with the given TTY
// stub, logs one WARN, and returns the rendered output.
func newViaNew(t *testing.T, isTTY func(io.Writer) bool) string {
	t.Helper()
	var buf bytes.Buffer
	logger, err := New(Options{Format: FormatConsole, Writer: &buf, IsTTY: isTTY})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	logger.Warn("boom")
	return buf.String()
}

// unsetNoColor removes NO_COLOR for the duration of the test. t.Setenv records
// the original value and restores it at cleanup (it has no Unsetenv), so we set
// it through t first, then os.Unsetenv it for the test body.
func unsetNoColor(t *testing.T) {
	t.Helper()
	t.Setenv("NO_COLOR", "")
	if err := os.Unsetenv("NO_COLOR"); err != nil {
		t.Fatalf("unset NO_COLOR: %v", err)
	}
}
