// SPDX-License-Identifier: FSL-1.1-ALv2

// Package logging provides the agent's structured logging baseline.
//
// All runtime logs flow through a single *slog.Logger configured here:
//   - JSON handler for machine consumption / log shipping (the production
//     default on a non-TTY)
//   - console handler — one human-readable colored line per record — for
//     live watching on a terminal
//   - Level driven by config (debug, info, warn, error)
//
// No package in the binary should call fmt.Println for runtime logs;
// use the logger returned by New or the process default set via SetDefault.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/mattn/go-isatty"
)

// Format selects the slog handler.
type Format string

const (
	// FormatAuto resolves to FormatConsole on a TTY and FormatJSON otherwise.
	// It is a selection value only — Resolve turns it into a concrete handler
	// before New is called; New itself does not accept it.
	FormatAuto    Format = "auto"
	FormatJSON    Format = "json"
	FormatConsole Format = "console"
)

// Options configures the logger.
type Options struct {
	// Level is one of "debug", "info", "warn", "error". Empty means "info".
	Level string
	// Format selects the output handler. Empty means JSON.
	Format Format
	// Writer is the destination. Nil means os.Stderr.
	Writer io.Writer
	// IsTTY reports whether w is an interactive terminal. It is used by the
	// console format to decide whether to emit ANSI color. Nil means use the
	// built-in detector (IsTerminalWriter); tests inject a stub.
	IsTTY func(w io.Writer) bool
}

// New constructs a *slog.Logger from Options. It returns an error only if
// Level is non-empty and not a recognized value.
func New(opts Options) (*slog.Logger, error) {
	level, err := parseLevel(opts.Level)
	if err != nil {
		return nil, err
	}

	w := opts.Writer
	if w == nil {
		w = os.Stderr
	}

	handlerOpts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	switch opts.Format {
	case "", FormatJSON:
		handler = slog.NewJSONHandler(w, handlerOpts)
	case FormatConsole:
		handler = newConsoleHandler(w, level, colorEnabled(w, opts.IsTTY))
	case FormatAuto:
		// auto is a selection value: it must be resolved to a concrete handler
		// (via Resolve) before New is called.
		return nil, fmt.Errorf("logging: format %q must be resolved before New (use Resolve)", opts.Format)
	default:
		return nil, fmt.Errorf("logging: unknown format %q", opts.Format)
	}

	return slog.New(handler), nil
}

// Resolve turns a selection format into a concrete handler format. FormatAuto
// becomes FormatConsole when w is a terminal, FormatJSON otherwise; any other
// value passes through unchanged. isTTY may be nil (uses IsTerminalWriter).
// Keying off the log writer (stderr) lets `alertint serve > findings.json`
// keep the colored trail on the terminal while JSON findings redirect.
func Resolve(format Format, w io.Writer, isTTY func(io.Writer) bool) Format {
	if format != FormatAuto {
		return format
	}
	if isTTY == nil {
		isTTY = IsTerminalWriter
	}
	if isTTY(w) {
		return FormatConsole
	}
	return FormatJSON
}

// colorEnabled reports whether the console handler should emit ANSI color.
// NO_COLOR (any value) disables color and wins over everything (the de-facto
// no-color convention, https://no-color.org). Otherwise CLICOLOR_FORCE forces
// color on even when the writer is not a terminal — useful when the colored
// stream is captured and replayed to a terminal, e.g. `docker logs`. Failing
// both, color follows TTY detection. isTTY may be nil (uses IsTerminalWriter).
func colorEnabled(w io.Writer, isTTY func(io.Writer) bool) bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	if forceColor() {
		return true
	}
	if isTTY == nil {
		isTTY = IsTerminalWriter
	}
	return isTTY(w)
}

// forceColor reports whether CLICOLOR_FORCE requests color regardless of TTY
// detection (the companion to NO_COLOR; see https://bixense.com/clicolors).
// Any value other than unset / "" / "0" / "false" enables it.
func forceColor() bool {
	v, ok := os.LookupEnv("CLICOLOR_FORCE")
	if !ok {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "0", "false":
		return false
	default:
		return true
	}
}

// IsTerminalWriter reports whether w is an interactive terminal. It returns
// false for any writer that is not an *os.File (or otherwise exposes no file
// descriptor) — e.g. a bytes.Buffer or a pipe — so redirected output stays
// plain. This is the default TTY detector for the console format and for
// resolving the auto log format.
func IsTerminalWriter(w io.Writer) bool {
	f, ok := w.(interface{ Fd() uintptr })
	if !ok {
		return false
	}
	fd := f.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

// SetDefault installs logger as the slog package default.
func SetDefault(logger *slog.Logger) {
	slog.SetDefault(logger)
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("logging: unknown level %q", s)
	}
}
