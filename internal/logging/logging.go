// Package logging provides the agent's structured logging baseline.
//
// All runtime logs flow through a single *slog.Logger configured here:
//   - JSON handler in production (default)
//   - Text handler in development
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
)

// Format selects the slog handler.
type Format string

const (
	FormatJSON Format = "json"
	FormatText Format = "text"
)

// Options configures the logger.
type Options struct {
	// Level is one of "debug", "info", "warn", "error". Empty means "info".
	Level string
	// Format selects JSON or text output. Empty means JSON.
	Format Format
	// Writer is the destination. Nil means os.Stderr.
	Writer io.Writer
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
	case FormatText:
		handler = slog.NewTextHandler(w, handlerOpts)
	default:
		return nil, fmt.Errorf("logging: unknown format %q", opts.Format)
	}

	return slog.New(handler), nil
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
