// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alertint/alertint-agent/internal/backup"
	"github.com/alertint/alertint-agent/internal/logging"
)

// runBackup implements "alertint backup": a consistent live snapshot of
// the agent's SQLite state via read-only VACUUM INTO. Safe while serve
// runs; never writes to the source DB.
func runBackup(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("alertint backup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "path to alertint YAML config")
	dbPathFlag := fs.String("db", "", "path to SQLite database (overrides config.storage.sqlite_path)")
	force := fs.Bool("force", false, "overwrite an existing target file")
	logLevel := fs.String("log-level", "warn", "log level: debug, info, warn, error")
	logFormat := fs.String("log-format", "auto", "log format: auto, console, json")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger, err := logging.New(logging.Options{
		Level:  *logLevel,
		Format: logging.Resolve(logging.Format(*logFormat), stderr, nil),
		Writer: stderr,
	})
	if err != nil {
		return err
	}
	logging.SetDefault(logger)

	dbPath, err := resolveDBPath("backup", *cfgPath, *dbPathFlag)
	if err != nil {
		return err
	}

	target := fs.Arg(0)
	if target == "" {
		target = backup.DefaultTarget(dbPath, time.Now())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	n, err := backup.Create(ctx, dbPath, target, *force)
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	_, _ = fmt.Fprintf(stdout, "backup written: %s (%d bytes)\n", target, n)
	return nil
}
