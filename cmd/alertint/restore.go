// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/backup"
	"github.com/alertint/alertint-agent/internal/logging"
	"github.com/alertint/alertint-agent/internal/store"
)

// restorePayload is the db.restore_applied audit row: the in-band record
// that makes an honest restore self-documenting (spec req 7; ADR-0030).
type restorePayload struct {
	Mode           string `json:"mode"`
	SourceFile     string `json:"source_file"`
	SourceBytes    int64  `json:"source_bytes"`
	InstalledBytes int64  `json:"installed_bytes"`
	AuditVerify    string `json:"audit_verify"`
}

// runRestore implements "alertint restore": an offline restore of a
// backup file onto the agent's DB path. Refuses while the agent runs.
func runRestore(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("alertint restore", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "path to alertint YAML config")
	dbPathFlag := fs.String("db", "", "path to SQLite database (overrides config.storage.sqlite_path)")
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

	backupFile := fs.Arg(0)
	if backupFile == "" {
		return fmt.Errorf("restore: <backup-file> argument is required")
	}
	dbPath, err := resolveDBPath("restore", *cfgPath, *dbPathFlag)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	info, err := backup.Restore(ctx, dbPath, backupFile)
	if err != nil {
		return fmt.Errorf("restore: %w", err)
	}

	// Open the restored DB (migrates an older backup forward), verify the
	// chain, append the db.restore_applied row.
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("restore: open restored database: %w", err)
	}
	defer func() { _ = st.Close() }()
	if err := finalizeRestore(ctx, st, info, logger); err != nil {
		return fmt.Errorf("restore: %w", err)
	}

	if info.SafetyCopy != "" {
		_, _ = fmt.Fprintf(stdout, "restore applied: %s from %s (previous database at %s)\n",
			dbPath, backupFile, info.SafetyCopy)
	} else {
		_, _ = fmt.Fprintf(stdout, "restore applied: %s from %s (no previous database)\n", dbPath, backupFile)
	}
	return nil
}

// finalizeRestore verifies the restored DB's audit chain (loud, warn-only:
// the operator chose this file, and verify-audit remains available for a
// deliberate check) and appends the db.restore_applied row. Shared by the
// offline CLI and serve's staged startup path.
func finalizeRestore(ctx context.Context, st *store.Store, info *backup.RestoreInfo, logger *slog.Logger) error {
	auditor := audit.New(st.DB())

	var verifyResult string
	report, verr := auditor.Verify(ctx)
	switch {
	case verr != nil && report != nil:
		verifyResult = fmt.Sprintf("failed at seq %d: %s", report.FailedSeq, report.Reason)
		logger.Warn("restored audit chain failed verification",
			slog.Int64("failed_seq", report.FailedSeq), slog.String("reason", report.Reason))
	case verr != nil:
		verifyResult = fmt.Sprintf("failed: %v", verr)
		logger.Warn("restored audit chain could not be verified", slog.String("error", verr.Error()))
	default:
		verifyResult = fmt.Sprintf("ok (%d rows)", report.RowsChecked)
		logger.Info("restored audit chain verified", slog.Int("rows_checked", report.RowsChecked))
	}

	if err := auditor.Append(ctx, "restore", "db.restore_applied", restorePayload{
		Mode:           info.Mode,
		SourceFile:     info.SourceFile,
		SourceBytes:    info.SourceBytes,
		InstalledBytes: info.InstalledBytes,
		AuditVerify:    verifyResult,
	}); err != nil {
		return fmt.Errorf("append restore_applied audit row: %w", err)
	}
	return nil
}
