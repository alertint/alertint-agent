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

	"github.com/alertint/alertint-agent/internal/logging"
	"github.com/alertint/alertint-agent/internal/store"
)

// runFunnel implements `alertint funnel --since <UTC> --until <UTC>`: the
// same store.PokeFunnel query the alertint_poke_funnel_get MCP tool uses, so
// both surfaces report identical delivery -> source-episode -> Incident ->
// Situation -> main-channel-poke counts. It reports local compression
// against both deliveries and distinct source episodes; it never claims a
// count of external Zabbix-to-Slack messages avoided — that baseline is
// observable only from the operator's separate path.
func runFunnel(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("alertint funnel", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "path to alertint YAML config")
	dbPathFlag := fs.String("db", "", "path to SQLite database (overrides config.storage.sqlite_path)")
	sinceFlag := fs.String("since", "", "window start (RFC3339, e.g. 2026-08-01T00:00:00Z)")
	untilFlag := fs.String("until", "", "window end (RFC3339)")
	logLevel := fs.String("log-level", "warn", "log level: debug, info, warn, error")
	logFormat := fs.String("log-format", "auto", "log format: auto, console, json")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *sinceFlag == "" || *untilFlag == "" {
		return fmt.Errorf("funnel: --since and --until are required (RFC3339)")
	}
	since, err := time.Parse(time.RFC3339, *sinceFlag)
	if err != nil {
		return fmt.Errorf("funnel: invalid --since: %w", err)
	}
	until, err := time.Parse(time.RFC3339, *untilFlag)
	if err != nil {
		return fmt.Errorf("funnel: invalid --until: %w", err)
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

	dbPath, err := resolveDBPath("funnel", *cfgPath, *dbPathFlag)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	s, err := store.Open(ctx, dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()

	report, err := s.PokeFunnel(ctx, since, until)
	if err != nil {
		return fmt.Errorf("funnel: %w", err)
	}

	_, _ = fmt.Fprintf(stdout, "window: %s to %s\n", report.Since.Format(time.RFC3339), report.Until.Format(time.RFC3339))
	_, _ = fmt.Fprintf(stdout, "accepted deliveries:      %d\n", report.AcceptedDeliveries)
	_, _ = fmt.Fprintf(stdout, "distinct source episodes: %d\n", report.SourceEpisodes)
	_, _ = fmt.Fprintf(stdout, "incidents:                %d\n", report.Incidents)
	_, _ = fmt.Fprintf(stdout, "situations:               %d\n", report.Situations)
	_, _ = fmt.Fprintf(stdout, "root creates:             %d\n", report.RootCreates)
	_, _ = fmt.Fprintf(stdout, "root edits:               %d\n", report.RootEdits)
	_, _ = fmt.Fprintf(stdout, "non-broadcast replies:    %d\n", report.ThreadReplies)
	_, _ = fmt.Fprintf(stdout, "broadcast replies:        %d\n", report.BroadcastReplies)
	_, _ = fmt.Fprintf(stdout, "envelope reviews:         %d\n", report.EnvelopeReviews)
	_, _ = fmt.Fprintf(stdout, "health pokes:             %d\n", report.HealthPokes)
	_, _ = fmt.Fprintf(stdout, "main-channel pokes:       %d\n", report.MainChannelPokes)
	return nil
}
