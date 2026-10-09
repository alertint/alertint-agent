// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/notify/ntfy"
	"github.com/alertint/alertint-agent/internal/store"
)

func buildNTFYRuntime(ctx context.Context, cfg *config.Config, st *store.Store, auditor *audit.Auditor, owner string, logger *slog.Logger) (*ntfy.Worker, error) {
	c := cfg.Notify.NTFY
	var token string
	if c.Enabled && c.TokenEnv != "" {
		token = strings.TrimSpace(os.Getenv(c.TokenEnv))
		if token == "" {
			return nil, fmt.Errorf("notify.ntfy.token_env: environment variable %s is empty or unset", c.TokenEnv)
		}
	}
	if err := st.ConfigureNTFY(ctx, c, time.Now().UTC()); err != nil {
		return nil, fmt.Errorf("ntfy configuration: %w", err)
	}
	if !c.Enabled {
		return nil, nil //nolint:nilnil // Disabled sink intentionally has no worker.
	}
	var sink ntfy.AuditSink
	if auditor != nil {
		sink = auditor
	}
	return ntfy.NewWorker(st, ntfy.NewClient(token), owner+":ntfy", logger, sink), nil
}
