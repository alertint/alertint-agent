// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/telemetry"
)

// startTelemetry installs the OTLP trace exporter when telemetry.otlp is
// enabled and returns the function runServe defers to flush and stop it.
// Disabled (the default) installs nothing: every span stays a no-op and no
// telemetry leaves the process. The returned stop is always non-nil.
func startTelemetry(ctx context.Context, cfg *config.Config, version string, logger *slog.Logger) (func(), error) {
	o := cfg.Telemetry.OTLP
	if !o.Enabled {
		return func() {}, nil
	}
	timeout := time.Duration(o.TimeoutSeconds) * time.Second
	shutdown, err := telemetry.Start(ctx, telemetry.Options{
		Endpoint:       o.Endpoint,
		Protocol:       o.Protocol,
		Insecure:       o.Insecure,
		ServiceName:    o.ServiceName,
		ServiceVersion: version,
		Timeout:        timeout,
		Logger:         logger,
	})
	if err != nil {
		return nil, fmt.Errorf("telemetry: %w", err)
	}
	logger.Info("telemetry: OTLP trace export enabled",
		slog.String("endpoint", o.Endpoint), slog.String("protocol", o.Protocol),
		slog.Bool("insecure", o.Insecure), slog.String("service_name", o.ServiceName))
	return func() { //nolint:contextcheck // by design: the final flush runs after the serve context is already canceled, on its own bounded context
		flushCtx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if err := shutdown(flushCtx); err != nil {
			logger.Warn("telemetry: OTLP trace export shutdown", slog.String("err", err.Error()))
		}
	}, nil
}
