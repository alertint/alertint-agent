// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof" //nolint:gosec // G108: served only on telemetry.pprof.addr's own mux below, never on http.DefaultServeMux's servers
	"time"
)

// startPprof serves Go's runtime profiles on addr (telemetry.pprof.addr) on
// its own listener and mux. Empty addr starts nothing. It returns the bound
// address and the function runServe defers to stop the listener; stop is
// always non-nil. /debug/pprof/cmdline is left out: the command line can
// carry arguments an operator never meant to share.
func startPprof(ctx context.Context, addr string, logger *slog.Logger) (string, func(), error) {
	if addr == "" {
		return "", func() {}, nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return "", nil, fmt.Errorf("telemetry.pprof: listen %s: %w", addr, err)
	}
	// No WriteTimeout: a CPU profile or trace streams for its requested seconds.
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Warn("telemetry: pprof listener stopped", slog.String("err", err.Error()))
		}
	}()
	bound := ln.Addr().String()
	logger.Info("telemetry: pprof listening", slog.String("addr", bound))
	return bound, func() { //nolint:contextcheck // by design: stops after the serve context is already canceled, on its own bounded context
		stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(stopCtx)
	}, nil
}
