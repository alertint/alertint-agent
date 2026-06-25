// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/health"
	"github.com/alertint/alertint-agent/internal/sentry"
	"github.com/alertint/alertint-agent/internal/store"
)

func sentryEnabledConfig(baseURL string) *config.Config {
	cfg := config.Defaults()
	cfg.Sentry.BaseURL = baseURL
	cfg.Sentry.Org = "acme"
	cfg.Sentry.TokenEnv = "SENTRY_WIRING_TOK"
	cfg.Sentry.Releases.Enabled = true
	return &cfg
}

func statusByName(reg *health.Registry, name string) *health.Status {
	for _, s := range reg.Run(context.Background()) {
		if s.Name == name {
			s := s
			return &s
		}
	}
	return nil
}

// TestSentryWiring_DisabledIsSilent covers AE8: a disabled config constructs no
// client, no poller, and registers no health check.
func TestSentryWiring_DisabledIsSilent(t *testing.T) {
	cfg := config.Defaults() // sentry disabled by default

	client, err := newSentryClient(&cfg)
	if err != nil || client != nil {
		t.Fatalf("newSentryClient(disabled) = %v, %v; want nil, nil", client, err)
	}
	if p := newSentryPoller(&cfg, nil, nil, slog.Default()); p != nil {
		t.Error("newSentryPoller(nil client) should be nil")
	}
	reg := buildHealthChecks(&cfg, nil, nil, nil)
	if statusByName(reg, "sentry") != nil {
		t.Error("sentry health check registered while disabled")
	}
}

func TestSentryWiring_EnabledClientResolvesToken(t *testing.T) {
	t.Setenv("SENTRY_WIRING_TOK", "sntrys-secret")
	cfg := sentryEnabledConfig("https://sentry.io")

	client, err := newSentryClient(cfg)
	if err != nil || client == nil {
		t.Fatalf("newSentryClient(enabled) = %v, %v; want a client", client, err)
	}
	if client.Org() != "acme" || client.BaseURL() != "https://sentry.io" {
		t.Errorf("client org/baseURL = %q/%q", client.Org(), client.BaseURL())
	}

	// Missing env var → loud error, no client.
	t.Setenv("SENTRY_WIRING_TOK", "")
	if _, err := newSentryClient(cfg); err == nil {
		t.Error("expected error when token env var is unset")
	}
}

func TestSentryWiring_HealthCheckProbeOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	cfg := sentryEnabledConfig(srv.URL)
	client := sentry.NewClient(sentry.Config{BaseURL: srv.URL, Org: "acme", Token: "t"})
	reg := buildHealthChecks(cfg, nil, nil, client)

	s := statusByName(reg, "sentry")
	if s == nil {
		t.Fatal("sentry check not registered while enabled")
	}
	if !s.OK {
		t.Errorf("sentry probe = %#v, want OK", s)
	}
	if s.Detail != srv.URL {
		t.Errorf("detail = %q, want base URL %q", s.Detail, srv.URL)
	}
}

// TestSentryWiring_HealthCheckProbeFailed covers AE10: an unreachable / forbidden
// Sentry makes the probe (and GET /health) report FAILED. A 403 is the realistic
// bad-token/scope case and returns without retry sleeps.
func TestSentryWiring_HealthCheckProbeFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	cfg := sentryEnabledConfig(srv.URL)
	client := sentry.NewClient(sentry.Config{BaseURL: srv.URL, Org: "acme", Token: "bad"})
	reg := buildHealthChecks(cfg, nil, nil, client)

	s := statusByName(reg, "sentry")
	if s == nil || s.OK {
		t.Fatalf("sentry probe = %#v, want FAILED", s)
	}
}

// TestSentryWiring_PollerStartStop exercises the cmd-level poller wiring through
// a clean start/stop, standing in for the serve lifecycle's graceful shutdown.
func TestSentryWiring_PollerStartStop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	cfg := sentryEnabledConfig(srv.URL)
	client := sentry.NewClient(sentry.Config{BaseURL: srv.URL, Org: "acme", Token: "t"})
	poller := newSentryPoller(cfg, client, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if poller == nil {
		t.Fatal("newSentryPoller(enabled) returned nil")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	poller.Start(ctx)
	poller.Stop() // must return promptly (no goroutine leak / deadlock)
}
