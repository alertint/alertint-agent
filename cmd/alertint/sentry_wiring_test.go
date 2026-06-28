// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/health"
	"github.com/alertint/alertint-agent/internal/sentry"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

// The shared *sentry.Client must satisfy the Error-source reader the triage skill
// injects — a compile-time guard for the U6 wiring assignment.
var _ acutetriage.SentryReader = (*sentry.Client)(nil)

func sentryEnabledConfig(baseURL string) *config.Config {
	cfg := config.Defaults()
	cfg.Sentry.BaseURL = baseURL
	cfg.Sentry.Org = "acme"
	cfg.Sentry.TokenEnv = "SENTRY_WIRING_TOK"
	cfg.Sentry.Releases.Enabled = true
	return &cfg
}

// sentryStatus returns the "sentry" health probe's status from the registry, or
// nil when it is not registered. These tests only ever assert on the sentry check.
func sentryStatus(reg *health.Registry) *health.Status {
	for _, s := range reg.Run(context.Background()) {
		if s.Name == "sentry" {
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
	if sentryStatus(reg) != nil {
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

	s := sentryStatus(reg)
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

	s := sentryStatus(reg)
	if s == nil || s.OK {
		t.Fatalf("sentry probe = %#v, want FAILED", s)
	}
}

// issuesOnlyConfig enables the Error source with releases OFF, exercising the
// decoupled gating (KTD7).
func issuesOnlyConfig(baseURL string) *config.Config {
	cfg := config.Defaults()
	cfg.Sentry.BaseURL = baseURL
	cfg.Sentry.Org = "acme"
	cfg.Sentry.TokenEnv = "SENTRY_WIRING_TOK"
	cfg.Sentry.Issues.Enabled = true // releases stays disabled
	return &cfg
}

// TestSentryWiring_IssuesOnlyBuildsClientNoPoller covers KTD7: the Error source
// gets the shared client even when release polling is off, and NO release poller
// goroutine runs (the poller would hit the server on its immediate first cycle —
// the request count stays 0).
func TestSentryWiring_IssuesOnlyBuildsClientNoPoller(t *testing.T) {
	t.Setenv("SENTRY_WIRING_TOK", "sntrys-secret")
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	cfg := issuesOnlyConfig(srv.URL)
	if !cfg.AnySentryEnabled() {
		t.Fatal("AnySentryEnabled should be true for issues-only")
	}

	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	client, stop, err := startSentryPoller(context.Background(), cfg, st, slog.New(slog.DiscardHandler))
	if err != nil || client == nil {
		t.Fatalf("startSentryPoller(issues-only) = %v, %v; want a shared client", client, err)
	}
	defer stop()
	if hits != 0 {
		t.Errorf("no release poller should run for issues-only, but the server got %d request(s)", hits)
	}
}

// TestSentryWiring_IssuesOnlyRegistersHealthCheck: the health probe registers
// when either feature is on (KTD7).
func TestSentryWiring_IssuesOnlyRegistersHealthCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	cfg := issuesOnlyConfig(srv.URL)
	client := sentry.NewClient(sentry.Config{BaseURL: srv.URL, Org: "acme", Token: "t"})
	reg := buildHealthChecks(cfg, nil, nil, client)
	if sentryStatus(reg) == nil {
		t.Fatal("sentry health check must be registered for issues-only")
	}
}

// TestSentryErrorSource_TypedNilSafety pins KTD7's typed-nil trap avoidance: the
// injected SentryReader is a TRUE nil interface unless issues is on with a live
// client, so FetchSentry's r == nil guard fires for disabled/releases-only/no-client.
func TestSentryErrorSource_TypedNilSafety(t *testing.T) {
	client := sentry.NewClient(sentry.Config{BaseURL: "https://x", Org: "acme", Token: "t"})

	// Both features disabled → true nil interface, params off.
	cfg := config.Defaults()
	if r, p := sentryErrorSource(&cfg, nil); r != nil || p.Enabled {
		t.Errorf("disabled: reader=%v params.Enabled=%v; want nil, false", r, p.Enabled)
	}

	// Releases-only (issues off) with a live client → still a nil reader.
	relCfg := config.Defaults()
	relCfg.Sentry.Releases.Enabled = true
	if r, _ := sentryErrorSource(&relCfg, client); r != nil {
		t.Error("releases-only must not inject the Error-source reader")
	}

	// Issues-on with a live client → non-nil reader + enabled params.
	issCfg := config.Defaults()
	issCfg.Sentry.Issues.Enabled = true
	if r, p := sentryErrorSource(&issCfg, client); r == nil || !p.Enabled {
		t.Errorf("issues-on: reader=%v params.Enabled=%v; want a reader, true", r, p.Enabled)
	}

	// Issues-on but no client (construction absent) → still a true nil reader.
	if r, _ := sentryErrorSource(&issCfg, nil); r != nil {
		t.Error("issues-on with nil client must still yield a true nil reader")
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
	poller := newSentryPoller(cfg, client, st, slog.New(slog.DiscardHandler))
	if poller == nil {
		t.Fatal("newSentryPoller(enabled) returned nil")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	poller.Start(ctx)
	poller.Stop() // must return promptly (no goroutine leak / deadlock)
}
