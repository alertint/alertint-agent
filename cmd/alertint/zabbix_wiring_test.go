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
	"github.com/alertint/alertint-agent/internal/zabbix"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

// The client must satisfy the ZabbixReader the triage skill injects — a
// compile-time guard for the wiring assignment.
var _ acutetriage.ZabbixReader = (*zabbix.Client)(nil)

func zabbixEnabledConfig(baseURL string) *config.Config {
	cfg := config.Defaults()
	cfg.Zabbix.API.BaseURL = baseURL
	cfg.Zabbix.API.APITokenEnv = "ZABBIX_WIRING_TOK"
	return &cfg
}

// zabbixStatus returns the "zabbix" health probe's status from the registry, or
// nil when it is not registered.
func zabbixStatus(reg *health.Registry) *health.Status {
	for _, s := range reg.Run(context.Background()) {
		if s.Name == "zabbix" {
			s := s
			return &s
		}
	}
	return nil
}

// TestZabbixWiring_DisabledIsSilent: a disabled config constructs no client
// and registers no health check.
func TestZabbixWiring_DisabledIsSilent(t *testing.T) {
	cfg := config.Defaults() // zabbix api disabled by default

	client, err := newZabbixClient(&cfg, slog.Default())
	if err != nil || client != nil {
		t.Fatalf("newZabbixClient(disabled) = %v, %v; want nil, nil", client, err)
	}
	reg := buildHealthChecks(&cfg, nil, nil, nil, nil)
	if zabbixStatus(reg) != nil {
		t.Error("zabbix health check registered while disabled")
	}
}

func TestZabbixWiring_EnabledClientResolvesToken(t *testing.T) {
	t.Setenv("ZABBIX_WIRING_TOK", "s3cret")
	cfg := zabbixEnabledConfig("https://zbx.example.com")

	client, err := newZabbixClient(cfg, slog.Default())
	if err != nil || client == nil {
		t.Fatalf("newZabbixClient(enabled) = %v, %v; want a client", client, err)
	}

	// Missing env var → loud error, no client.
	t.Setenv("ZABBIX_WIRING_TOK", "")
	if _, err := newZabbixClient(cfg, slog.Default()); err == nil {
		t.Error("expected error when token env var is unset")
	}
}

func TestZabbixWiring_HealthCheckProbeOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":"7.0.0","id":1}`))
	}))
	defer srv.Close()

	cfg := zabbixEnabledConfig(srv.URL)
	client := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "t"})
	reg := buildHealthChecks(cfg, nil, nil, nil, client)

	s := zabbixStatus(reg)
	if s == nil {
		t.Fatal("zabbix check not registered while enabled")
	}
	if !s.OK {
		t.Errorf("zabbix probe = %#v, want OK", s)
	}
	if s.Detail != srv.URL {
		t.Errorf("detail = %q, want base URL %q", s.Detail, srv.URL)
	}
}

// TestZabbixWiring_HealthCheckProbeFailed: an unreachable Zabbix makes the
// probe (and GET /health) report FAILED.
func TestZabbixWiring_HealthCheckProbeFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	cfg := zabbixEnabledConfig(srv.URL)
	client := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "bad"})
	reg := buildHealthChecks(cfg, nil, nil, nil, client)

	s := zabbixStatus(reg)
	if s == nil || s.OK {
		t.Fatalf("zabbix probe = %#v, want FAILED", s)
	}
}
