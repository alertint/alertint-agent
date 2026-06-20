// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"strings"
	"testing"
)

func loadYAML(t *testing.T, y string) (*Config, error) {
	t.Helper()
	return LoadFrom(strings.NewReader(y), "test.yaml")
}

func TestConfig_ReceiversAddressRequiredWhenReceiverEnabled(t *testing.T) {
	// alertmanager enabled but receivers.address blank → error.
	_, err := loadYAML(t, `
receivers:
  address: ""
alertmanager:
  enabled: true
  webhook_token_env: TOK
mcp:
  enabled: false
llm:
  api_key_env: K
storage:
  sqlite_path: ./x.db
`)
	if err == nil || !strings.Contains(err.Error(), "receivers.address is required") {
		t.Fatalf("want receivers.address error, got %v", err)
	}
}

func TestConfig_ChangesIngressTokenRequired(t *testing.T) {
	_, err := loadYAML(t, `
receivers:
  address: ":9911"
alertmanager:
  enabled: false
changes:
  ingress:
    enabled: true
mcp:
  enabled: false
llm:
  api_key_env: K
storage:
  sqlite_path: ./x.db
`)
	if err == nil || !strings.Contains(err.Error(), "changes: ingress: webhook_token_env is required") {
		t.Fatalf("want changes ingress token error, got %v", err)
	}
}

func TestConfig_ChangesEnrichmentTunables(t *testing.T) {
	_, err := loadYAML(t, `
receivers:
  address: ":9911"
alertmanager:
  enabled: false
changes:
  enrichment:
    enabled: true
    window_minutes: 0
    max_events: 0
  retention_days: 0
mcp:
  enabled: true
  token_env: M
llm:
  api_key_env: K
storage:
  sqlite_path: ./x.db
`)
	if err == nil {
		t.Fatal("want enrichment-tunable errors")
	}
	for _, want := range []string{"window_minutes", "max_events", "retention_days"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("missing %q in %v", want, err)
		}
	}
}

func TestConfig_NothingToServe(t *testing.T) {
	_, err := loadYAML(t, `
alertmanager:
  enabled: false
mcp:
  enabled: false
llm:
  api_key_env: K
storage:
  sqlite_path: ./x.db
`)
	if err == nil || !strings.Contains(err.Error(), "nothing to serve") {
		t.Fatalf("want nothing-to-serve, got %v", err)
	}
}

func TestConfig_UnknownWebhookAddrRejected(t *testing.T) {
	// The removed key must fail loud under strict config.
	_, err := loadYAML(t, `
alertmanager:
  enabled: true
  webhook_addr: ":9911"
  webhook_token_env: TOK
llm:
  api_key_env: K
storage:
  sqlite_path: ./x.db
`)
	if err == nil || !strings.Contains(err.Error(), "webhook_addr") {
		t.Fatalf("want unknown-key error for webhook_addr, got %v", err)
	}
}
