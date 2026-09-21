// SPDX-License-Identifier: FSL-1.1-ALv2

package prometheus

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRuleDefinitionBoundedStableAcrossRuntimeChurnAndChangesOnDefinitionEdit(t *testing.T) {
	body := `{"status":"success","data":{"groups":[{"name":"jobs","file":"/etc/rules.yml","interval":15,"limit":0,"evaluationTime":9.1,"lastEvaluation":"2026-09-21T00:00:00Z","rules":[{"type":"alerting","name":"ReconciliationLoad","query":"cpu_load > 5","duration":60,"keepFiringFor":0,"labels":{"severity":"warning","service":"payment"},"annotations":{"summary":"busy"},"health":"ok","evaluationTime":3.2,"lastEvaluation":"2026-09-21T00:00:00Z","alerts":[{"labels":{"alertname":"ReconciliationLoad","service":"payment","instance":"db-1"},"state":"firing","activeAt":"2026-09-21T00:00:00Z","value":"6"}]}]}]}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/status/config" {
			_, _ = w.Write([]byte(`{"status":"success","data":{"yaml":"global: {}\n"}}`))
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	c := NewClient(Config{BaseURL: server.URL})
	one, err := c.RuleDefinitionBounded(context.Background(), "prod-prom", "jobs", "ReconciliationLoad", map[string]string{"service": "payment"})
	if err != nil {
		t.Fatal(err)
	}
	if !one.Available || one.Version == "" || one.Presence != "present" {
		t.Fatalf("definition = %+v", one)
	}

	body = `{"status":"success","data":{"groups":[{"name":"jobs","file":"/etc/rules.yml","interval":15,"limit":0,"evaluationTime":1,"rules":[{"type":"alerting","name":"ReconciliationLoad","query":"cpu_load > 5","duration":60,"keepFiringFor":0,"labels":{"service":"payment","severity":"warning"},"annotations":{"summary":"busy"},"health":"pending","alerts":[]}]}]}}`
	two, err := c.RuleDefinitionBounded(context.Background(), "prod-prom", "jobs", "ReconciliationLoad", map[string]string{"service": "payment"})
	if err != nil {
		t.Fatal(err)
	}
	if two.Version != one.Version {
		t.Fatalf("runtime churn changed version: %q != %q", two.Version, one.Version)
	}
	if two.Presence != "absent" {
		t.Fatalf("presence = %q", two.Presence)
	}

	body = `{"status":"success","data":{"groups":[{"name":"jobs","file":"/etc/rules.yml","interval":15,"limit":0,"rules":[{"type":"alerting","name":"ReconciliationLoad","query":"cpu_load > 7","duration":60,"keepFiringFor":0,"labels":{"service":"payment","severity":"warning"},"annotations":{"summary":"busy"},"alerts":[]}]}]}}`
	three, err := c.RuleDefinitionBounded(context.Background(), "prod-prom", "jobs", "ReconciliationLoad", map[string]string{"service": "payment"})
	if err != nil {
		t.Fatal(err)
	}
	if three.Version == one.Version {
		t.Fatal("definition edit did not change version")
	}
}

func TestRuleDefinitionBoundedReturnsExplicitUnsupportedForAmbiguousRule(t *testing.T) {
	body := `{"status":"success","data":{"groups":[{"name":"jobs","file":"a.yml","interval":15,"rules":[{"type":"alerting","name":"Load","query":"up","labels":{}}]},{"name":"jobs","file":"b.yml","interval":15,"rules":[{"type":"alerting","name":"Load","query":"up","labels":{}}]}]}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/status/config" {
			_, _ = w.Write([]byte(`{"status":"success","data":{"yaml":"global: {}\n"}}`))
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	got, err := NewClient(Config{BaseURL: server.URL}).RuleDefinitionBounded(context.Background(), "prod-prom", "jobs", "Load", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Available || got.UnavailableReason != "ambiguous_rule" {
		t.Fatalf("definition = %+v", got)
	}
}

func TestRuleDefinitionBoundedSelectsAlertingRuleWhenRecordingRuleSharesName(t *testing.T) {
	rules := `{"status":"success","data":{"groups":[{"name":"jobs","interval":15,"rules":[{"type":"recording","name":"Load","query":"sum(up)"},{"type":"alerting","name":"Load","query":"up == 0","labels":{},"alerts":[]}]}]}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/status/config" {
			_, _ = w.Write([]byte(`{"status":"success","data":{"yaml":"global: {}\n"}}`))
			return
		}
		_, _ = w.Write([]byte(rules))
	}))
	defer server.Close()
	got, err := NewClient(Config{BaseURL: server.URL}).RuleDefinitionBounded(context.Background(), "prod-prom", "jobs", "Load", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Available || got.UnavailableReason != "" {
		t.Fatalf("definition = %+v", got)
	}
}

func TestRuleDefinitionBoundedRejectsAlertRelabeling(t *testing.T) {
	rules := `{"status":"success","data":{"groups":[{"name":"jobs","interval":15,"rules":[{"type":"alerting","name":"Load","query":"up == 0","labels":{}}]}]}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/status/config" {
			_, _ = w.Write([]byte(`{"status":"success","data":{"yaml":"alerting:\n  alert_relabel_configs:\n    - action: labeldrop\n      regex: replica\n"}}`))
			return
		}
		_, _ = w.Write([]byte(rules))
	}))
	defer server.Close()
	got, err := NewClient(Config{BaseURL: server.URL}).RuleDefinitionBounded(context.Background(), "prod-prom", "jobs", "Load", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Available || got.UnavailableReason != "unsupported_alert_relabeling" {
		t.Fatalf("definition = %+v", got)
	}
}

func TestRuleDefinitionBoundedRejectsRecordingRuleDependency(t *testing.T) {
	rules := `{"status":"success","data":{"groups":[{"name":"jobs","interval":15,"rules":[{"type":"recording","name":"job:cpu_load:avg5m","query":"avg_over_time(cpu_load[5m])"},{"type":"alerting","name":"Load","query":"job:cpu_load:avg5m > 5","labels":{}}]}]}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/status/config" {
			_, _ = w.Write([]byte(`{"status":"success","data":{"yaml":"global: {}\n"}}`))
			return
		}
		_, _ = w.Write([]byte(rules))
	}))
	defer server.Close()
	got, err := NewClient(Config{BaseURL: server.URL}).RuleDefinitionBounded(context.Background(), "prod-prom", "jobs", "Load", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Available || got.UnavailableReason != "unsupported_recording_dependency" {
		t.Fatalf("definition = %+v", got)
	}
}
