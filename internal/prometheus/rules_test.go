// SPDX-License-Identifier: FSL-1.1-ALv2

package prometheus

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestRecordingRules(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		want       map[string]string
		wantErr    bool
	}{
		{"recording only", `{"status":"success","data":{"groups":[{"name":"g","rules":[{"type":"recording","name":"service:errors","query":"sum(rate(errors_total[5m]))"},{"type":"alerting","name":"Failure","query":"service:errors > 1"}]}]}}`, 200, map[string]string{"service:errors": "sum(rate(errors_total[5m]))"}, false},
		{"unsupported", `{"status":"error","error":"not supported"}`, 404, nil, true},
		{"malformed", `{"status":"success","data":{"groups":42}}`, 200, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != "/api/v1/rules" || r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer test" || r.Header.Get("X-Scope-Orgid") != "tenant" {
					t.Errorf("unexpected rules request: %s %s headers=%v", r.Method, r.URL, r.Header)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			reader, ok := any(NewClient(Config{BaseURL: server.URL, BearerToken: "test", OrgID: "tenant"})).(interface {
				RecordingRules(ctx context.Context) (map[string]string, error)
			})
			if !ok {
				t.Fatal("client does not expose recording rules")
			}
			got, err := reader.RecordingRules(context.Background())
			if (err != nil) != tc.wantErr || !reflect.DeepEqual(got, tc.want) || calls != 1 {
				t.Fatalf("definitions=%v error=%v calls=%d; want %v error=%v", got, err, calls, tc.want, tc.wantErr)
			}
		})
	}
}

func TestRuleDefinitionObservedBoundedDoesNotSettleWhenReservationFails(t *testing.T) {
	rules := `{"status":"success","data":{"groups":[{"name":"jobs","interval":15,"rules":[{"type":"alerting","name":"Load","query":"up == 0","labels":{},"alerts":[]}]}]}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(rules))
	}))
	defer server.Close()

	reservationErr := errors.New("reservation denied")
	beforeCalls := 0
	afterCalls := 0
	_, err := NewClient(Config{BaseURL: server.URL}).RuleDefinitionObservedBounded(context.Background(), "prod-prom", "jobs", "Load", nil,
		func() error {
			beforeCalls++
			if beforeCalls == 2 {
				return reservationErr
			}
			return nil
		},
		func(started bool, err error) {
			afterCalls++
			if !started || err != nil {
				t.Fatalf("settled request = started %v err %v, want the successful first request", started, err)
			}
		})
	if !errors.Is(err, reservationErr) {
		t.Fatalf("error = %v, want reservation failure", err)
	}
	if beforeCalls != 2 || afterCalls != 1 {
		t.Fatalf("before calls = %d, after calls = %d; failed reservation must not settle an earlier request", beforeCalls, afterCalls)
	}
}

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
