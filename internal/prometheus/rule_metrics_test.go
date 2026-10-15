// SPDX-License-Identifier: FSL-1.1-ALv2

package prometheus

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestAlertRuleMetricsRequiresUniqueRuleAndExactMetricNames(t *testing.T) {
	for _, tc := range []struct {
		name, query, alerts, extra string
		want                       []string
		reason                     string
	}{
		{name: "compound expression", query: `sum(rate(errors_total{job="windows"}[5m])) / requests_total > 0.1`, want: []string{"errors_total", "requests_total"}},
		{name: "exact name matcher", query: `{__name__="replication_failed"} == 1`, want: []string{"replication_failed"}},
		{name: "invalid expression", query: `sum(`, reason: "unsupported_expression"},
		{name: "anonymous name regex", query: `{__name__=~"windows_.*"} > 0`, reason: "unsupported_expression"},
		{name: "scalar only", query: `vector(1)`, reason: "unsupported_expression"},
		{name: "duplicate rule", query: `replication_failed > 0`, extra: `,{"name":"other","rules":[{"type":"alerting","name":"ReplicationFailed","query":"other > 0"}]}`, reason: "ambiguous_rule"},
		{name: "wrong partition is advisory", query: `replication_failed > 0`, alerts: `[{"state":"firing","labels":{"job":"windows","instance":"exchange01","cluster":"other"}}]`, want: []string{"replication_failed"}, reason: "current_definition_hint"},
		{name: "no firing member is advisory", query: `replication_failed > 0`, alerts: `[]`, want: []string{"replication_failed"}, reason: "current_definition_hint"},
		{name: "pending member is advisory", query: `replication_failed > 0`, alerts: `[{"state":"pending","labels":{"job":"windows","instance":"exchange01","cluster":"prod"}}]`, want: []string{"replication_failed"}, reason: "current_definition_hint"},
		{name: "inactive recording dependency still falls back", query: `service:errors > 0`, alerts: `[]`, extra: `,{"name":"recorded","rules":[{"type":"recording","name":"service:errors","query":"sum(errors_total)"}]}`, reason: "recording_dependency"},
		{name: "inactive unsupported expression still falls back", query: `{__name__=~"windows_.*"} > 0`, alerts: `[]`, reason: "unsupported_expression"},
		{name: "recording dependency", query: `service:errors > 0`, extra: `,{"name":"recorded","rules":[{"type":"recording","name":"service:errors","query":"sum(errors_total)"}]}`, reason: "recording_dependency"},
		{name: "metric text in string is not a reference", query: `label_replace(up,"note","service:errors","job",".*")`, extra: `,{"name":"recorded","rules":[{"type":"recording","name":"service:errors","query":"sum(errors_total)"}]}`, want: []string{"up"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			alerts := tc.alerts
			if alerts == "" {
				alerts = `[{"state":"firing","labels":{"job":"windows","instance":"exchange01","cluster":"prod"}}]`
			}
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != "/api/v1/rules" || r.Header.Get("X-Scope-Orgid") != "tenant" {
					t.Errorf("unexpected request %s", r.URL)
				}
				_, _ = fmt.Fprintf(w, `{"status":"success","data":{"groups":[{"name":"exchange","rules":[{"type":"alerting","name":"ReplicationFailed","query":%q,"alerts":%s}]}%s]}}`, tc.query, alerts, tc.extra)
			}))
			defer srv.Close()
			reader, ok := any(NewClient(Config{BaseURL: srv.URL, OrgID: "tenant"})).(interface {
				AlertRuleMetrics(ctx context.Context, alertName string, scope map[string]string) ([]string, string, error)
			})
			if !ok {
				t.Fatal("bounded alert rule metric discovery is missing")
			}
			names, reason, err := reader.AlertRuleMetrics(context.Background(), "ReplicationFailed", map[string]string{"job": "windows", "instance": "exchange01", "cluster": "prod"})
			if err != nil || !reflect.DeepEqual(names, tc.want) || reason != tc.reason || calls != 1 {
				t.Fatalf("names=%v reason=%q err=%v calls=%d; want %v %q and one request", names, reason, err, calls, tc.want, tc.reason)
			}
		})
	}
}
