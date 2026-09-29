// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"net/url"
	"reflect"
	"testing"
)

const case014RuleURL = `http://b253116d4b00:9090/graph?g0.expr=service%3Aspan_error_ratio%3A5m+%3E+0.05+and+sum+by+%28service_name%29+%28rate%28traces_span_metrics_calls_total%7Bspan_kind%3D%22SPAN_KIND_SERVER%22%7D%5B5m%5D%29%29+%3E+0.02&g0.tab=1`
const case014RuleExpr = `service:span_error_ratio:5m > 0.05 and sum by (service_name) (rate(traces_span_metrics_calls_total{span_kind="SPAN_KIND_SERVER"}[5m])) > 0.02`

func TestRuleExpressions(t *testing.T) {
	longExpr := make([]byte, 2049)
	for i := range longExpr {
		longExpr[i] = 'a'
	}
	urls := []string{
		case014RuleURL, case014RuleURL,
		"http://grafana/explore?expr=up",
		"http://prom/graph?g0.tab=1",
		"http://prom/graph?g0.expr=" + url.QueryEscape(string(longExpr)),
		"http://prom/graph?g0.expr=" + url.QueryEscape("sum("),
		"http://prom/graph?g0.expr=" + url.QueryEscape("up"),
		"http://prom/graph?g0.expr=" + url.QueryEscape("rate(http_requests_total[5m])"),
		"http://prom/graph?g0.expr=" + url.QueryEscape("node_cpu_seconds_total"),
	}
	want := []string{"node_cpu_seconds_total", "rate(http_requests_total[5m])", case014RuleExpr}
	if got := ruleExpressions(urls); !reflect.DeepEqual(got, want) {
		t.Fatalf("ruleExpressions = %v, want %v", got, want)
	}
}
