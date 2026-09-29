// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/logs"
	"github.com/alertint/alertint-agent/internal/store"
)

func clusterAlerts() []store.Alert {
	return []store.Alert{
		{Labels: map[string]string{
			"alertname": "CheckoutHighErrorRate", "cluster": "eu-west",
			"namespace": "payments", "service": "checkout", "severity": "critical",
		}},
		{Labels: map[string]string{
			"alertname": "CheckoutHighErrorRate", "cluster": "eu-west",
			"namespace": "payments", "service": "checkout", "severity": "critical",
		}},
	}
}

func TestAllowedSelectorKeys_ExtendsBuiltins(t *testing.T) {
	got := allowedSelectorKeys([]string{"cluster", "region"})
	want := append(append([]string{}, logs.AllowedSelectorKeys...), "cluster", "region")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	// nil extras must not alias or mutate the built-in slice
	if !reflect.DeepEqual(allowedSelectorKeys(nil), logs.AllowedSelectorKeys) {
		t.Fatal("nil extras must yield exactly the built-in allowlist")
	}
}

func TestTranslateSelector(t *testing.T) {
	sel := map[string][]string{"service": {"payment", "checkout"}, "service_name": {"payment"}, "job": {"api"}}
	want := map[string][]string{"service_name": {"checkout", "payment"}}
	got := translateSelector(sel, map[string]string{"service": "service_name", "job": ""})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("translateSelector = %v, want %v", got, want)
	}
	cloned := translateSelector(sel, nil)
	if !reflect.DeepEqual(cloned, sel) {
		t.Fatalf("nil map changed selector: %v", cloned)
	}
	cloned["service"][0] = "changed"
	if sel["service"][0] == "changed" {
		t.Fatal("translation aliased input values")
	}
}

func TestRenderPhysicalCore_KeepsMappedSource(t *testing.T) {
	shared := map[string][]string{"service": {"payment"}, "job": {"api"}}
	got := renderPhysicalCore(shared, nil, map[string]string{"service": "service_name"})
	if got != `{service_name="payment"}` {
		t.Fatalf("physical core = %q", got)
	}
}

func TestRenderPhysicalCore_KeepsMappedTarget(t *testing.T) {
	shared := map[string][]string{"service": {"payment"}, "job": {"api"}, "namespace": {"prod"}, "noise": {"x"}}
	got := renderPhysicalCore(shared, nil, map[string]string{"service": "job"})
	if got != `{job=~"api|payment",namespace="prod"}` {
		t.Fatalf("physical core = %q", got)
	}
}

func TestParentScope_LabelMap(t *testing.T) {
	got := parentScope([]store.Alert{alertWithLabels(map[string]string{"service": "payment"})}, nil, map[string]string{"service": "service_name"})
	if got != `{service_name="payment"}` {
		t.Fatalf("parent scope = %q", got)
	}
}

func TestBuildMetricSelector_ExtraIncluded(t *testing.T) {
	sel := buildMetricSelector(clusterAlerts(), []string{"cluster"})
	if !reflect.DeepEqual(sel["cluster"], []string{"eu-west"}) {
		t.Fatalf("cluster missing from selector: %v", sel)
	}
	if _, ok := sel["severity"]; ok {
		t.Fatalf("alert-metadata key leaked into selector: %v", sel)
	}
}

func TestBuildMetricSelector_NoExtras_Unchanged(t *testing.T) {
	sel := buildMetricSelector(clusterAlerts(), nil)
	if _, ok := sel["cluster"]; ok {
		t.Fatalf("cluster must be dropped without extras: %v", sel)
	}
}

func TestBuildLogSelector_ExtraIncluded(t *testing.T) {
	sel := buildLogSelector(clusterAlerts(), []string{"cluster"})
	if !reflect.DeepEqual(sel.Labels["cluster"], []string{"eu-west"}) {
		t.Fatalf("cluster missing from log selector: %v", sel.Labels)
	}
}

func TestRenderPhysicalCore_KeepsExtras(t *testing.T) {
	shared := map[string][]string{
		"cluster":   {"eu-west"},
		"namespace": {"payments"},
		"service":   {"checkout"}, // logical: shed by the retry
	}
	got := renderPhysicalCore(shared, []string{"cluster"}, nil)
	want := `{cluster="eu-west",namespace="payments"}`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestRenderPhysicalCore_NoLogicalKey_NoRetry(t *testing.T) {
	// Nothing to shed (cluster is an extra, namespace physical) → "" means
	// "retry would equal the primary, skip it".
	shared := map[string][]string{"cluster": {"eu-west"}, "namespace": {"payments"}}
	if got := renderPhysicalCore(shared, []string{"cluster"}, nil); got != "" {
		t.Fatalf("want no-op retry, got %q", got)
	}
}

func TestInstanceSupplements_ExtrasANDed(t *testing.T) {
	alerts := []store.Alert{
		{Labels: map[string]string{"instance": "10.0.4.7:9100", "cluster": "eu-west"}},
	}
	got := instanceSupplements(alerts, map[string][]string{"cluster": {"eu-west"}}, nil)
	want := []string{`{cluster="eu-west",instance="10.0.4.7:9100"}`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestInstanceSupplements_NoExtras_Bare(t *testing.T) {
	alerts := []store.Alert{
		{Labels: map[string]string{"instance": "10.0.4.7:9100"}},
	}
	got := instanceSupplements(alerts, nil, nil)
	want := []string{`{instance="10.0.4.7:9100"}`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestInstanceSupplements_DroppedInstanceHasNoEmptyQuery(t *testing.T) {
	alerts := []store.Alert{alertWithLabels(map[string]string{"instance": "db-01:9100"})}
	if got := instanceSupplements(alerts, nil, map[string]string{"instance": ""}); len(got) != 0 {
		t.Fatalf("dropped instance produced supplement %v", got)
	}
}

func TestExtraSelectorValues_PicksOnlyExtras(t *testing.T) {
	shared := map[string][]string{"cluster": {"eu-west"}, "namespace": {"payments"}}
	got := extraSelectorValues(shared, []string{"cluster"})
	want := map[string][]string{"cluster": {"eu-west"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestParentScope_ExtraIncluded(t *testing.T) {
	got := parentScope(clusterAlerts(), []string{"cluster"}, nil)
	want := `{cluster="eu-west",namespace="payments",service="checkout"}`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestParentScope_NoExtras_Unchanged(t *testing.T) {
	got := parentScope(clusterAlerts(), nil, nil)
	want := `{namespace="payments",service="checkout"}`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

// The invariant end-to-end (ADR-0035): primary matches nothing, the retry
// still carries the extra.
func TestFetchMetrics_RetryKeepsExtra(t *testing.T) {
	q := &fakeProm{}
	params := MetricParams{TimeoutSeconds: 5, ExtraSelectorLabels: []string{"cluster"}}
	FetchMetrics(context.Background(), q, params, nil, clusterAlerts(), time.Now(), "inc-1", nil)
	if len(q.calls) != 2 {
		t.Fatalf("want primary + retry, got %d queries: %v", len(q.calls), q.calls)
	}
	if want := `{cluster="eu-west",namespace="payments",service="checkout"}`; q.calls[0] != want {
		t.Fatalf("primary: got %q want %q", q.calls[0], want)
	}
	if want := `{cluster="eu-west",namespace="payments"}`; q.calls[1] != want {
		t.Fatalf("retry must keep the extra: got %q want %q", q.calls[1], want)
	}
}
