// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"testing"

	"github.com/alertint/alertint-agent/internal/store"
)

func alert(labels map[string]string) store.Alert { return store.Alert{Labels: labels} }

func TestRenderPromMatcher_EqualityAndRegexEscaping(t *testing.T) {
	// Single value → equality, quoted verbatim (AE2).
	sel := map[string][]string{"instance": {"db-01:9100"}}
	if got := renderPromMatcher(sel); got != `{instance="db-01:9100"}` {
		t.Errorf("equality: got %q", got)
	}
	// Two values → anchored regex alternation, regex metacharacters escaped (AE2).
	sel = map[string][]string{"instance": {"db-01:9100", "10.0.0.2:9100"}}
	// Sorted, QuoteMeta escapes dots; %q escapes the backslashes for the PromQL string.
	if got := renderPromMatcher(sel); got != `{instance=~"10\\.0\\.0\\.2:9100|db-01:9100"}` {
		t.Errorf("regex: got %q", got)
	}
}

func TestBuildMetricSelector_AllowlistIntersectionUnioned(t *testing.T) {
	alerts := []store.Alert{
		alert(map[string]string{"namespace": "checkout", "pod": "api-7f9x", "severity": "critical"}),
		alert(map[string]string{"namespace": "checkout", "pod": "api-2a1b", "severity": "warning"}),
	}
	sel := buildMetricSelector(alerts)
	// severity is not allowlisted → dropped; pod present on both, values unioned.
	if _, ok := sel["severity"]; ok {
		t.Error("severity must be dropped (not allowlisted)")
	}
	if got := renderPromMatcher(sel); got != `{namespace="checkout",pod=~"api-2a1b|api-7f9x"}` {
		t.Errorf("got %q", got)
	}
}

func TestInstanceSupplements_PerUniqueInstance(t *testing.T) {
	alerts := []store.Alert{
		alert(map[string]string{"instance": "db-01:9100", "job": "node"}),
		alert(map[string]string{"instance": "db-01:9100", "job": "node"}), // dup
		alert(map[string]string{"instance": "10.0.0.2:9100"}),
	}
	got := instanceSupplements(alerts)
	// One matcher per UNIQUE instance, each a bare {instance="X"} (AE7).
	want := []string{`{instance="db-01:9100"}`, `{instance="10.0.0.2:9100"}`}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	seen := map[string]bool{}
	for _, s := range got {
		seen[s] = true
	}
	for _, w := range want {
		if !seen[w] {
			t.Errorf("missing supplement %q in %v", w, got)
		}
	}
}

func TestRenderPhysicalCore_DropsLogicalKeys(t *testing.T) {
	// service is logical and exists on no series → physical-core drops it (AE8).
	shared := map[string][]string{"namespace": {"checkout"}, "pod": {"api-7f9x"}, "service": {"checkout-api"}}
	if got := renderPhysicalCore(shared); got != `{namespace="checkout",pod="api-7f9x"}` {
		t.Errorf("got %q", got)
	}
	// No logical key → no distinct retry.
	if got := renderPhysicalCore(map[string][]string{"namespace": {"checkout"}}); got != "" {
		t.Errorf("no-logical-key must yield empty retry, got %q", got)
	}
}
