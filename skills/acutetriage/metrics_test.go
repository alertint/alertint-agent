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
