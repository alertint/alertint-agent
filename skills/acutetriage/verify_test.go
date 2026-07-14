// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"encoding/json"
	"testing"

	"github.com/alertint/alertint-agent/internal/store"
)

func alertWithLabels(labels map[string]string) store.Alert {
	return store.Alert{ID: "a1", Labels: labels}
}

// Floor: broad keys kept, narrow identity dropped (spec R2, grill resolution).
func TestParentScopeBroadKeys(t *testing.T) {
	alerts := []store.Alert{alertWithLabels(map[string]string{
		"namespace": "paysvc-sandbox-staging", "pod": "stolon-0", "instance": "10.0.0.1:9100",
	})}
	if got := parentScope(alerts); got != `{namespace="paysvc-sandbox-staging"}` {
		t.Fatalf("got %q", got)
	}
}

// Host-only alert → unscoped global ratio (spec R2).
func TestParentScopeInstanceOnlyIsUnscoped(t *testing.T) {
	alerts := []store.Alert{alertWithLabels(map[string]string{"instance": "10.0.0.1:9100"})}
	if got := parentScope(alerts); got != "" {
		t.Fatalf("want unscoped, got %q", got)
	}
}

// T1 half 1: the floor is always two queries, regardless of anything.
func TestFloorPlanAlways(t *testing.T) {
	alerts := []store.Alert{alertWithLabels(map[string]string{"instance": "x"})}
	fp := floorPlan(alerts)
	if len(fp) != 2 || fp[0].Kind != kindUpRatio || fp[1].Kind != kindIncidentsInWindow {
		t.Fatalf("unexpected floor: %+v", fp)
	}
	for _, q := range fp {
		if q.Source != "floor" {
			t.Fatalf("floor query mislabeled: %+v", q)
		}
	}
}

// T2: a malformed verification block degrades to nil (floor-only), never errors.
func TestParseVerificationPlanMalformed(t *testing.T) {
	raw := json.RawMessage(`{"analysis_name":"x","verification":{"queries":"not-a-list"}}`)
	if got := parseVerificationPlan(raw, 4, nil, "inc1"); got != nil {
		t.Fatalf("want nil on malformed, got %+v", got)
	}
}

// Cap + closed kind set: unknown kinds dropped, list capped at maxQueries (R3/R4).
func TestParseVerificationPlanCapAndKinds(t *testing.T) {
	raw := json.RawMessage(`{"verification":{"queries":[
		{"kind":"promql","expr":"q1"},{"kind":"sql","expr":"DROP TABLE"},
		{"kind":"promql","expr":"q2"},{"kind":"incidents_in_window","params":{"window_minutes":30}},
		{"kind":"promql","expr":"q3"},{"kind":"promql","expr":"q4"}]}}`)
	got := parseVerificationPlan(raw, 4, nil, "inc1")
	if len(got) != 4 {
		t.Fatalf("want 4 (capped, sql dropped), got %d: %+v", len(got), got)
	}
	for _, q := range got {
		if q.Kind == "sql" {
			t.Fatal("raw sql must be rejected at parse time (R4)")
		}
		if q.Source != "model" {
			t.Fatalf("model query mislabeled: %+v", q)
		}
	}
}
