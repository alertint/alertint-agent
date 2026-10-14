// SPDX-License-Identifier: FSL-1.1-ALv2

package ntfy

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestRenderCoverageExplainsStoredCauseWithoutModelSelection(t *testing.T) {
	for _, tc := range []struct {
		code              string
		returned, omitted int
		atLeast           bool
		want              []string
	}{
		{"truncated", 20, 1, true, []string{"series limit", "retained 20", "at least 1", "run:coverage"}},
		{"fact_bytes_capped", 76, 124, false, []string{"summary size limit", "16 KiB", "retained 76", "omitted 124", "run:coverage"}},
		{"response_too_large", 0, 0, false, []string{"response size limit", "1 MiB", "no usable metrics", "unknown", "run:coverage"}},
		{"response_too_large", 1, 0, false, []string{"response size limit", "retained 1", "other read", "run:coverage"}},
		{"rule_metrics_ambiguous_rule", 10, 0, false, []string{"ambiguous", "bounded scope", "run:coverage"}},
		{"diagnostics_withheld_by_budget", 1, 0, false, []string{"diagnostic", "request budget", "retained 1", "run:coverage"}},
	} {
		t.Run(fmt.Sprintf("%s_%d", tc.code, tc.returned), func(t *testing.T) {
			projection := map[string]any{"coverage_limitations": []any{map[string]any{"run_id": "run:coverage", "capability": "prometheus_query", "codes": []string{tc.code}, "returned": tc.returned, "omitted": tc.omitted, "omitted_at_least": tc.atLeast}}}
			encoded, _ := json.Marshal(projection)
			var tr model.Transition
			if err := json.Unmarshal(encoded, &tr.Projection); err != nil {
				t.Fatal(err)
			}
			tr.SituationID = "S-138"
			tr.Lifecycle = model.LifecycleActive
			msg := Render(tr, []string{"first_notification"}, false)
			for _, want := range tc.want {
				if !strings.Contains(strings.ToLower(msg.Body), strings.ToLower(want)) {
					t.Errorf("missing %q: %s", want, msg.Body)
				}
			}
			if tc.code == "response_too_large" && strings.Contains(msg.Body, "omitted 0") {
				t.Fatal("unknown omitted count reported as zero")
			}
		})
	}
}

func TestRenderLegacyCoverageDoesNotInventCause(t *testing.T) {
	tr := model.Transition{SituationID: "S-138", Lifecycle: model.LifecycleActive, Projection: model.ProjectionFacts{Assessment: &model.AssessmentConclusion{LimitationCodes: []string{"prometheus_query_truncated"}}}}
	msg := Render(tr, []string{"first_notification"}, false)
	if !strings.Contains(msg.Body, "cause unavailable") || strings.Contains(msg.Body, "series limit reached") {
		t.Fatalf("legacy warning must admit missing cause: %s", msg.Body)
	}
}

func TestCoverageEventSelectionUsesActualRunCauses(t *testing.T) {
	prior := model.Transition{Lifecycle: model.LifecycleActive}
	tr := prior
	tr.Projection.CoverageLimitations = []model.CoverageLimitation{{RunID: "run:new", Capability: "prometheus_query", Codes: []string{"fact_bytes_capped"}, Returned: 76, Omitted: 124}}
	events := Select(tr, &prior, true, []string{"coverage_degraded", "coverage_restored"})
	if len(events) != 1 || events[0] != "coverage_degraded" {
		t.Fatalf("degradation events=%v", events)
	}
	events = Select(prior, &tr, true, []string{"coverage_degraded", "coverage_restored"})
	if len(events) != 1 || events[0] != "coverage_restored" {
		t.Fatalf("restoration events=%v", events)
	}
}
