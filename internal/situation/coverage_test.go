// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestAuthoritativeChangeFreezesActualCoverageIndependentOfAssessment(t *testing.T) {
	now := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	basis := historyBasis{Now: now, Snap: Snapshot{CapabilityResults: []CapabilityResult{{RunID: "run:original", Capability: "prometheus_query", Subject: "exchange01", Status: "truncated", Returned: 76, Omitted: 124, LimitationCodes: []string{"fact_bytes_capped"}}}}}
	change := authoritativeChangeOf(Claim{}, basis, ControllerCommit{})
	encoded, err := json.Marshal(change.Projection)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"coverage_limitations"`, `"run_id":"run:original"`, `"fact_bytes_capped"`, `"returned":76`, `"omitted":124`} {
		if !strings.Contains(string(encoded), want) {
			t.Errorf("missing %s: %s", want, encoded)
		}
	}
}

func TestCoverageTransitionsTrackCauseChangesButIgnoreProvenanceChurn(t *testing.T) {
	limited := []model.CoverageLimitation{{RunID: "run:old", Capability: "prometheus_query", Codes: []string{"fact_bytes_capped"}, Returned: 76, Omitted: 124}}
	for _, tc := range []struct {
		name          string
		before, after []model.CoverageLimitation
		count         int
	}{
		{"degraded", nil, limited, 1},
		{"restored", limited, nil, 1},
		{"new cause", limited, []model.CoverageLimitation{{RunID: "run:new", Capability: "prometheus_query", Codes: []string{"response_too_large"}}}, 1},
		{"new run same cause", limited, []model.CoverageLimitation{{RunID: "run:new", Capability: "prometheus_query", Codes: []string{"fact_bytes_capped"}, Returned: 75, Omitted: 125}}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := hsNext(t)
			c.PriorTransition.Projection.CoverageLimitations = tc.before
			c.Projection.CoverageLimitations = tc.after
			transitions, err := BuildTransitions(c)
			if err != nil || len(transitions) != tc.count {
				t.Fatalf("transitions=%v err=%v want=%d", transitions, err, tc.count)
			}
		})
	}
}

func TestCoverageCountsAreLowerBoundsWhenOtherReadsAreUnknown(t *testing.T) {
	results := []CapabilityResult{{RunID: "run:partial", Capability: "prometheus_query", Returned: 2, Omitted: 3, LimitationCodes: []string{"fact_bytes_capped", "response_too_large"}}}
	rows := coverageLimitationsOf(results)
	if len(rows) != 1 || !rows[0].OmittedAtLeast {
		t.Fatalf("partial omissions must be a lower bound: %+v", rows)
	}
}

func TestCoverageCurrentRuleHintDoesNotClaimFailedFallback(t *testing.T) {
	p := model.ProjectionFacts{CoverageLimitations: []model.CoverageLimitation{{
		RunID: "run:hint", Capability: "prometheus_query", Codes: []string{"rule_metrics_current_definition_hint"}, Returned: 4,
	}}}
	text := strings.Join(CoverageLimitationLines(p), " ")
	if strings.Contains(text, "unavailable") || strings.Contains(text, "used bounded scope metrics as fallback") || !strings.Contains(text, "advisory") || !strings.Contains(text, "historical") {
		t.Fatalf("current-rule hint must be advisory provenance, not a failed read or historical proof: %s", text)
	}
}
