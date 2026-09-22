// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"
	"time"
)

// Lab 2026-09-11: assessment ran during collection; readiness alone did not
// change its coverage hashes. No investigation had ever run.
func TestOperatorOutcomeAssessmentCoverageIsNotInvestigation(t *testing.T) {
	in := triageDecideInput(t)
	snap := BuildSnapshot(in)
	prior := trustworthyPriorCovering(t, snap, in)
	in.CurrentAssessment = &prior
	got := DecideTriage(snap, in, in.Now)
	if len(got) != 1 || got[0].Decision != TriageDecisionRequest {
		t.Fatalf("fresh incident with no investigation was skipped: %+v", got)
	}
}

func TestOperatorOutcomeSkipRequiresMatchingAcceptedInvestigation(t *testing.T) {
	for _, kind := range []string{"accepted", "missing digest", "unmatched", "empty", "different inputs", "unresolved delivery"} {
		t.Run(kind, func(t *testing.T) {
			in := triageDecideInput(t)
			at := in.Now.Add(-time.Minute)
			ids := make([]string, 0, len(in.Deliveries))
			for _, d := range in.Deliveries {
				ids = append(ids, d.ID)
			}
			e := &TriageExecution{AttemptID: "attempt-1", ResultCode: "success", OutputDigest: "digest", CompletedAt: &at, MemberDeliveryIDs: ids,
				Evidence: &TriageCompletionEvidence{Hypothesis: "Payment failures", Observations: []string{"Payment errors in logs"}}}
			switch kind {
			case "missing digest":
				e.OutputDigest = ""
			case "unmatched":
				e.Evidence = nil
			case "empty":
				e.Evidence = &TriageCompletionEvidence{}
			case "different inputs":
				d := in.Deliveries[0]
				d.ID = "new-delivery"
				d.AlertID = "new-alert"
				in.Deliveries = append(in.Deliveries, d)
			case "unresolved delivery":
				e.MemberDeliveryIDs = append(e.MemberDeliveryIDs, "missing")
			}
			in.Incidents[0].Triage.LastExecution = e
			snap := BuildSnapshot(in)
			prior := trustworthyPriorCovering(t, snap, in)
			in.CurrentAssessment = &prior
			got := DecideTriage(snap, in, in.Now)
			want := TriageDecisionRequest
			if kind == "accepted" {
				want = TriageDecisionSkip
			}
			if len(got) != 1 || got[0].Decision != want {
				t.Fatalf("%s: %+v; want %s", kind, got, want)
			}
		})
	}
}
