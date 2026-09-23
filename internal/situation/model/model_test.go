// SPDX-License-Identifier: FSL-1.1-ALv2

package model

import "testing"

// TestDueReasonValidate proves DueReason's closed set accepts Plan 2's
// eighteen values plus R5's DueOperatorArtifactRecorded, and rejects the
// near-miss "operator_artifact" and other unknown strings. The
// due_reasons_json SQL CHECK (internal/store/migrations/0014_situation_foundation.sql)
// only checks that the column is a JSON array — this validator is the
// actual gate on the closed value vocabulary.
func TestDueReasonValidate(t *testing.T) {
	valid := []DueReason{
		DueIncidentCreated, DueMembershipChanged, DueNewSymptom, DueAlertResolved, DueAlertRefired,
		DueDurationMilestone, DueConnectorHealthChanged, DueSemanticProfileChanged, DueTriageChanged,
		DueOperatorJudgment, DueEnvelopeChanged, DueEnvelopeBoundary, DueJudgmentBoundary,
		DueManualReassessment, DueRecoveryGraceExpired, DueObservationDeadline, DueRetry,
		DueUpgradeReconstruction, DueOperatorArtifactRecorded,
	}
	if len(valid) != 19 {
		t.Fatalf("expected 19 closed DueReason values (Plan 2's 18 + R5), got %d", len(valid))
	}
	for _, v := range valid {
		if err := v.Validate(); err != nil {
			t.Errorf("valid due reason %q: unexpected error: %v", v, err)
		}
	}

	bogus := []DueReason{"operator_artifact", "operator_judgment_needed", "bogus", ""}
	for _, v := range bogus {
		if err := v.Validate(); err == nil {
			t.Errorf("bogus due reason %q: want error, got nil", v)
		}
	}
}
