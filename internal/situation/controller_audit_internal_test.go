// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Task 9: direct, package-internal proof of the derivation -> spec.md-named
// audit event mapping (assessmentAuditKind) and the commit-success audit
// emission (auditCommitSuccess). Driven directly rather than only through a
// full Reconcile fixture, since both are unexported and the mapping itself
// is the load-bearing behavior — a full Reconcile-level proof for the
// dispatch/rejected/failed/stale/reused/requested events lives in
// controller_audit_test.go (package situation_test), reusing controller_test.go's
// own established fixtures end to end.
// ----------------------------------------------------------------------

type auditRecord struct {
	actor, kind string
	payload     any
}

type recordingAuditSink struct {
	records []auditRecord
}

func (s *recordingAuditSink) Append(_ context.Context, actor, kind string, payload any) error {
	s.records = append(s.records, auditRecord{actor: actor, kind: kind, payload: payload})
	return nil
}

func (s *recordingAuditSink) kinds() []string {
	out := make([]string, len(s.records))
	for i, r := range s.records {
		out[i] = r.kind
	}
	return out
}

func TestAssessmentAuditKindMapsEveryDerivationToItsSpecName(t *testing.T) {
	cases := []struct {
		derivation model.AssessmentDerivation
		wantKind   string
		wantOK     bool
	}{
		{model.DerivationModelValidated, "situation.assessment_authoritative", true},
		{model.DerivationDeterministic, "situation.assessment_authoritative", true},
		{model.DerivationDeterministicFallback, "situation.assessment_fallback", true},
		{model.DerivationRevalidatedReuse, "situation.assessment_reused", true},
		{model.AssessmentDerivation("bogus"), "", false},
		{model.AssessmentDerivation(""), "", false},
	}
	for _, tc := range cases {
		kind, ok := assessmentAuditKind(tc.derivation)
		if ok != tc.wantOK || kind != tc.wantKind {
			t.Fatalf("assessmentAuditKind(%q) = (%q, %v), want (%q, %v)", tc.derivation, kind, ok, tc.wantKind, tc.wantOK)
		}
	}
}

// TestAuditCommitSuccessEmitsExactlyOneAssessmentEventForANewAttempt proves
// a commit carrying a fresh authoritative attempt emits exactly one of
// spec.md's three named assessment events, with the stable attribute keys
// spec.md's OTel/log requirement names (Situation ID, attempt ID, input
// version, and the material/basis-hash digests) — never a proposal, prompt,
// or provider body.
func TestAuditCommitSuccessEmitsExactlyOneAssessmentEventForANewAttempt(t *testing.T) {
	sink := &recordingAuditSink{}
	c := NewController(nil, nil, ControllerConfig{}, nil, sink, nil)
	claim := Claim{Situation: model.Situation{ID: "sit-1"}}
	commit := ControllerCommit{
		Attempt: AssessmentAttempt{
			ID: "attempt-1", Derivation: model.DerivationModelValidated, InputVersion: 3,
			CreatedAt: time.Unix(0, 0), CompletedAt: time.Unix(1, 0),
		},
		MaterialFactHash: "mat-1", AssessmentBasisHash: "basis-1",
	}

	c.auditCommitSuccess(context.Background(), claim, commit)

	if len(sink.records) != 1 {
		t.Fatalf("audit records = %+v, want exactly 1", sink.records)
	}
	if sink.records[0].kind != "situation.assessment_authoritative" {
		t.Fatalf("kind = %q, want situation.assessment_authoritative", sink.records[0].kind)
	}
	payload, ok := sink.records[0].payload.(map[string]any)
	if !ok {
		t.Fatalf("payload type = %T, want map[string]any", sink.records[0].payload)
	}
	for _, key := range []string{
		"situation_id", "attempt_id", "input_version", "derivation",
		"material_fact_hash", "assessment_basis_hash", "duration_ms",
	} {
		if _, ok := payload[key]; !ok {
			t.Fatalf("payload missing key %q: %+v", key, payload)
		}
	}
	if payload["situation_id"] != "sit-1" || payload["attempt_id"] != "attempt-1" {
		t.Fatalf("payload identity = %+v, want situation_id=sit-1 attempt_id=attempt-1", payload)
	}
}

// TestAuditCommitSuccessEmitsNoAssessmentEventForAProjectionOnlyCommit
// proves a cycle that produces no NEW authoritative attempt row (Attempt.ID
// == "" — a still-parked cycle, or a preserve/blocked bounded-projection
// refresh) spends no assessment audit event: spec.md's "reconciliation
// churn within an unchanged basis does not spend a model call" correctly
// extends to not spending an audit event announcing a judgment that never
// happened.
func TestAuditCommitSuccessEmitsNoAssessmentEventForAProjectionOnlyCommit(t *testing.T) {
	sink := &recordingAuditSink{}
	c := NewController(nil, nil, ControllerConfig{}, nil, sink, nil)
	claim := Claim{Situation: model.Situation{ID: "sit-1"}}

	c.auditCommitSuccess(context.Background(), claim, ControllerCommit{})

	if len(sink.records) != 0 {
		t.Fatalf("audit records = %+v, want none", sink.records)
	}
}

// TestAuditCommitSuccessEmitsTriageRequestedAndSkippedPerDecision proves
// every Triage decision sharing this commit gets its own event — request ->
// situation.triage_requested, skip -> situation.triage_skipped — carrying
// Incident ID, input version, and the covered digests spec.md's
// OTel/log-attribute requirement names.
func TestAuditCommitSuccessEmitsTriageRequestedAndSkippedPerDecision(t *testing.T) {
	sink := &recordingAuditSink{}
	c := NewController(nil, nil, ControllerConfig{}, nil, sink, nil)
	claim := Claim{Situation: model.Situation{ID: "sit-1"}}
	commit := ControllerCommit{
		TriageDecisions: []TriageDecision{
			{
				IncidentID: "inc-a", Decision: TriageDecisionRequest, DecisionReason: DecisionReasonNoTrustworthyAssessment,
				SituationInputVersion: 4, MaterialFactHash: "mat-a", MembershipDigest: "mem-a", IncidentInputDigest: "inp-a",
			},
			{
				IncidentID: "inc-b", Decision: TriageDecisionSkip, DecisionReason: DecisionReasonCleanSkip,
				SituationInputVersion: 4, MaterialFactHash: "mat-b", MembershipDigest: "mem-b", IncidentInputDigest: "inp-b",
			},
		},
	}

	c.auditCommitSuccess(context.Background(), claim, commit)

	if got := sink.kinds(); len(got) != 2 || got[0] != "situation.triage_requested" || got[1] != "situation.triage_skipped" {
		t.Fatalf("kinds = %v, want [situation.triage_requested situation.triage_skipped]", got)
	}
	requested, ok := sink.records[0].payload.(map[string]any)
	if !ok {
		t.Fatalf("requested payload type = %T", sink.records[0].payload)
	}
	for _, key := range []string{"situation_id", "incident_id", "input_version", "decision_reason", "material_fact_hash", "membership_digest", "incident_input_digest"} {
		if _, ok := requested[key]; !ok {
			t.Fatalf("requested payload missing key %q: %+v", key, requested)
		}
	}
	if requested["incident_id"] != "inc-a" {
		t.Fatalf("requested incident_id = %v, want inc-a", requested["incident_id"])
	}
	skipped, ok := sink.records[1].payload.(map[string]any)
	if !ok {
		t.Fatalf("skipped payload type = %T", sink.records[1].payload)
	}
	if skipped["incident_id"] != "inc-b" {
		t.Fatalf("skipped incident_id = %v, want inc-b", skipped["incident_id"])
	}
}
