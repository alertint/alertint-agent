// SPDX-License-Identifier: FSL-1.1-ALv2

package situation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
)

// ----------------------------------------------------------------------
// Task 9: TriageWorker's own dispatch/outcome audit trail
// (incident.triage_attempt/triage_stale_input/triage_completed/
// triage_exhausted — spec.md's own named events). SetAuditSink is an
// optional post-construction setter (mirrors ControllerWorker.
// SetDependencyRecoveryWaker), so every existing newWorker/newWorkerFull
// call site keeps working unchanged; these tests wire it explicitly.
// ----------------------------------------------------------------------

// TestTriageWorkerAuditsAttemptDispatchedThenCompleted mirrors
// TestTriageWorker_CurrentCompatibleSuccess's exact scenario and proves it
// audits incident.triage_attempt (the consumed dispatch slot) then
// incident.triage_completed — never triage_stale_input or triage_exhausted.
func TestTriageWorkerAuditsAttemptDispatchedThenCompleted(t *testing.T) {
	claim := testClaim("inc-audit-1", 1)
	store := &fakeStore{claimFn: func(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (situation.TriageAttemptClaim, error) {
		return claim, nil
	}}
	lister := &fakeLister{ids: []string{"inc-audit-1"}}
	analyzer := &fakeAnalyzer{fn: func(ctx context.Context, c situation.TriageAttemptClaim) (situation.AcuteResult, error) {
		return situation.AcuteResult{IncidentID: c.IncidentID, EvidencePackDigest: "sha256:pack"}, nil
	}}
	w := newWorker(store, lister, analyzer, &fakeAfterCommit{}, situation.TriageWorkerConfig{})
	audit := &fakeAuditSink{}
	w.SetAuditSink(audit)

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	if got := audit.kinds; len(got) != 2 || got[0] != "incident.triage_attempt" || got[1] != "incident.triage_completed" {
		t.Fatalf("audit kinds = %v, want [incident.triage_attempt incident.triage_completed]", got)
	}
	payload, ok := audit.payloads[0].(map[string]any)
	if !ok {
		t.Fatalf("payload type = %T", audit.payloads[0])
	}
	for _, key := range []string{"situation_id", "incident_id", "attempt_id", "attempt_number", "input_version", "membership_digest", "incident_input_digest"} {
		if _, ok := payload[key]; !ok {
			t.Fatalf("attempt payload missing key %q: %+v", key, payload)
		}
	}
	completed, ok := audit.payloads[1].(map[string]any)
	if !ok {
		t.Fatalf("payload type = %T", audit.payloads[1])
	}
	for _, key := range []string{"situation_id", "incident_id", "attempt_id", "input_version", "evidence_pack_digest", "duration_ms"} {
		if _, ok := completed[key]; !ok {
			t.Fatalf("completed payload missing key %q: %+v", key, completed)
		}
	}
}

// TestTriageWorkerAuditsStaleInputNotCompleted mirrors
// TestTriageWorker_StaleMembership's exact scenario and proves it audits
// incident.triage_stale_input, never incident.triage_completed.
func TestTriageWorkerAuditsStaleInputNotCompleted(t *testing.T) {
	claim := testClaim("inc-audit-2", 1)
	store := &fakeStore{
		claimFn: func(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (situation.TriageAttemptClaim, error) {
			return claim, nil
		},
		completeFn: func(ctx context.Context, attemptID, incidentID string, finding situation.TriageFindingInput, now time.Time) (situation.TriageCompletionOutcome, error) {
			return situation.TriageCompletionStaleMembership, nil
		},
	}
	lister := &fakeLister{ids: []string{"inc-audit-2"}}
	w := newWorker(store, lister, &fakeAnalyzer{}, &fakeAfterCommit{}, situation.TriageWorkerConfig{})
	audit := &fakeAuditSink{}
	w.SetAuditSink(audit)

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	if !audit.has("incident.triage_stale_input") {
		t.Fatalf("audit kinds = %v, want incident.triage_stale_input", audit.kinds)
	}
	if audit.has("incident.triage_completed") {
		t.Fatalf("audit kinds = %v, want no triage_completed for a stale outcome", audit.kinds)
	}
}

// TestTriageWorkerAuditsExhaustionOnFifthAttempt mirrors
// TestTriageWorker_FifthAttemptExhaustion's exact scenario and proves it
// audits incident.triage_exhausted after the durable exhaust write commits.
func TestTriageWorkerAuditsExhaustionOnFifthAttempt(t *testing.T) {
	claim := testClaim("inc-audit-3", 5)
	store := &fakeStore{claimFn: func(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (situation.TriageAttemptClaim, error) {
		return claim, nil
	}}
	lister := &fakeLister{ids: []string{"inc-audit-3"}}
	analyzer := &fakeAnalyzer{fn: func(ctx context.Context, c situation.TriageAttemptClaim) (situation.AcuteResult, error) {
		return situation.AcuteResult{}, errors.New("still failing")
	}}
	w := newWorkerFull(store, lister, analyzer, &fakeAfterCommit{}, &fakeExhaustionNotifier{}, situation.TriageWorkerConfig{MaxAttempts: 5})
	audit := &fakeAuditSink{}
	w.SetAuditSink(audit)

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	if !audit.has("incident.triage_exhausted") {
		t.Fatalf("audit kinds = %v, want incident.triage_exhausted", audit.kinds)
	}
}

// TestTriageWorkerNilAuditSinkIsANoOp proves a TriageWorker with no audit
// sink wired (the default — SetAuditSink never called) runs exactly as
// before: no panic, no behavior change.
func TestTriageWorkerNilAuditSinkIsANoOp(t *testing.T) {
	claim := testClaim("inc-audit-4", 1)
	store := &fakeStore{claimFn: func(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (situation.TriageAttemptClaim, error) {
		return claim, nil
	}}
	lister := &fakeLister{ids: []string{"inc-audit-4"}}
	analyzer := &fakeAnalyzer{fn: func(ctx context.Context, c situation.TriageAttemptClaim) (situation.AcuteResult, error) {
		return situation.AcuteResult{IncidentID: c.IncidentID}, nil
	}}
	w := newWorker(store, lister, analyzer, &fakeAfterCommit{}, situation.TriageWorkerConfig{})

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
}
