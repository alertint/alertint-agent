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

// countKind returns how many of sink's recorded audit rows carry kind —
// TestTriageWorkerAuditsExhaustionOnFifthAttempt's own exactly-once proof
// needs a count, not merely fakeAuditSink.has's boolean "at least one".
func countKind(sink *fakeAuditSink, kind string) int {
	n := 0
	for _, k := range sink.kinds {
		if k == kind {
			n++
		}
	}
	return n
}

// TestTriageWorkerAuditsExhaustionOnFifthAttempt mirrors
// TestTriageWorker_FifthAttemptExhaustion's exact scenario and proves the
// worker itself unconditionally emits exactly one incident.triage_exhausted
// audit row, carrying the full identity (situation_id/attempt_id/
// attempt_number/input_version) — in the production configuration where
// BOTH the worker's own audit sink (SetAuditSink) AND a real
// ExhaustionNotifier are wired.
//
// Task 9 fix round 2: TriageWorker is now the row's single, unconditional
// owner (completeFailure in triage_worker.go) — skills/acutetriage.Skill.
// OnTriageExhausted no longer audits at all, only notifies (see
// skills/acutetriage/exhaustion_test.go's own
// TestOnTriageExhausted_NotifiesWithoutAuditing). notifier here is
// fakeExhaustionNotifier, which — exactly like the real, fixed
// Skill.OnTriageExhausted — never touches the shared audit sink, so this
// proves both that the row is emitted (with full identity) and that wiring
// a real notifier alongside the worker's own audit sink does not
// double-emit it.
func TestTriageWorkerAuditsExhaustionOnFifthAttempt(t *testing.T) {
	claim := testClaim("inc-audit-3", 5)
	store := &fakeStore{claimFn: func(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (situation.TriageAttemptClaim, error) {
		return claim, nil
	}}
	lister := &fakeLister{ids: []string{"inc-audit-3"}}
	analyzer := &fakeAnalyzer{fn: func(ctx context.Context, c situation.TriageAttemptClaim) (situation.AcuteResult, error) {
		return situation.AcuteResult{}, errors.New("still failing")
	}}
	audit := &fakeAuditSink{}
	notifier := &fakeExhaustionNotifier{}
	w := situation.NewTriageWorker(store, lister, analyzer, &fakeAfterCommit{}, notifier, situation.TriageWorkerConfig{MaxAttempts: 5, Owner: "test-owner"}, nil)
	w.SetAuditSink(audit)

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	if n := countKind(audit, "incident.triage_exhausted"); n != 1 {
		t.Fatalf("incident.triage_exhausted audit rows = %d, want exactly 1 (double-emission regression): kinds=%v", n, audit.kinds)
	}
	payload := payloadOfKind(t, audit, "incident.triage_exhausted")
	for _, key := range []string{"situation_id", "incident_id", "attempt_id", "attempt_number", "input_version", "code"} {
		if _, ok := payload[key]; !ok {
			t.Fatalf("incident.triage_exhausted payload missing key %q: %+v", key, payload)
		}
	}
	if got := payload["situation_id"]; got != claim.SituationID {
		t.Errorf("situation_id = %v, want %v", got, claim.SituationID)
	}
	if got := payload["incident_id"]; got != claim.IncidentID {
		t.Errorf("incident_id = %v, want %v", got, claim.IncidentID)
	}
	if got := payload["attempt_id"]; got != claim.AttemptID {
		t.Errorf("attempt_id = %v, want %v", got, claim.AttemptID)
	}
	if got, ok := payload["attempt_number"].(int); !ok || got != claim.AttemptNumber {
		t.Errorf("attempt_number = %v (ok=%v), want %v", payload["attempt_number"], ok, claim.AttemptNumber)
	}
	if got, ok := payload["input_version"].(int); !ok || got != claim.DecisionInputVersion {
		t.Errorf("input_version = %v (ok=%v), want %v", payload["input_version"], ok, claim.DecisionInputVersion)
	}

	// The notifier is still called (it is the one thing this hook is left
	// for), proving the worker's own unconditional audit append did not
	// also suppress the notification side of exhaustion handling.
	if calls := notifier.snapshot(); len(calls) != 1 {
		t.Fatalf("exhaustion notifier calls = %d, want exactly 1", len(calls))
	}
}

// TestTriageWorkerAuditsExhaustionRegardlessOfNotifierConfigured proves the
// worker's own incident.triage_exhausted append no longer depends in any
// way on whether an ExhaustionNotifier is configured: exactly one row lands
// whether or not a notifier is wired (compare with
// TestTriageWorkerAuditsExhaustionOnFifthAttempt above, which wires one).
// Task 9 fix round 2 removed the prior "fallback only when no notifier
// configured" gate entirely — this is no longer a fallback path, it is THE
// path, so a genuine exhaustion is never left unaudited, or under-audited,
// regardless of notifier wiring.
func TestTriageWorkerAuditsExhaustionRegardlessOfNotifierConfigured(t *testing.T) {
	claim := testClaim("inc-audit-3b", 5)
	store := &fakeStore{claimFn: func(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (situation.TriageAttemptClaim, error) {
		return claim, nil
	}}
	lister := &fakeLister{ids: []string{"inc-audit-3b"}}
	analyzer := &fakeAnalyzer{fn: func(ctx context.Context, c situation.TriageAttemptClaim) (situation.AcuteResult, error) {
		return situation.AcuteResult{}, errors.New("still failing")
	}}
	w := newWorker(store, lister, analyzer, &fakeAfterCommit{}, situation.TriageWorkerConfig{MaxAttempts: 5})
	audit := &fakeAuditSink{}
	w.SetAuditSink(audit)

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	if n := countKind(audit, "incident.triage_exhausted"); n != 1 {
		t.Fatalf("incident.triage_exhausted audit rows = %d, want exactly 1 (no notifier configured): kinds=%v", n, audit.kinds)
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
