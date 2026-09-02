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

// auditingExhaustionNotifier mirrors the production shape closely enough to
// catch Task 9 fix round Finding #1's double-emission regression:
// skills/acutetriage.Skill.OnTriageExhausted appends its OWN
// incident.triage_exhausted row to the SAME AuditSink the worker itself was
// wired with (both share one audit sink in cmd/alertint's
// newControllerRuntime) — unlike fakeExhaustionNotifier, which only records
// calls on itself and never touches the shared sink, so it could never have
// caught a double append.
type auditingExhaustionNotifier struct {
	sink situation.AuditSink
}

func (n *auditingExhaustionNotifier) OnTriageExhausted(ctx context.Context, incidentID, code, detail string) error {
	return n.sink.Append(ctx, "skill:acute-triage", "incident.triage_exhausted", map[string]any{
		"incident_id": incidentID, "code": code, "detail": detail,
	})
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
// TestTriageWorker_FifthAttemptExhaustion's exact scenario and proves it
// audits incident.triage_exhausted after the durable exhaust write commits —
// and, Task 9 fix round Finding #1: EXACTLY ONCE, in the production
// configuration where both the worker's own audit sink (SetAuditSink) AND a
// real ExhaustionNotifier are wired into the SAME sink. The prior version of
// this test wired a fakeExhaustionNotifier that never touched the shared
// sink at all, so it could not have caught the double-emission regression
// (the worker's own direct append plus the notifier's own real append,
// wired here via auditingExhaustionNotifier, both landing in one sink).
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
	notifier := &auditingExhaustionNotifier{sink: audit}
	w := situation.NewTriageWorker(store, lister, analyzer, &fakeAfterCommit{}, notifier, situation.TriageWorkerConfig{MaxAttempts: 5, Owner: "test-owner"}, nil)
	w.SetAuditSink(audit)

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	if !audit.has("incident.triage_exhausted") {
		t.Fatalf("audit kinds = %v, want incident.triage_exhausted", audit.kinds)
	}
	if n := countKind(audit, "incident.triage_exhausted"); n != 1 {
		t.Fatalf("incident.triage_exhausted audit rows = %d, want exactly 1 (double-emission regression): kinds=%v", n, audit.kinds)
	}
}

// TestTriageWorkerAuditsExhaustionFallbackWhenNoNotifierConfigured proves
// the OTHER half of Finding #1's fix: when no ExhaustionNotifier is
// configured at all (the worker's own SetAuditSink is still wired), the
// worker's own direct append is the fallback — a genuine exhaustion is never
// silently unaudited just because no notifier exists to own the row.
func TestTriageWorkerAuditsExhaustionFallbackWhenNoNotifierConfigured(t *testing.T) {
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
		t.Fatalf("incident.triage_exhausted audit rows = %d, want exactly 1 (fallback with no notifier configured): kinds=%v", n, audit.kinds)
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
