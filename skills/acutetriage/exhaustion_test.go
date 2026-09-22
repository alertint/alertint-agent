// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage_test

import (
	"context"
	"testing"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

// exhaustionSpyNotifier implements both notify.Notifier and
// notify.TriageFailureSink — proving Skill.OnTriageExhausted (Task 7 fix,
// Finding #3's concrete situation.ExhaustionNotifier implementation) reaches
// a sink through the SAME s.notifier field AfterCommit already uses for
// Finding content, via a notify.TriageFailureSink capability check.
type exhaustionSpyNotifier struct {
	calls []notify.TriageExhaustedEvent
}

func (n *exhaustionSpyNotifier) Notify(_ context.Context, _ notify.Finding) error { return nil }
func (n *exhaustionSpyNotifier) Name() string                                     { return "exhaustion-spy" }
func (n *exhaustionSpyNotifier) OnTriageExhausted(_ context.Context, ev notify.TriageExhaustedEvent) error {
	n.calls = append(n.calls, ev)
	return nil
}

// TestOnTriageExhausted_NotifiesWithoutAuditing proves Skill.OnTriageExhausted
// (the concrete situation.ExhaustionNotifier implementation Task 9 wires
// into a real TriageWorker) calls the notifier's TriageFailureSink
// capability exactly once and appends NO incident.triage_exhausted audit
// row of its own — even with a real auditor configured.
//
// Task 9 fix round 2: this method used to also append its own
// incident.triage_exhausted row, which either double-emitted the event or
// (after an intermediate fix) became the sole surviving row in production
// while missing situation_id/attempt_id/attempt_number/input_version —
// fields this method's own signature (incidentID, code, detail) never
// receives. TriageWorker itself (internal/situation/triage_worker.go's
// completeFailure) is now the row's single, unconditional owner, since it
// alone holds the full identity via its TriageAttemptClaim; this method is
// left as a pure notification hook.
func TestOnTriageExhausted_NotifiesWithoutAuditing(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	auditor := audit.New(st.DB())
	sink := &exhaustionSpyNotifier{}
	skill := acutetriage.New(acutetriage.Config{}, st, &fakeLLM{}, auditor, sink, nil)

	if err := skill.OnTriageExhausted(ctx, "inc-exhausted-1", "acute_triage_failed", "still failing"); err != nil {
		t.Fatalf("OnTriageExhausted: %v", err)
	}

	var n int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE kind = 'incident.triage_exhausted'`).Scan(&n); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	if n != 0 {
		t.Fatalf("incident.triage_exhausted audit rows = %d, want 0 (OnTriageExhausted no longer audits — TriageWorker owns the row)", n)
	}

	if len(sink.calls) != 1 {
		t.Fatalf("notifier calls = %d, want 1", len(sink.calls))
	}
	if sink.calls[0].IncidentID != "inc-exhausted-1" {
		t.Errorf("notified IncidentID = %q, want inc-exhausted-1", sink.calls[0].IncidentID)
	}
}

// TestOnTriageExhausted_PlainNotifierIsSkippedNotFailed proves a configured
// notifier that does NOT implement notify.TriageFailureSink (the Slack sink
// deliberately does not — see that interface's own doc comment) is silently
// skipped rather than treated as an error.
func TestOnTriageExhausted_PlainNotifierIsSkippedNotFailed(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	skill := acutetriage.New(acutetriage.Config{}, st, &fakeLLM{}, nil, &spyNotifier{}, nil)

	if err := skill.OnTriageExhausted(ctx, "inc-exhausted-2", "acute_triage_failed", "still failing"); err != nil {
		t.Fatalf("OnTriageExhausted: %v", err)
	}
}

// TestOnTriageExhausted_NilAuditorAndNotifierIsANoOp proves the method is
// safe with everything disabled (mirroring AfterCommit's own nil-tolerant
// convention).
func TestOnTriageExhausted_NilAuditorAndNotifierIsANoOp(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	skill := acutetriage.New(acutetriage.Config{}, st, &fakeLLM{}, nil, nil, nil)

	if err := skill.OnTriageExhausted(ctx, "inc-exhausted-3", "acute_triage_failed", "still failing"); err != nil {
		t.Fatalf("OnTriageExhausted: %v", err)
	}
}
