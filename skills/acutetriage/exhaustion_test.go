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

// TestOnTriageExhausted_AppendsAuditAndNotifies proves Skill.OnTriageExhausted
// (the concrete situation.ExhaustionNotifier implementation Task 9 wires
// into a real TriageWorker) both appends one incident.triage_exhausted
// audit row and calls the notifier's TriageFailureSink capability exactly
// once — restoring the operator-visible signal the deleted pre-Plan-2
// exhaustTriage produced.
func TestOnTriageExhausted_AppendsAuditAndNotifies(t *testing.T) {
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
	if n != 1 {
		t.Fatalf("incident.triage_exhausted audit rows = %d, want 1", n)
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
