// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage_test

import (
	"context"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

func resolveTestAlert(t *testing.T, st *store.Store, ctx context.Context, a store.Alert) {
	t.Helper()
	a.Status = "resolved"
	a.ReceivedAt = time.Now().UTC()
	if _, err := st.UpsertAlertByFingerprint(ctx, a); err != nil {
		t.Fatalf("resolve alert: %v", err)
	}
}

// TestRunReportsResolvedWithoutClaimingSituationRecovery preserves the
// compatibility Finding status while leaving recovery ownership to the
// Situation controller. Acute Triage may finish after every member recovered,
// but it must not consume the Incident transition the durable delivery path
// and Situation notification ledger own.
func TestRunReportsResolvedWithoutClaimingSituationRecovery(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	a := insertTestAlert(t, st, ctx, inc.ID, "fp-resolved-during-triage", map[string]string{
		"alertname": "DiskFull",
		"host":      "web1",
	})
	resolveTestAlert(t, st, ctx, a)

	notifier := &captureNotifier{}
	fllm := &fakeLLM{response: validLLMResponse([]string{a.ID})}
	skill := acutetriage.New(acutetriage.Config{}, st, fllm, nil, notifier, nil)

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if notifier.last == nil {
		t.Fatal("notifier never received the winning finding")
	}
	if notifier.last.Status != "resolved" {
		t.Errorf("Finding.Status = %q, want resolved", notifier.last.Status)
	}
	if notifier.last.Severity != "high" {
		t.Errorf("Finding.Severity = %q, want model severity high", notifier.last.Severity)
	}

	got, err := st.GetIncidentByID(ctx, inc.ID)
	if err != nil {
		t.Fatalf("load incident: %v", err)
	}
	if got.Status != "analyzed" {
		t.Fatalf("incident status = %q, want analyzed until durable recovery is applied", got.Status)
	}
	if err := st.MarkIncidentResolved(ctx, inc.ID); err != nil {
		t.Fatalf("durable recovery owner could not settle Incident: %v", err)
	}
}

func TestRunNotifiesOngoingWhenAnyMemberIsFiring(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	a := insertTestAlert(t, st, ctx, inc.ID, "fp-still-firing", map[string]string{
		"alertname": "DiskFull",
		"host":      "web1",
	})

	notifier := &captureNotifier{}
	fllm := &fakeLLM{response: validLLMResponse([]string{a.ID})}
	skill := acutetriage.New(acutetriage.Config{}, st, fllm, nil, notifier, nil)

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if notifier.last == nil {
		t.Fatal("notifier never received the ongoing finding")
	}
	if notifier.last.Status != "ongoing" {
		t.Errorf("Finding.Status = %q, want ongoing", notifier.last.Status)
	}
	got, err := st.GetIncidentByID(ctx, inc.ID)
	if err != nil {
		t.Fatalf("load incident: %v", err)
	}
	if got.Status != "analyzed" {
		t.Errorf("incident status = %q, want analyzed", got.Status)
	}
}

func TestRejudgeResolvedIncidentStillNotifies(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	a := insertTestAlert(t, st, ctx, inc.ID, "fp-resolved-rejudge", map[string]string{
		"alertname": "DiskFull",
		"host":      "web1",
	})

	initialLLM := &fakeLLM{response: validLLMResponse([]string{a.ID})}
	initialSkill := acutetriage.New(acutetriage.Config{}, st, initialLLM, nil, nil, nil)
	if err := initialSkill.Run(ctx, inc); err != nil {
		t.Fatalf("initial Run: %v", err)
	}
	if err := st.MarkIncidentResolved(ctx, inc.ID); err != nil {
		t.Fatalf("mark incident resolved: %v", err)
	}
	resolveTestAlert(t, st, ctx, a)
	resolved, err := st.GetIncidentByID(ctx, inc.ID)
	if err != nil {
		t.Fatalf("load resolved incident: %v", err)
	}

	notifier := &captureNotifier{}
	rejudgeLLM := &fakeLLM{response: validLLMResponse([]string{a.ID})}
	rejudgeSkill := acutetriage.New(acutetriage.Config{}, st, rejudgeLLM, nil, notifier, nil)
	if err := rejudgeSkill.Rejudge(ctx, *resolved, "severity"); err != nil {
		t.Fatalf("Rejudge: %v", err)
	}
	if notifier.last == nil {
		t.Fatal("resolved re-judgment was incorrectly suppressed")
	}
	if notifier.last.Status != "resolved" {
		t.Errorf("Finding.Status = %q, want resolved", notifier.last.Status)
	}
}

// TestRejudgeReportsResolvedWithoutClaimingSituationRecovery is the recurrence
// form of the same ownership rule.
func TestRejudgeReportsResolvedWithoutClaimingSituationRecovery(t *testing.T) {
	ctx, st, _, _, analyzed, a := analyzedFixture(t)
	if _, err := st.DB().ExecContext(ctx, `
		CREATE TRIGGER resolve_member_after_rejudge
		AFTER UPDATE OF last_judged_at ON incidents
		BEGIN
			UPDATE alerts SET status = 'resolved';
		END
	`); err != nil {
		t.Fatalf("create resolved-during-rejudge trigger: %v", err)
	}

	notifier := &captureNotifier{}
	rejudgeLLM := &fakeLLM{response: validLLMResponse([]string{a.ID})}
	rejudgeSkill := acutetriage.New(acutetriage.Config{}, st, rejudgeLLM, nil, notifier, nil)
	if err := rejudgeSkill.Rejudge(ctx, analyzed, "severity"); err != nil {
		t.Fatalf("Rejudge: %v", err)
	}
	if notifier.last == nil || notifier.last.Status != "resolved" {
		t.Fatalf("re-judgment finding = %+v, want resolved", notifier.last)
	}
	got, err := st.GetIncidentByID(ctx, analyzed.ID)
	if err != nil {
		t.Fatalf("load incident: %v", err)
	}
	if got.Status != "analyzed" {
		t.Fatalf("incident status = %q, want analyzed until durable recovery is applied", got.Status)
	}
	if err := st.MarkIncidentResolved(ctx, analyzed.ID); err != nil {
		t.Fatalf("durable recovery owner could not settle Incident: %v", err)
	}
}
