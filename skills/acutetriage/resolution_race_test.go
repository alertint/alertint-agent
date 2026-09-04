// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage_test

import (
	"context"
	"errors"
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

// TestRunClaimsIncidentResolutionBeforeNotifying catches the missing state
// transition behind issue #76. When every member recovers while initial triage
// is in flight, the model finding owns the analyzed -> resolved transition
// before it publishes the resolved notification. The queued correlator path
// then loses the same CAS and cannot publish a second resolution.
func TestRunClaimsIncidentResolutionBeforeNotifying(t *testing.T) {
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
	if got.Status != "resolved" {
		t.Fatalf("incident status = %q, want resolved before notification", got.Status)
	}
	if err := st.MarkIncidentResolved(ctx, inc.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second resolver = %v, want ErrNotFound from lost CAS", err)
	}
}

// TestRunSuppressesResolvedNotificationWhenAnotherPathWon simulates the
// correlator winning the resolution CAS immediately after the finding is
// persisted. Initial triage must not publish another resolved notification.
func TestRunSuppressesResolvedNotificationWhenAnotherPathWon(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	a := insertTestAlert(t, st, ctx, inc.ID, "fp-resolution-already-claimed", map[string]string{
		"alertname": "DiskFull",
		"host":      "web1",
	})
	resolveTestAlert(t, st, ctx, a)

	// Deterministically model the competing resolution path: as soon as
	// SaveIncidentOutput transitions ready -> analyzed, this trigger claims
	// analyzed -> resolved before acute triage can claim it.
	if _, err := st.DB().ExecContext(ctx, `
		CREATE TRIGGER resolve_after_analysis
		AFTER UPDATE OF status ON incidents
		WHEN NEW.status = 'analyzed'
		BEGIN
			UPDATE incidents SET status = 'resolved' WHERE id = NEW.id;
		END
	`); err != nil {
		t.Fatalf("create competing resolver: %v", err)
	}

	notifier := &captureNotifier{}
	fllm := &fakeLLM{response: validLLMResponse([]string{a.ID})}
	skill := acutetriage.New(acutetriage.Config{}, st, fllm, nil, notifier, nil)

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if notifier.last != nil {
		t.Fatalf("losing path notified %+v, want no duplicate finding", *notifier.last)
	}

	got, err := st.GetIncidentByID(ctx, inc.ID)
	if err != nil {
		t.Fatalf("load incident: %v", err)
	}
	if got.Status != "resolved" {
		t.Errorf("incident status = %q, want winner's resolved state preserved", got.Status)
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

// TestRejudgeClaimsReopenedIncidentResolution covers the recurrence race: the
// ingress path may persist the occurrence's resolved alert while a synchronous
// re-judgment is still running. The re-judgment's resolved finding must claim
// analyzed -> resolved before it notifies, so the queued correlator delivery
// cannot publish the same recovery a second time.
func TestRejudgeClaimsReopenedIncidentResolution(t *testing.T) {
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
	if got.Status != "resolved" {
		t.Fatalf("incident status = %q, want resolved before notification", got.Status)
	}
	if err := st.MarkIncidentResolved(ctx, analyzed.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("queued resolver = %v, want ErrNotFound from lost CAS", err)
	}
}

func TestRejudgeSuppressesResolvedNotificationWhenAnotherPathWon(t *testing.T) {
	ctx, st, _, _, analyzed, a := analyzedFixture(t)
	if _, err := st.DB().ExecContext(ctx, `
		CREATE TRIGGER win_resolution_during_rejudge
		AFTER UPDATE OF last_judged_at ON incidents
		BEGIN
			UPDATE alerts SET status = 'resolved';
			UPDATE incidents SET status = 'resolved' WHERE id = NEW.id;
		END
	`); err != nil {
		t.Fatalf("create competing resolver trigger: %v", err)
	}

	notifier := &captureNotifier{}
	rejudgeLLM := &fakeLLM{response: validLLMResponse([]string{a.ID})}
	rejudgeSkill := acutetriage.New(acutetriage.Config{}, st, rejudgeLLM, nil, notifier, nil)
	if err := rejudgeSkill.Rejudge(ctx, analyzed, "severity"); err != nil {
		t.Fatalf("Rejudge: %v", err)
	}
	if notifier.last != nil {
		t.Fatalf("losing re-judgment notified %+v, want no duplicate finding", *notifier.last)
	}
}
