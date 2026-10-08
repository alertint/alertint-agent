// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/notify/ntfy"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestNTFYAtomicSelectionAndConfiguration(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	cfg := ntfy.Config{Enabled: true, BaseURL: "http://localhost", Topic: "lab"}
	if err := st.ConfigureNTFY(ctx, cfg, now); err != nil {
		t.Fatal(err)
	}
	sit, first := snSeedOneCycle(t, st, "service=ntfy", now)
	claims, err := st.ClaimNTFY(ctx, "a", now, time.Minute)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claims %v: %v", claims, err)
	}
	frozen := claims[0].Message
	if err := st.FinishNTFY(ctx, claims[0], "pending", "ntfy_unavailable", now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	cfg.Events = []string{}
	if err := st.ConfigureNTFY(ctx, cfg, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	snCommit(t, st, sit, &first, now.Add(2*time.Second))
	var n int
	if err := st.db.QueryRowContext(ctx, "SELECT count(*) FROM ntfy_notifications").Scan(&n); err != nil || n != 1 {
		t.Fatalf("queue count %d: %v", n, err)
	}
	cfg.Enabled = false
	if err := st.ConfigureNTFY(ctx, cfg, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if got, err := st.ClaimNTFY(ctx, "a", now.Add(time.Hour), time.Minute); err != nil || len(got) != 0 {
		t.Fatalf("disabled claims %v %v", got, err)
	}
	cfg.Enabled = true
	if err := st.ConfigureNTFY(ctx, cfg, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	// A retry's immutable content is not rewritten by reconfiguration.
	var payload string
	if err := st.db.QueryRowContext(ctx, "SELECT message_json FROM ntfy_notifications WHERE id=?", claims[0].ID).Scan(&payload); err != nil || !strings.Contains(payload, frozen.Title) {
		t.Fatalf("frozen payload %s: %v", payload, err)
	}
	cfg.Topic = "new-topic"
	if err := st.ConfigureNTFY(ctx, cfg, now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if got, err := st.ClaimNTFY(ctx, "a", now.Add(time.Hour), time.Minute); err != nil || len(got) != 0 {
		t.Fatalf("retired claims %v %v", got, err)
	}
	if err := st.FinishNTFY(ctx, claims[0], "delivered", "", now, now); !errors.Is(err, ntfy.ErrClaimLost) {
		t.Fatalf("stale ack: %v", err)
	}
}

func TestNTFYCoalescesArtifactAndHandoffInOneCommit(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	group := "service=ntfy-artifact"
	if err := st.ConfigureNTFY(ctx, ntfy.Config{Enabled: true, BaseURL: "http://localhost", Topic: "lab", Events: []string{"operator_action_required", "operator_updated"}}, now); err != nil {
		t.Fatal(err)
	}
	sit, first := snSeedOneCycle(t, st, group, now)
	shMakeDue(t, st, sit, now)
	claim := claimSituation(t, st, sit, "controller-a", now.Add(time.Second))
	artifact := shSeedPendingArtifact(t, st, sit, "inc-"+group, group, "annotation-ntfy", "operator_annotation_recorded", claim.Situation.InputVersion, now)
	cycle := shPrepare(t, claim, shOperatorContract(now.Add(time.Minute)), model.LifecycleActive, model.AttentionInvestigate, now.Add(time.Second))
	last := first.History.Transitions[len(first.History.Transitions)-1]
	cycle.Change.PriorTransition = &last
	cycle.Change.PriorSummary = first.History.Summary
	cycle.Change.OperatorArtifacts = []situation.OperatorArtifactInput{artifact}
	cycle.Change.Projection.OperatorDelta = &model.OperatorDelta{HumanRequestChanged: true}
	cycle.Change.Projection.Briefing = &model.OperatorBriefing{Scope: "service"}
	cycle.Publish.PriorTransition = &last
	cycle.Publish.RootPublished = true
	if err := st.CommitController(ctx, claim, shDerive(t, cycle)); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := st.db.QueryRowContext(ctx, "SELECT count(*) FROM ntfy_notifications").Scan(&n); err != nil || n != 1 {
		t.Fatalf("same-commit notification count %d: %v", n, err)
	}
	var raw string
	if err := st.db.QueryRowContext(ctx, "SELECT events_json FROM ntfy_notifications").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var events []string
	if err := json.Unmarshal([]byte(raw), &events); err != nil || len(events) != 2 {
		t.Fatalf("coalesced events %s: %v", raw, err)
	}
}

func TestNTFYStaleUnattemptedActionUsesRecoveredState(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := st.ConfigureNTFY(ctx, ntfy.Config{Enabled: true, BaseURL: "http://localhost", Topic: "lab"}, now); err != nil {
		t.Fatal(err)
	}
	sit, first := snSeedOneCycle(t, st, "service=ntfy-stale-action", now)
	claimed, err := st.ClaimNTFY(ctx, "a", now, time.Minute)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim %v %v", claimed, err)
	}
	if err := st.FinishNTFY(ctx, claimed[0], "delivered", "", now, now); err != nil {
		t.Fatal(err)
	}
	snCommit(t, st, sit, &first, now.Add(time.Second))
	observed := now.Add(2 * time.Second)
	grace := observed.Add(s5RecoveryGrace)
	briefing := &model.OperatorBriefing{Scope: "service", Total: 1, Resolved: 1, Work: model.WorkProjection{Phase: model.WorkPhaseSettled, SourceGraceUntil: &grace}}
	s5RecoveryCycle(t, st, sit, observed, osMonitoringContract(grace), model.LifecycleRecoveryPending, briefing, observed)
	s5RecoveryCycle(t, st, sit, grace, model.ActionContract{NextActor: model.NextActorNone}, model.LifecycleRecovered, briefing, observed)
	got, err := st.ClaimNTFY(ctx, "b", grace.Add(time.Second), time.Minute)
	if err != nil || len(got) != 1 || strings.Contains(got[0].Message.Body, "Required action:") || !strings.Contains(got[0].Message.Title, "Recovered") {
		t.Fatalf("obsolete action replay: %v %v", got, err)
	}
}

func TestNTFYRestartRecoversBlockedAndLeasedWork(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "ntfy.db")
	st, err := openTestStoreWithMigrations(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	cfg := ntfy.Config{Enabled: true, BaseURL: "http://localhost", Topic: "lab"}
	if err := st.ConfigureNTFY(ctx, cfg, now); err != nil {
		t.Fatal(err)
	}
	snSeedOneCycle(t, st, "service=ntfy-restart", now)
	first, err := st.ClaimNTFY(ctx, "a", now, time.Minute)
	if err != nil || len(first) != 1 {
		t.Fatalf("claim %v %v", first, err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = openTestStoreWithMigrations(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.ConfigureNTFY(ctx, cfg, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	retry, err := st.ClaimNTFY(ctx, "b", now.Add(2*time.Second), time.Minute)
	if err != nil || len(retry) != 1 || retry[0].Message != first[0].Message {
		t.Fatalf("lost restart work %v %v", retry, err)
	}
	if err := st.FinishNTFY(ctx, first[0], "delivered", "", now, now); !errors.Is(err, ntfy.ErrClaimLost) {
		t.Fatalf("restart accepted stale ack %v", err)
	}
	if err := st.FinishNTFY(ctx, retry[0], "blocked", "ntfy_configuration_rejected", now, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if got, err := st.ClaimNTFY(ctx, "c", now.Add(time.Hour), time.Minute); err != nil || len(got) != 0 {
		t.Fatalf("blocked work retried %v %v", got, err)
	}
	if err := st.ConfigureNTFY(ctx, cfg, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if got, err := st.ClaimNTFY(ctx, "c", now.Add(4*time.Second), time.Minute); err != nil || len(got) != 1 || got[0].Message != first[0].Message {
		t.Fatalf("corrected config lost work %v %v", got, err)
	}
}

func TestNTFYFencedOrderingAndCatchup(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	cfg := ntfy.Config{Enabled: true, BaseURL: "http://localhost", Topic: "lab"}
	if err := st.ConfigureNTFY(ctx, cfg, now); err != nil {
		t.Fatal(err)
	}
	sit, first := snSeedOneCycle(t, st, "service=ntfy-gap", now)
	claims, err := st.ClaimNTFY(ctx, "a", now, time.Minute)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claims %v %v", claims, err)
	}
	if got, err := st.ClaimNTFY(ctx, "b", now, time.Minute); err != nil || len(got) != 0 {
		t.Fatalf("double claim %v %v", got, err)
	}
	if err := st.FinishNTFY(ctx, claims[0], "pending", "ntfy_unavailable", now.Add(5*time.Second), now); err != nil {
		t.Fatal(err)
	}
	snCommit(t, st, sit, &first, now.Add(time.Second))
	got, err := st.ClaimNTFY(ctx, "b", now.Add(6*time.Second), time.Minute)
	if err != nil || len(got) != 1 {
		t.Fatalf("catchup claims %v %v", got, err)
	}
	if !strings.Contains(got[0].Message.Title, "ntfy delivery resumed") {
		t.Fatalf("catchup %v", got[0])
	}
	var replaced int
	if err := st.db.QueryRowContext(ctx, "SELECT count(*) FROM ntfy_notifications WHERE status='superseded' AND replacement_id=?", got[0].ID).Scan(&replaced); err != nil || replaced != 2 {
		t.Fatalf("replacement count %d: %v", replaced, err)
	}
	// Lease expiry fences the previous sender and preserves frozen catch-up content.
	reclaimed, err := st.ClaimNTFY(ctx, "c", now.Add(2*time.Minute), time.Minute)
	if err != nil || len(reclaimed) != 1 || reclaimed[0].Message != got[0].Message {
		t.Fatalf("reclaim %v %v", reclaimed, err)
	}
	if err := st.FinishNTFY(ctx, got[0], "delivered", "", now, now); !errors.Is(err, ntfy.ErrClaimLost) {
		t.Fatalf("stale ack %v", err)
	}
}

func TestNTFYUnchangedRetryKeepsIdentity(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := st.ConfigureNTFY(ctx, ntfy.Config{Enabled: true, BaseURL: "http://localhost", Topic: "lab"}, now); err != nil {
		t.Fatal(err)
	}
	snSeedOneCycle(t, st, "service=ntfy-frozen", now)
	first, err := st.ClaimNTFY(ctx, "a", now, time.Minute)
	if err != nil || len(first) != 1 {
		t.Fatalf("claim %v %v", first, err)
	}
	if err := st.FinishNTFY(ctx, first[0], "pending", "ntfy_unavailable", now.Add(time.Second), now); err != nil {
		t.Fatal(err)
	}
	retry, err := st.ClaimNTFY(ctx, "b", now.Add(2*time.Second), time.Minute)
	if err != nil || len(retry) != 1 || retry[0].ID != first[0].ID || retry[0].Message != first[0].Message || retry[0].Attempts != 2 {
		t.Fatalf("changed retry: first=%v retry=%v err=%v", first, retry, err)
	}
}
