// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

func TestSituationsMigrationEnforcesAggregateIdentity(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "sit-1", "host=db-1", "db-1-cpu", situationmodel.LifecycleActive, now)

	if _, err := insertSituationFixtureErr(s, "sit-2", "host=db-1", "", situationmodel.LifecycleRecoveryPending, now); err == nil {
		t.Fatal("inserted a second nonterminal situation for one exact group key")
	}
	insertSituationFixture(t, s, "sit-terminal", "host=db-1", "", situationmodel.LifecycleRecovered, now)
	if _, err := insertSituationFixtureErr(s, "sit-3", "host=db-2", "DB-1-CPU", situationmodel.LifecycleActive, now); err == nil {
		t.Fatal("inserted a case-insensitive duplicate public handle")
	}
}

func TestSituationsMigrationKeepsTerminalHandleAndMembershipImmutable(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "immutable-terminal", "host=immutable", "stable-handle", situationmodel.LifecycleRecovered, now)
	if _, err := s.DB().Exec(`UPDATE situations SET lifecycle = 'active', terminal_at = NULL WHERE id = ?`, "immutable-terminal"); err == nil {
		t.Fatal("reopened a terminal situation")
	}
	if _, err := s.DB().Exec(`UPDATE situations SET public_handle = ? WHERE id = ?`, "changed-handle", "immutable-terminal"); err == nil {
		t.Fatal("changed an immutable public handle")
	}
	seedIncident(t, s, "immutable-inc", "host=immutable", "resolved", now)
	if _, err := s.DB().Exec(`INSERT INTO situation_incidents(situation_id, incident_id, attached_at) VALUES (?, ?, ?)`, "immutable-terminal", "immutable-inc", canonicalTime(now)); err != nil {
		t.Fatal(err)
	}
	insertSituationFixture(t, s, "other-terminal", "host=other", "", situationmodel.LifecycleRecovered, now)
	if _, err := s.DB().Exec(`UPDATE situation_incidents SET situation_id = ? WHERE incident_id = ?`, "other-terminal", "immutable-inc"); err == nil {
		t.Fatal("moved immutable primary membership")
	}
}

func TestSituationsMigrationFreezesFirstTerminalProjection(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "frozen-terminal", "host=frozen", "", situationmodel.LifecycleRecovered, now)
	if _, err := s.DB().Exec(`UPDATE situations SET lifecycle = 'recovered', terminal_at = ? WHERE id = ?`, canonicalTime(now.Add(time.Hour)), "frozen-terminal"); err == nil {
		t.Fatal("mutated first terminal projection through a same-state transition")
	}
	var terminalAt string
	if err := s.DB().QueryRow(`SELECT terminal_at FROM situations WHERE id = ?`, "frozen-terminal").Scan(&terminalAt); err != nil {
		t.Fatal(err)
	}
	if terminalAt != canonicalTime(now) {
		t.Fatalf("terminal_at = %q, want %q", terminalAt, canonicalTime(now))
	}
}

func TestSituationsMigrationRequiresRecoveryEvidence(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "missing-pending-evidence", "host=missing-pending", "", situationmodel.LifecycleActive, now)
	if _, err := s.DB().Exec(`UPDATE situations SET lifecycle = 'recovery_pending' WHERE id = ?`, "missing-pending-evidence"); err == nil {
		t.Fatal("stored recovery_pending without recovery evidence")
	}

	if _, err := s.DB().Exec(`
		INSERT INTO situations (
			id, group_key, lifecycle, attention, input_version,
			opened_at, effective_started_at, effective_started_at_basis,
			first_received_at, last_lifecycle_observed_at, terminal_at,
			next_assessment_at, due_reasons_json, created_at, updated_at
		) VALUES (?, ?, 'recovered', 'observe', 1, ?, ?, 'receipt_fallback', ?, ?, ?, ?, '[]', ?, ?)`,
		"missing-recovered-evidence", "host=missing-recovered", canonicalTime(now), canonicalTime(now),
		canonicalTime(now), canonicalTime(now), canonicalTime(now), canonicalTime(now), canonicalTime(now), canonicalTime(now)); err == nil {
		t.Fatal("stored recovered without recovery evidence")
	}
}

func TestOpenMigratesPopulated0010IncidentAnalysisState(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "situations-from-0010.db")
	db, err := sql.Open("sqlite", buildDSN(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	legacy := &Store{db: db}
	if _, err := db.ExecContext(ctx, `CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL) STRICT`); err != nil {
		t.Fatal(err)
	}
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations {
		if migration.version > 10 {
			break
		}
		if err := legacy.applyMigration(ctx, migration); err != nil {
			t.Fatalf("apply migration %d: %v", migration.version, err)
		}
	}
	now := "2026-08-20T10:00:00Z"
	cases := []struct {
		id, incidentStatus string
		output             any
		want               string
	}{
		{"analyzed-finding", "analyzed", `{}`, "complete"},
		{"resolved-finding", "resolved", `{}`, "complete"},
		{"ready", "ready", nil, "planned"},
		{"processing", "processing", nil, "planned"},
		{"failed", "failed", nil, "exhausted"},
		{"resolved-empty", "resolved", nil, "not_requested"},
	}
	for _, tc := range cases {
		if _, err := db.ExecContext(ctx, `
			INSERT INTO incidents
				(id, group_key, status, first_alert_at, last_alert_at, ready_at, alert_count, output_json, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)`, tc.id, "group="+tc.id, tc.incidentStatus, now, now, now, tc.output, now, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upgraded.Close() }()
	for _, tc := range cases {
		var got string
		if err := upgraded.DB().QueryRowContext(ctx, `SELECT status FROM incident_analysis_state WHERE incident_id = ?`, tc.id).Scan(&got); err != nil {
			t.Fatalf("analysis state for %s: %v", tc.id, err)
		}
		if got != tc.want {
			t.Fatalf("analysis state for %s = %q, want %q", tc.id, got, tc.want)
		}
	}
}

func TestApplySituationInputExactlyOnce(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	seedIncident(t, s, "input-inc-1", "host=db-1", "ready", now)
	in := SituationInput{
		ID:             "input-1",
		IdempotencyKey: "incident:input-inc-1:created",
		IncidentID:     "input-inc-1",
		Kind:           "incident_created",
		GroupKey:       "host=db-1",
		OccurredAt:     now,
	}
	seedSituationInput(t, s, in, "claimed", "worker-1", now.Add(time.Minute))

	claim := claimedSituationInputForTest(in, "worker-1")
	first, err := s.ApplySituationInput(context.Background(), claim)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.ApplySituationInput(context.Background(), claim)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || first.InputVersion != 1 || second.InputVersion != first.InputVersion {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
	if !first.OpenedAt.After(in.OccurredAt) {
		t.Fatalf("opened_at = %s, must record aggregate creation after input occurrence %s", first.OpenedAt, in.OccurredAt)
	}
	var membershipCount int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM situation_incidents WHERE incident_id = ?`, in.IncidentID).Scan(&membershipCount); err != nil {
		t.Fatal(err)
	}
	if membershipCount != 1 {
		t.Fatalf("membership count = %d", membershipCount)
	}
}

func TestApplySituationInputUnionsReasonsAndMovesScheduleEarlier(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	seedIncident(t, s, "input-inc-2", "host=db-2", "ready", now)
	created := SituationInput{ID: "input-created", IdempotencyKey: "incident:input-inc-2:created", IncidentID: "input-inc-2", Kind: "incident_created", GroupKey: "host=db-2", OccurredAt: now}
	seedSituationInput(t, s, created, "claimed", "worker-1", now.Add(time.Minute))
	if _, err := s.ApplySituationInput(context.Background(), claimedSituationInputForTest(created, "worker-1")); err != nil {
		t.Fatal(err)
	}
	if claimed, err := s.ClaimDueSituations(context.Background(), "reconciler", now, time.Minute, 1); err != nil || len(claimed) != 1 {
		t.Fatalf("claim before new input=%+v err=%v", claimed, err)
	}
	earlier := now.Add(-time.Minute)
	changed := SituationInput{ID: "input-changed", IdempotencyKey: "incident:input-inc-2:changed", IncidentID: "input-inc-2", Kind: "membership_changed", GroupKey: "host=db-2", OccurredAt: earlier}
	seedSituationInput(t, s, changed, "claimed", "worker-1", now.Add(time.Minute))

	got, err := s.ApplySituationInput(context.Background(), claimedSituationInputForTest(changed, "worker-1"))
	if err != nil {
		t.Fatal(err)
	}
	if got.InputVersion != 2 || !got.NextAssessmentAt.Equal(earlier) || got.LeaseOwner != nil || got.AttemptCount != 0 {
		t.Fatalf("situation=%+v", got)
	}
	wantReasons := []situationmodel.DueReason{situationmodel.DueIncidentCreated, situationmodel.DueMembershipChanged}
	if len(got.DueReasons) != len(wantReasons) || got.DueReasons[0] != wantReasons[0] || got.DueReasons[1] != wantReasons[1] {
		t.Fatalf("due reasons = %v, want %v", got.DueReasons, wantReasons)
	}
}

func TestApplySituationInputStartsLinkedAggregateAfterTerminal(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	seedIncident(t, s, "terminal-inc", "host=db-3", "resolved", now.Add(-time.Hour))
	insertSituationFixture(t, s, "terminal-situation", "host=db-3", "", situationmodel.LifecycleRecovered, now.Add(-time.Hour))
	if _, err := s.DB().Exec(`INSERT INTO situation_incidents(situation_id, incident_id, attached_at) VALUES (?, ?, ?)`, "terminal-situation", "terminal-inc", canonicalTime(now.Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}
	seedIncident(t, s, "new-inc", "host=db-3", "ready", now)
	in := SituationInput{ID: "new-input", IdempotencyKey: "incident:new-inc:created", IncidentID: "new-inc", Kind: "incident_created", GroupKey: "host=db-3", OccurredAt: now}
	seedSituationInput(t, s, in, "claimed", "worker-1", now.Add(time.Minute))

	got, err := s.ApplySituationInput(context.Background(), claimedSituationInputForTest(in, "worker-1"))
	if err != nil {
		t.Fatal(err)
	}
	if got.ID == "terminal-situation" || got.PreviousSituationID == nil || *got.PreviousSituationID != "terminal-situation" {
		t.Fatalf("new situation linkage = %+v", got)
	}
	if got.Lifecycle != situationmodel.LifecycleActive {
		t.Fatalf("new situation lifecycle = %q", got.Lifecycle)
	}
}

func TestApplySituationInputMovesEffectiveStartEarlierWithExplicitBasis(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	seedIncident(t, s, "basis-inc-1", "host=basis", "ready", now)
	first := SituationInput{ID: "basis-input-1", IdempotencyKey: "incident:basis:1", IncidentID: "basis-inc-1", Kind: "incident_created", GroupKey: "host=basis", OccurredAt: now}
	seedSituationInput(t, s, first, "claimed", "worker-1", now.Add(time.Minute))
	if _, err := s.ApplySituationInput(context.Background(), claimedSituationInputForTest(first, "worker-1")); err != nil {
		t.Fatal(err)
	}

	earlier := now.Add(-time.Hour)
	received := now.Add(time.Minute)
	deliveryID := "basis-delivery"
	seedIncident(t, s, "basis-inc-2", "host=basis", "ready", received)
	if _, err := s.AcceptDeliveries(context.Background(), []DeliveryInput{{
		ID:     deliveryID,
		Alert:  Alert{ID: "basis-alert", Fingerprint: "basis-fp", Status: "firing", Labels: map[string]string{}, Annotations: map[string]string{}, StartsAt: received, ReceivedAt: received},
		Source: "alertmanager", SourceEpisodeKey: "alertmanager:basis", SourceStartedAt: &earlier,
		StartedAtBasis: situationmodel.SourceTimeBasisSourcePayload, ResolvedAtBasis: situationmodel.SourceTimeBasisMissing,
		ReceiverGroupingIdentity: "host=basis", PayloadDigest: "sha256:basis",
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`INSERT INTO incident_alert_deliveries(incident_id, delivery_id, created_at) VALUES (?, ?, ?)`, "basis-inc-2", deliveryID, canonicalTime(received)); err != nil {
		t.Fatal(err)
	}
	second := SituationInput{ID: "basis-input-2", IdempotencyKey: "incident:basis:2", IncidentID: "basis-inc-2", DeliveryID: &deliveryID, Kind: "membership_changed", GroupKey: "host=basis", OccurredAt: received}
	seedSituationInput(t, s, second, "claimed", "worker-1", received.Add(time.Minute))
	got, err := s.ApplySituationInput(context.Background(), claimedSituationInputForTest(second, "worker-1"))
	if err != nil {
		t.Fatal(err)
	}
	if !got.EffectiveStartedAt.Equal(earlier) || got.EffectiveStartedAtBasis != situationmodel.SourceTimeBasisMixed {
		t.Fatalf("effective start=%s basis=%q", got.EffectiveStartedAt, got.EffectiveStartedAtBasis)
	}
}

func TestClaimSituationInputsReturnsOnlyRowsChangedByClaim(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	for index, id := range []string{"claim-inc-1", "claim-inc-2", "claim-inc-3"} {
		seedIncident(t, s, id, "host="+id, "ready", now)
		in := SituationInput{ID: "input-" + id, IdempotencyKey: "incident:" + id, IncidentID: id, Kind: "incident_created", GroupKey: "host=" + id, OccurredAt: now.Add(time.Duration(index) * time.Second)}
		if index == 2 {
			seedSituationInput(t, s, in, "claimed", "dead-worker", now.Add(-time.Second))
		} else {
			seedSituationInput(t, s, in, "pending", "", time.Time{})
		}
	}

	first, err := s.ClaimSituationInputs(context.Background(), "worker-1", now, time.Minute, 1)
	if err != nil || len(first) != 1 || first[0].ID != "input-claim-inc-1" {
		t.Fatalf("first claim=%+v err=%v", first, err)
	}
	second, err := s.ClaimSituationInputs(context.Background(), "worker-1", now, time.Minute, 1)
	if err != nil || len(second) != 1 || second[0].ID != "input-claim-inc-2" {
		t.Fatalf("second claim=%+v err=%v", second, err)
	}
	third, err := s.ClaimSituationInputs(context.Background(), "worker-2", now, time.Minute, 1)
	if err != nil || len(third) != 1 || third[0].ID != "input-claim-inc-3" {
		t.Fatalf("expired claim=%+v err=%v", third, err)
	}
}

func TestApplySituationInputRejectsExpiredReclaimedFence(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	seedIncident(t, s, "fenced-input-inc", "host=fenced-input", "ready", now)
	in := SituationInput{ID: "fenced-input", IdempotencyKey: "incident:fenced-input", IncidentID: "fenced-input-inc", Kind: "incident_created", GroupKey: "host=fenced-input", OccurredAt: now}
	seedSituationInput(t, s, in, "pending", "", time.Time{})
	first, err := s.ClaimSituationInputs(context.Background(), "worker-1", now, time.Minute, 1)
	if err != nil || len(first) != 1 {
		t.Fatalf("first claim=%+v err=%v", first, err)
	}
	second, err := s.ClaimSituationInputs(context.Background(), "worker-2", now.Add(2*time.Minute), time.Minute, 1)
	if err != nil || len(second) != 1 {
		t.Fatalf("second claim=%+v err=%v", second, err)
	}
	if first[0].ClaimToken >= second[0].ClaimToken || first[0].ClaimOwner != "worker-1" || second[0].ClaimOwner != "worker-2" {
		t.Fatalf("claim fences first=%+v second=%+v", first[0], second[0])
	}
	if _, err := s.ApplySituationInput(context.Background(), first[0]); !errors.Is(err, ErrSituationLeaseLost) {
		t.Fatalf("stale apply err=%v", err)
	}
	var status, owner string
	var token int64
	if err := s.DB().QueryRow(`SELECT status, lease_owner, claim_token FROM situation_input_outbox WHERE id = ?`, in.ID).Scan(&status, &owner, &token); err != nil {
		t.Fatal(err)
	}
	if status != "claimed" || owner != "worker-2" || token != second[0].ClaimToken {
		t.Fatalf("current claim status=%s owner=%s token=%d", status, owner, token)
	}
	if _, err := s.ApplySituationInput(context.Background(), second[0]); err != nil {
		t.Fatal(err)
	}
}

func TestRetrySituationInputClearsClaimAndCanDeadLetter(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	for _, id := range []string{"retry-inc", "failed-inc"} {
		seedIncident(t, s, id, "host="+id, "ready", now)
		seedSituationInput(t, s, SituationInput{ID: "input-" + id, IdempotencyKey: "incident:" + id, IncidentID: id, Kind: "incident_created", GroupKey: "host=" + id, OccurredAt: now}, "claimed", "worker-1", now.Add(time.Minute))
	}
	retryAt := now.Add(2 * time.Minute)
	if err := s.RetrySituationInput(context.Background(), claimedSituationInputForTest(SituationInput{ID: "input-retry-inc"}, "worker-1"), "temporary_dependency", retryAt, false); err != nil {
		t.Fatal(err)
	}
	if err := s.RetrySituationInput(context.Background(), claimedSituationInputForTest(SituationInput{ID: "input-failed-inc"}, "worker-1"), "invalid_input", retryAt, true); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		id, status string
		wantRetry  bool
	}{{"input-retry-inc", "pending", true}, {"input-failed-inc", "failed", false}} {
		var status string
		var owner, retry sql.NullString
		if err := s.DB().QueryRow(`SELECT status, lease_owner, retry_at FROM situation_input_outbox WHERE id = ?`, tc.id).Scan(&status, &owner, &retry); err != nil {
			t.Fatal(err)
		}
		if status != tc.status || owner.Valid || retry.Valid != tc.wantRetry {
			t.Fatalf("%s status=%s owner=%v retry=%v", tc.id, status, owner, retry)
		}
	}
}

func TestClaimDueSituationsUsesPriorityAndRecoversExpiredLeases(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "due-observe", "host=observe", "", situationmodel.LifecycleActive, now)
	insertSituationFixture(t, s, "due-symptom", "host=symptom", "", situationmodel.LifecycleActive, now)
	insertSituationFixture(t, s, "due-urgent", "host=urgent", "", situationmodel.LifecycleActive, now)
	if _, err := s.DB().Exec(`UPDATE situations SET next_assessment_at = ?, due_reasons_json = ? WHERE id = ?`, canonicalTime(now.Add(-30*time.Second)), `[]`, "due-observe"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`UPDATE situations SET due_reasons_json = ? WHERE id = ?`, `["new_symptom"]`, "due-symptom"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`UPDATE situations SET attention = 'urgent' WHERE id = ?`, "due-urgent"); err != nil {
		t.Fatal(err)
	}

	claimed, err := s.ClaimDueSituations(context.Background(), "worker-1", now, time.Minute, 1)
	if err != nil || len(claimed) != 1 || claimed[0].Situation.ID != "due-urgent" {
		t.Fatalf("urgent claim=%+v err=%v", claimed, err)
	}
	claimed, err = s.ClaimDueSituations(context.Background(), "worker-1", now, time.Minute, 1)
	if err != nil || len(claimed) != 1 || claimed[0].Situation.ID != "due-symptom" {
		t.Fatalf("symptom claim=%+v err=%v", claimed, err)
	}
	if _, err := s.DB().Exec(`UPDATE situations SET lease_owner = ?, lease_expires_at = ? WHERE id = ?`, "dead-worker", canonicalTime(now.Add(-time.Second)), "due-observe"); err != nil {
		t.Fatal(err)
	}
	recovered, err := s.RecoverExpiredSituationLeases(context.Background(), now)
	if err != nil || recovered != 1 {
		t.Fatalf("recovered=%d err=%v", recovered, err)
	}
	claimed, err = s.ClaimDueSituations(context.Background(), "worker-2", now, time.Minute, 1)
	if err != nil || len(claimed) != 1 || claimed[0].Situation.ID != "due-observe" {
		t.Fatalf("recovered claim=%+v err=%v", claimed, err)
	}
}

func TestClaimDueSituationsDoesNotPromotePublishedNonMaterialReasons(t *testing.T) {
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	cases := []struct {
		id, handle, reasons string
	}{
		{"a-material", "material", `["membership_changed"]`},
		{"b-symptom", "", `["new_symptom"]`},
		{"c-recovery", "recovery", `["recovery_grace_expired"]`},
		{"d-manual", "manual", `["manual_reassessment"]`},
		{"e-retry", "retry", `["retry_due"]`},
	}
	seed := func(t *testing.T, s *Store) {
		t.Helper()
		for _, tc := range cases {
			insertSituationFixture(t, s, tc.id, "host="+tc.id, tc.handle, situationmodel.LifecycleActive, now)
			if _, err := s.DB().Exec(`UPDATE situations SET due_reasons_json = ? WHERE id = ?`, tc.reasons, tc.id); err != nil {
				t.Fatal(err)
			}
		}
	}

	s := newTestStore(t)
	seed(t, s)
	for index, want := range []string{"a-material", "b-symptom"} {
		claimed, err := s.ClaimDueSituations(context.Background(), "sql-priority-worker", now, time.Minute, 1)
		if err != nil || len(claimed) != 1 || claimed[0].Situation.ID != want {
			t.Fatalf("SQL claim[%d]=%+v, want %q, err=%v", index, claimed, want, err)
		}
	}
	if _, err := s.DB().Exec(`DELETE FROM situations`); err != nil {
		t.Fatal(err)
	}
	seed(t, s)
	claimed, err := s.ClaimDueSituations(context.Background(), "priority-worker", now, time.Minute, len(cases))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a-material", "b-symptom", "c-recovery", "d-manual", "e-retry"}
	if len(claimed) != len(want) {
		t.Fatalf("claimed=%+v", claimed)
	}
	for i := range want {
		if claimed[i].Situation.ID != want[i] {
			t.Fatalf("claim[%d]=%q, want %q (all=%+v)", i, claimed[i].Situation.ID, want[i], claimed)
		}
	}
}

func TestExtendSituationLeaseRequiresCurrentOwnership(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "heartbeat-situation", "host=heartbeat", "", situationmodel.LifecycleActive, now)
	claimed, err := s.ClaimDueSituations(context.Background(), "worker-1", now, time.Minute, 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim=%+v err=%v", claimed, err)
	}
	claim := claimed[0]
	if err := s.ExtendSituationLease(context.Background(), claim.Situation.ID, claim.ClaimOwner, claim.ClaimToken, now.Add(30*time.Second), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.ExtendSituationLease(context.Background(), claim.Situation.ID, "worker-2", claim.ClaimToken, now.Add(31*time.Second), time.Minute); !errors.Is(err, ErrSituationLeaseLost) {
		t.Fatalf("wrong-owner extension err = %v", err)
	}
}

func TestCommitSituationTransitionRejectsExpiredReclaimedFence(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "fenced-situation", "host=fenced-situation", "", situationmodel.LifecycleActive, now)
	first, err := s.ClaimDueSituations(context.Background(), "worker-1", now, time.Minute, 1)
	if err != nil || len(first) != 1 {
		t.Fatalf("first claim=%+v err=%v", first, err)
	}
	second, err := s.ClaimDueSituations(context.Background(), "worker-2", now.Add(2*time.Minute), time.Minute, 1)
	if err != nil || len(second) != 1 {
		t.Fatalf("second claim=%+v err=%v", second, err)
	}
	if first[0].ClaimToken >= second[0].ClaimToken {
		t.Fatalf("claim tokens first=%d second=%d", first[0].ClaimToken, second[0].ClaimToken)
	}
	if err := s.ExtendSituationLease(context.Background(), second[0].Situation.ID, second[0].ClaimOwner, first[0].ClaimToken, now.Add(2*time.Minute+time.Second), time.Minute); !errors.Is(err, ErrSituationLeaseLost) {
		t.Fatalf("stale-token extension err=%v", err)
	}
	next := now.Add(5 * time.Minute)
	transition := situationmodel.Transition{
		ID: "fenced-transition", SituationID: first[0].Situation.ID, InputVersion: first[0].Situation.InputVersion,
		Lifecycle: situationmodel.LifecycleActive, Attention: situationmodel.AttentionInvestigate,
		ActionContract: situationmodel.ActionContract{NextUpdateAt: &next}, CreatedAt: now.Add(2*time.Minute + time.Second),
	}
	if err := s.CommitSituationTransition(context.Background(), first[0], transition, nil); !errors.Is(err, ErrSituationLeaseLost) {
		t.Fatalf("stale commit err=%v", err)
	}
	var owner string
	var token int64
	if err := s.DB().QueryRow(`SELECT lease_owner, claim_token FROM situations WHERE id = ?`, "fenced-situation").Scan(&owner, &token); err != nil {
		t.Fatal(err)
	}
	if owner != "worker-2" || token != second[0].ClaimToken {
		t.Fatalf("current claim owner=%s token=%d", owner, token)
	}
	transition.SituationID = second[0].Situation.ID
	transition.InputVersion = second[0].Situation.InputVersion
	if err := s.CommitSituationTransition(context.Background(), second[0], transition, nil); err != nil {
		t.Fatal(err)
	}
}

func TestCommitSituationTransitionRejectsStaleInputVersion(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	seedIncident(t, s, "transition-inc", "host=transition", "ready", now)
	firstInput := SituationInput{ID: "transition-input-1", IdempotencyKey: "incident:transition:1", IncidentID: "transition-inc", Kind: "incident_created", GroupKey: "host=transition", OccurredAt: now}
	seedSituationInput(t, s, firstInput, "claimed", "worker-1", now.Add(time.Minute))
	situation, err := s.ApplySituationInput(context.Background(), claimedSituationInputForTest(firstInput, "worker-1"))
	if err != nil {
		t.Fatal(err)
	}
	oldClaims, err := s.ClaimDueSituations(context.Background(), "reconciler-old", now, time.Minute, 1)
	if err != nil || len(oldClaims) != 1 {
		t.Fatalf("old claim=%+v err=%v", oldClaims, err)
	}
	secondInput := SituationInput{ID: "transition-input-2", IdempotencyKey: "incident:transition:2", IncidentID: "transition-inc", Kind: "membership_changed", GroupKey: "host=transition", OccurredAt: now.Add(time.Second)}
	seedSituationInput(t, s, secondInput, "claimed", "worker-1", now.Add(time.Minute))
	if _, err := s.ApplySituationInput(context.Background(), claimedSituationInputForTest(secondInput, "worker-1")); err != nil {
		t.Fatal(err)
	}
	transition := situationmodel.Transition{
		ID: "transition-1", SituationID: situation.ID, InputVersion: 1,
		Lifecycle: situationmodel.LifecycleActive, Attention: situationmodel.AttentionInvestigate,
		CreatedAt: now.Add(2 * time.Second),
	}
	if err := s.CommitSituationTransition(context.Background(), oldClaims[0], transition, nil); !errors.Is(err, ErrSituationVersionConflict) {
		t.Fatalf("stale commit err = %v", err)
	}
	got, err := s.SituationForIncident(context.Background(), "transition-inc")
	if err != nil {
		t.Fatal(err)
	}
	if got.Attention != situationmodel.AttentionObserve || got.InputVersion != 2 {
		t.Fatalf("stale commit mutated situation: %+v", got)
	}
}

func TestCommitSituationTransitionPersistsRecoveryPendingAndRefire(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	seedIncident(t, s, "lifecycle-inc", "host=lifecycle", "ready", now)
	in := SituationInput{ID: "lifecycle-input", IdempotencyKey: "incident:lifecycle", IncidentID: "lifecycle-inc", Kind: "incident_created", GroupKey: "host=lifecycle", OccurredAt: now}
	seedSituationInput(t, s, in, "claimed", "worker-1", now.Add(time.Minute))
	created, err := s.ApplySituationInput(context.Background(), claimedSituationInputForTest(in, "worker-1"))
	if err != nil {
		t.Fatal(err)
	}
	claims, err := s.ClaimDueSituations(context.Background(), "reconciler-1", now, time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("pending claim=%+v err=%v", claims, err)
	}
	graceUntil := now.Add(2 * time.Minute)
	pending := situationmodel.Transition{
		ID: "pending-transition", SituationID: created.ID, InputVersion: 1,
		Lifecycle: situationmodel.LifecycleRecoveryPending, Attention: situationmodel.AttentionInvestigate,
		ActionContract: situationmodel.ActionContract{NextUpdateAt: &graceUntil}, CreatedAt: now.Add(time.Second),
	}
	if err := s.CommitSituationTransition(context.Background(), claims[0], pending, nil); err != nil {
		t.Fatal(err)
	}
	got, err := s.SituationForIncident(context.Background(), "lifecycle-inc")
	if err != nil {
		t.Fatal(err)
	}
	if got.Lifecycle != situationmodel.LifecycleRecoveryPending || got.RecoveryObservedAt == nil || got.GraceUntil == nil || !got.GraceUntil.Equal(graceUntil) || len(got.DueReasons) != 0 {
		t.Fatalf("pending situation=%+v", got)
	}
	if got.PublicHandle != nil {
		t.Fatalf("unpublished transition minted handle %q", *got.PublicHandle)
	}
	next := now.Add(5 * time.Minute)
	refired := situationmodel.Transition{
		ID: "refire-transition", SituationID: created.ID, InputVersion: 1,
		Lifecycle: situationmodel.LifecycleActive, Attention: situationmodel.AttentionUrgent,
		ActionContract: situationmodel.ActionContract{NextUpdateAt: &next}, CreatedAt: now.Add(2 * time.Second),
	}
	claims, err = s.ClaimDueSituations(context.Background(), "reconciler-2", graceUntil, time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("refire claim=%+v err=%v", claims, err)
	}
	if err := s.CommitSituationTransition(context.Background(), claims[0], refired, nil); err != nil {
		t.Fatal(err)
	}
	got, err = s.SituationForIncident(context.Background(), "lifecycle-inc")
	if err != nil {
		t.Fatal(err)
	}
	if got.Lifecycle != situationmodel.LifecycleActive || got.RecoveryObservedAt != nil || got.GraceUntil != nil || !got.NextAssessmentAt.Equal(next) {
		t.Fatalf("refired situation=%+v", got)
	}
}

func TestCommitSituationTransitionRecoveryRetainsGraceEvidence(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "recovering-situation", "host=recovering", "", situationmodel.LifecycleActive, now)
	claims, err := s.ClaimDueSituations(context.Background(), "reconciler-1", now, time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("pending claim=%+v err=%v", claims, err)
	}
	graceUntil := now.Add(2 * time.Minute)
	pending := situationmodel.Transition{
		ID: "recovering-pending", SituationID: "recovering-situation", InputVersion: 1,
		Lifecycle: situationmodel.LifecycleRecoveryPending, Attention: situationmodel.AttentionUrgent,
		ActionContract: situationmodel.ActionContract{NextUpdateAt: &graceUntil}, CreatedAt: now.Add(time.Second),
	}
	if err := s.CommitSituationTransition(context.Background(), claims[0], pending, nil); err != nil {
		t.Fatal(err)
	}
	recoveredAt := graceUntil.Add(time.Second)
	recovered := situationmodel.Transition{
		ID: "recovered", SituationID: "recovering-situation", InputVersion: 1,
		Lifecycle: situationmodel.LifecycleRecovered, Attention: situationmodel.AttentionUrgent, CreatedAt: recoveredAt,
	}
	claims, err = s.ClaimDueSituations(context.Background(), "reconciler-2", graceUntil, time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("recovery claim=%+v err=%v", claims, err)
	}
	if err := s.CommitSituationTransition(context.Background(), claims[0], recovered, nil); err != nil {
		t.Fatal(err)
	}
	got, err := s.CurrentSituationForGroup(context.Background(), "host=recovering")
	if err != nil {
		t.Fatal(err)
	}
	if got.Lifecycle != situationmodel.LifecycleRecovered || got.Attention != situationmodel.AttentionObserve || got.RecoveryObservedAt == nil || got.GraceUntil == nil || got.TerminalAt == nil {
		t.Fatalf("recovered situation=%+v", got)
	}
}

func TestCommitSituationTransitionIgnoresMutableCompatibilityFiring(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	seedIncident(t, s, "firing-inc", "host=firing", "ready", now)
	alert := Alert{ID: "firing-alert", Fingerprint: "firing-fingerprint", Status: "firing", Labels: map[string]string{}, Annotations: map[string]string{}, StartsAt: now, ReceivedAt: now}
	if _, err := s.UpsertAlertByFingerprint(context.Background(), alert); err != nil {
		t.Fatal(err)
	}
	if err := s.AddAlertToIncident(context.Background(), "firing-inc", alert.ID, now); err != nil {
		t.Fatal(err)
	}
	in := SituationInput{ID: "firing-input", IdempotencyKey: "incident:firing", IncidentID: "firing-inc", Kind: "incident_created", GroupKey: "host=firing", OccurredAt: now}
	seedSituationInput(t, s, in, "claimed", "worker-1", now.Add(time.Minute))
	created, err := s.ApplySituationInput(context.Background(), claimedSituationInputForTest(in, "worker-1"))
	if err != nil {
		t.Fatal(err)
	}
	claims, err := s.ClaimDueSituations(context.Background(), "reconciler", now, time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("close claim=%+v err=%v", claims, err)
	}
	transition := situationmodel.Transition{
		ID: "unknown-transition", SituationID: created.ID, InputVersion: 1,
		Lifecycle: situationmodel.LifecycleClosedUnknown, Attention: situationmodel.AttentionObserve,
		Reason: string(situationmodel.TerminalReasonResolutionMissing), CreatedAt: now.Add(time.Minute),
	}
	if err := s.CommitSituationTransition(context.Background(), claims[0], transition, nil); err != nil {
		t.Fatalf("closed unknown from compatibility projection: %v", err)
	}
	got, err := s.SituationForIncident(context.Background(), "firing-inc")
	if err != nil {
		t.Fatal(err)
	}
	if got.Lifecycle != situationmodel.LifecycleClosedUnknown {
		t.Fatalf("compatibility firing left lifecycle %q", got.Lifecycle)
	}
}

func TestCommitSituationTransitionUsesFreshAuthoritativeFiringDeadline(t *testing.T) {
	for _, tc := range []struct {
		name      string
		closeAt   time.Duration
		wantError bool
	}{
		{"fresh", time.Hour, true},
		{"stale", 24*time.Hour + time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			now := mustSituationTime(t, "2026-08-20T10:00:00Z")
			incidentID := "authoritative-" + tc.name
			deliveryID := "delivery-" + tc.name
			seedIncident(t, s, incidentID, "host="+tc.name, "ready", now)
			if _, err := s.AcceptDeliveries(context.Background(), []DeliveryInput{{
				ID:     deliveryID,
				Alert:  Alert{ID: "alert-" + tc.name, Fingerprint: "fingerprint-" + tc.name, Status: "firing", Labels: map[string]string{}, Annotations: map[string]string{}, StartsAt: now, ReceivedAt: now},
				Source: "alertmanager", SourceEpisodeKey: "episode-" + tc.name,
				StartedAtBasis: situationmodel.SourceTimeBasisReceiptFallback, ResolvedAtBasis: situationmodel.SourceTimeBasisMissing,
				ReceiverGroupingIdentity: "host=" + tc.name, PayloadDigest: "sha256:" + tc.name,
			}}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB().Exec(`INSERT INTO incident_alert_deliveries(incident_id, delivery_id, created_at) VALUES (?, ?, ?)`, incidentID, deliveryID, canonicalTime(now)); err != nil {
				t.Fatal(err)
			}
			in := SituationInput{ID: "input-" + tc.name, IdempotencyKey: "incident:" + tc.name, IncidentID: incidentID, DeliveryID: &deliveryID, Kind: "incident_created", GroupKey: "host=" + tc.name, OccurredAt: now}
			seedSituationInput(t, s, in, "claimed", "input-worker", now.Add(time.Minute))
			created, err := s.ApplySituationInput(context.Background(), claimedSituationInputForTest(in, "input-worker"))
			if err != nil {
				t.Fatal(err)
			}
			if !created.LastLifecycleObservedAt.Equal(now) {
				t.Fatalf("last lifecycle observation=%s", created.LastLifecycleObservedAt)
			}
			claims, err := s.ClaimDueSituations(context.Background(), "reconciler", now, time.Minute, 1)
			if err != nil || len(claims) != 1 {
				t.Fatalf("claim=%+v err=%v", claims, err)
			}
			transition := situationmodel.Transition{
				ID: "close-" + tc.name, SituationID: created.ID, InputVersion: created.InputVersion,
				Lifecycle: situationmodel.LifecycleClosedUnknown, Attention: situationmodel.AttentionObserve,
				Reason: string(situationmodel.TerminalReasonResolutionMissing), CreatedAt: now.Add(tc.closeAt),
			}
			err = s.CommitSituationTransition(context.Background(), claims[0], transition, nil)
			if tc.wantError && (err == nil || !strings.Contains(err.Error(), "firing")) {
				t.Fatalf("fresh authoritative close err=%v", err)
			}
			if !tc.wantError && err != nil {
				t.Fatalf("stale authoritative close err=%v", err)
			}
		})
	}
}

func TestApplySituationInputInternalEventDoesNotAdvanceLifecycleObservation(t *testing.T) {
	s := newTestStore(t)
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	seedIncident(t, s, "observation-inc", "host=observation", "ready", now)
	deliveryID := "observation-delivery"
	resolvedAt := now
	if _, err := s.AcceptDeliveries(context.Background(), []DeliveryInput{{
		ID:     deliveryID,
		Alert:  Alert{ID: "observation-alert", Fingerprint: "observation-fingerprint", Status: "resolved", Labels: map[string]string{}, Annotations: map[string]string{}, StartsAt: now, EndsAt: &resolvedAt, ReceivedAt: now},
		Source: "alertmanager", SourceEpisodeKey: "observation-episode", SourceResolvedAt: &resolvedAt,
		StartedAtBasis: situationmodel.SourceTimeBasisReceiptFallback, ResolvedAtBasis: situationmodel.SourceTimeBasisSourcePayload,
		ReceiverGroupingIdentity: "host=observation", PayloadDigest: "sha256:observation",
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`INSERT INTO incident_alert_deliveries(incident_id, delivery_id, created_at) VALUES (?, ?, ?)`, "observation-inc", deliveryID, canonicalTime(now)); err != nil {
		t.Fatal(err)
	}
	first := SituationInput{ID: "observation-input", IdempotencyKey: "observation:delivery", IncidentID: "observation-inc", DeliveryID: &deliveryID, Kind: "incident_created", GroupKey: "host=observation", OccurredAt: now}
	seedSituationInput(t, s, first, "claimed", "worker-1", now.Add(time.Minute))
	created, err := s.ApplySituationInput(context.Background(), claimedSituationInputForTest(first, "worker-1"))
	if err != nil {
		t.Fatal(err)
	}
	internalAt := now.Add(2 * time.Hour)
	internal := SituationInput{ID: "observation-internal", IdempotencyKey: "observation:internal", IncidentID: "observation-inc", Kind: "incident_ready", GroupKey: "host=observation", OccurredAt: internalAt}
	seedSituationInput(t, s, internal, "claimed", "worker-2", internalAt.Add(time.Minute))
	updated, err := s.ApplySituationInput(context.Background(), claimedSituationInputForTest(internal, "worker-2"))
	if err != nil {
		t.Fatal(err)
	}
	if !updated.LastLifecycleObservedAt.Equal(created.LastLifecycleObservedAt) || !updated.LastLifecycleObservedAt.Equal(now) {
		t.Fatalf("internal event advanced lifecycle observation from %s to %s", created.LastLifecycleObservedAt, updated.LastLifecycleObservedAt)
	}
}

func seedSituationInput(t *testing.T, s *Store, in SituationInput, status, owner string, leaseExpires time.Time) {
	t.Helper()
	var deliveryID any
	if in.DeliveryID != nil {
		deliveryID = *in.DeliveryID
	}
	var leaseOwner, leaseAt any
	var claimToken int64
	if owner != "" {
		leaseOwner = owner
		leaseAt = canonicalTime(leaseExpires)
		claimToken = 1
	}
	if _, err := s.DB().Exec(`
		INSERT INTO situation_input_outbox
			(id, idempotency_key, incident_id, delivery_id, kind, group_key, occurred_at, status, lease_owner, lease_expires_at, claim_token)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		in.ID, in.IdempotencyKey, in.IncidentID, deliveryID, in.Kind, in.GroupKey, canonicalTime(in.OccurredAt), status, leaseOwner, leaseAt, claimToken); err != nil {
		t.Fatal(err)
	}
}

func claimedSituationInputForTest(in SituationInput, owner string) SituationInput {
	in.ClaimOwner = owner
	in.ClaimToken = 1
	return in
}

func insertSituationFixture(t *testing.T, s *Store, id, groupKey, handle string, lifecycle situationmodel.Lifecycle, now time.Time) {
	t.Helper()
	if _, err := insertSituationFixtureErr(s, id, groupKey, handle, lifecycle, now); err != nil {
		t.Fatal(err)
	}
}

func insertSituationFixtureErr(s *Store, id, groupKey, handle string, lifecycle situationmodel.Lifecycle, now time.Time) (sql.Result, error) {
	var publicHandle any
	if handle != "" {
		publicHandle = handle
	}
	var recoveryObservedAt, graceUntil, terminalAt, terminalReason any
	if lifecycle == situationmodel.LifecycleRecoveryPending || lifecycle == situationmodel.LifecycleRecovered {
		recoveryObservedAt = canonicalTime(now.Add(-time.Minute))
		graceUntil = canonicalTime(now)
	}
	if lifecycle == situationmodel.LifecycleRecovered || lifecycle == situationmodel.LifecycleClosedUnknown {
		terminalAt = canonicalTime(now)
	}
	if lifecycle == situationmodel.LifecycleClosedUnknown {
		terminalReason = string(situationmodel.TerminalReasonResolutionMissing)
	}
	return s.DB().Exec(`
		INSERT INTO situations (
			id, group_key, public_handle, lifecycle, attention, input_version,
			opened_at, effective_started_at, effective_started_at_basis,
			first_received_at, last_lifecycle_observed_at, recovery_observed_at, grace_until, terminal_at, terminal_reason,
			next_assessment_at, due_reasons_json, attempt_count, created_at, updated_at
		) VALUES (?, ?, ?, ?, 'observe', 1, ?, ?, 'source_payload', ?, ?, ?, ?, ?, ?, ?, '[]', 0, ?, ?)`,
		id, groupKey, publicHandle, lifecycle, canonicalTime(now), canonicalTime(now), canonicalTime(now),
		canonicalTime(now), recoveryObservedAt, graceUntil, terminalAt, terminalReason, canonicalTime(now), canonicalTime(now), canonicalTime(now))
}

func mustSituationTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
