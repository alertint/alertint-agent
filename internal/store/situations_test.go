// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Fixture helpers
// ----------------------------------------------------------------------

// insertIncidentAndInputKind inserts a fresh collecting Incident and a
// pending situation_input_outbox row of the given kind for it, directly —
// bypassing ApplyCorrelatedDelivery/MarkIncidentReadyWithSituationInput so
// these tests can drive ApplySituationInput's owner-selection and
// idempotency behavior against precisely controlled fixtures.
func insertIncidentAndInputKind(t *testing.T, st *Store, incidentID, inputID, groupKey, kind string, occurredAt time.Time) {
	t.Helper()
	ctx := context.Background()
	if err := st.InsertIncident(ctx, Incident{
		ID:           incidentID,
		GroupKey:     groupKey,
		FirstAlertAt: occurredAt,
		LastAlertAt:  occurredAt,
		ReadyAt:      occurredAt.Add(time.Minute),
	}); err != nil {
		t.Fatalf("insert incident %s: %v", incidentID, err)
	}
	// incidents_one_collecting_group_idx allows only one "collecting"
	// Incident per group_key; move this one on immediately so a later
	// same-group fixture Incident (a distinct correlation event, same exact
	// group) does not collide with it, matching how a real Incident leaves
	// "collecting" long before a fresh one opens under the same group.
	if err := st.MarkIncidentReady(ctx, incidentID); err != nil {
		t.Fatalf("mark incident %s ready: %v", incidentID, err)
	}
	insertInputForExistingIncident(t, st, incidentID, inputID, groupKey, kind, occurredAt)
}

// insertInputForExistingIncident inserts one more pending situation_input_outbox
// row for an Incident that already exists — used to prove a second input for
// the same Incident joins its existing Situation rather than re-inserting
// the Incident itself.
func insertInputForExistingIncident(t *testing.T, st *Store, incidentID, inputID, groupKey, kind string, occurredAt time.Time) {
	t.Helper()
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO situation_input_outbox (id, idempotency_key, incident_id, kind, group_key, occurred_at, status)
		VALUES (?, ?, ?, ?, ?, ?, 'pending')`,
		inputID, "idem:"+inputID, incidentID, kind, groupKey, canonicalTime(occurredAt)); err != nil {
		t.Fatalf("insert situation input %s: %v", inputID, err)
	}
}

// insertIncidentAndInput inserts a fresh collecting Incident plus one
// pending "incident_created" situation_input_outbox row for it.
func insertIncidentAndInput(t *testing.T, st *Store, incidentID, inputID, groupKey string, occurredAt time.Time) {
	t.Helper()
	insertIncidentAndInputKind(t, st, incidentID, inputID, groupKey, "incident_created", occurredAt)
}

// insertArtifactSituationInput inserts one pending operator-artifact
// situation_input_outbox row (kind operator_annotation_recorded or
// captured_verdict_recorded) for an Incident that already exists, with
// journal_state='pending' from creation — matching what a later task's
// enqueue path will do; this task's own tests exercise only
// ApplySituationInput's R1/R2 handling of an already-pending artifact row,
// never the enqueue path itself.
func insertArtifactSituationInput(t *testing.T, st *Store, incidentID, inputID, groupKey, kind string, annotationID, verdictID any, occurredAt time.Time) {
	t.Helper()
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO situation_input_outbox (
			id, idempotency_key, incident_id, kind, group_key, occurred_at,
			status, annotation_id, verdict_id, journal_state
		) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, 'pending')`,
		inputID, "idem:"+inputID, incidentID, kind, groupKey, canonicalTime(occurredAt), annotationID, verdictID); err != nil {
		t.Fatalf("insert artifact situation input %s: %v", inputID, err)
	}
}

// insertIncidentAndDeliveryInput inserts a fresh collecting Incident, links
// it to an already-accepted delivery's immutable ownership row, and inserts
// one pending "membership_changed" situation_input_outbox row referencing
// that delivery — enough for ApplySituationInput to derive source times from
// a real, immutable alert_deliveries row.
func insertIncidentAndDeliveryInput(t *testing.T, st *Store, incidentID, inputID, groupKey, deliveryID string, occurredAt time.Time) {
	t.Helper()
	ctx := context.Background()
	if err := st.InsertIncident(ctx, Incident{
		ID:           incidentID,
		GroupKey:     groupKey,
		FirstAlertAt: occurredAt,
		LastAlertAt:  occurredAt,
		ReadyAt:      occurredAt.Add(time.Minute),
	}); err != nil {
		t.Fatalf("insert incident %s: %v", incidentID, err)
	}
	if err := st.MarkIncidentReady(ctx, incidentID); err != nil {
		t.Fatalf("mark incident %s ready: %v", incidentID, err)
	}
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO incident_alert_deliveries (incident_id, delivery_id, created_at) VALUES (?, ?, ?)`,
		incidentID, deliveryID, canonicalTime(occurredAt)); err != nil {
		t.Fatalf("link delivery %s to incident %s: %v", deliveryID, incidentID, err)
	}
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO situation_input_outbox (id, idempotency_key, incident_id, delivery_id, kind, group_key, occurred_at, status)
		VALUES (?, ?, ?, ?, 'membership_changed', ?, ?, 'pending')`,
		inputID, "idem:"+inputID, incidentID, deliveryID, groupKey, canonicalTime(occurredAt)); err != nil {
		t.Fatalf("insert situation input %s: %v", inputID, err)
	}
}

// deliveryFixtureWithSource builds on deliveryFixture (deliveries_test.go)
// to additionally control the delivery's immutable SourceStartedAt/basis
// independently of its ReceivedAt, so time-computation tests can pin exact
// values for both.
//
//nolint:unparam // basis is a general fixture parameter; every current test happens to use SourceTimeBasisSourcePayload.
func deliveryFixtureWithSource(id, fingerprint string, receivedAt, sourceStartedAt time.Time, basis situationmodel.SourceTimeBasis) DeliveryInput {
	d := deliveryFixture(id, fingerprint, receivedAt)
	start := sourceStartedAt
	d.SourceStartedAt = &start
	d.StartedAtBasis = basis
	return d
}

func claimOneInput(t *testing.T, st *Store, owner string, now time.Time) SituationClaim {
	t.Helper()
	claims, err := st.ClaimSituationInputs(context.Background(), owner, now, time.Minute, 1)
	if err != nil {
		t.Fatalf("claim situation inputs: %v", err)
	}
	if len(claims) != 1 {
		t.Fatalf("claimed = %d, want 1", len(claims))
	}
	return claims[0]
}

func listSituations(t *testing.T, st *Store) []situationmodel.Situation {
	t.Helper()
	rows, err := st.db.QueryContext(context.Background(), situationSelect+` ORDER BY created_at ASC, id ASC`)
	if err != nil {
		t.Fatalf("list situations: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []situationmodel.Situation
	for rows.Next() {
		sit, err := scanSituation(rows)
		if err != nil {
			t.Fatalf("scan situation: %v", err)
		}
		out = append(out, sit)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate situations: %v", err)
	}
	return out
}

func getSituationByID(t *testing.T, st *Store, id string) situationmodel.Situation {
	t.Helper()
	row := st.db.QueryRowContext(context.Background(), situationSelect+` WHERE id = ?`, id)
	got, err := scanSituation(row)
	if err != nil {
		t.Fatalf("get situation %s: %v", id, err)
	}
	return got
}

func listSituationIncidentIDs(t *testing.T, st *Store, situationID string) []string {
	t.Helper()
	rows, err := st.db.QueryContext(context.Background(), `
		SELECT incident_id FROM situation_incidents WHERE situation_id = ? ORDER BY attached_at ASC, incident_id ASC`, situationID)
	if err != nil {
		t.Fatalf("list situation incidents: %v", err)
	}
	ids, err := scanStringRows(rows)
	if err != nil {
		t.Fatalf("scan situation incidents: %v", err)
	}
	return ids
}

func assertSituationLeaseOwner(t *testing.T, st *Store, situationID, want string) {
	t.Helper()
	got := getSituationByID(t, st, situationID)
	if got.LeaseOwner == nil || *got.LeaseOwner != want {
		t.Fatalf("lease_owner = %v, want %q", got.LeaseOwner, want)
	}
}

// dueSituationFixture creates one Situation (via a real ApplySituationInput
// call) whose next_assessment_at already equals now, so it is immediately
// eligible for ClaimDueSituations.
func dueSituationFixture(t *testing.T) (*Store, string, time.Time) {
	t.Helper()
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 4, 0, 0, 0, time.UTC)
	insertIncidentAndInput(t, st, "inc-due", "input-due", "service=due", now)
	claim := claimOneInput(t, st, "worker-seed", now)
	if err := st.ApplySituationInput(context.Background(), claim); err != nil {
		t.Fatalf("seed apply: %v", err)
	}
	sits := listSituations(t, st)
	if len(sits) != 1 {
		t.Fatalf("situations = %+v, want exactly 1", sits)
	}
	return st, sits[0].ID, now
}

func TestSituationSupersedeGuardColumnsDefaultClear(t *testing.T) {
	st, situationID, _ := dueSituationFixture(t)
	var streak, protected int
	if err := st.db.QueryRowContext(context.Background(), `
		SELECT supersede_streak, lease_protected FROM situations WHERE id = ?`, situationID).Scan(&streak, &protected); err != nil {
		t.Fatalf("read supersede guard columns: %v", err)
	}
	if streak != 0 || protected != 0 {
		t.Fatalf("new Situation guard = (%d, %d), want (0, 0)", streak, protected)
	}
}

func applyGuardTestInput(t *testing.T, st *Store, incidentID, inputID string, now time.Time) {
	t.Helper()
	insertIncidentAndInput(t, st, incidentID, inputID, "service=due", now)
	claim := claimOneInput(t, st, "input-worker", now)
	if err := st.ApplySituationInput(context.Background(), claim); err != nil {
		t.Fatalf("apply input %s: %v", inputID, err)
	}
}

func claimGuardTestSituation(t *testing.T, st *Store, now time.Time) situationmodel.Situation {
	t.Helper()
	claims, err := st.ClaimDueSituations(context.Background(), "controller", now, time.Minute, 1)
	if err != nil {
		t.Fatalf("claim due Situation: %v", err)
	}
	if len(claims) != 1 {
		t.Fatalf("claimed %d Situations, want one", len(claims))
	}
	return claims[0]
}

func TestJoinCountsSupersededLiveClaims(t *testing.T) {
	st, situationID, _ := dueSituationFixture(t)
	now := time.Now().UTC().Add(2 * time.Second)
	claimGuardTestSituation(t, st, now)
	applyGuardTestInput(t, st, "inc-guard-1", "input-guard-1", now)
	first := getSituationByID(t, st, situationID)
	if first.SupersedeStreak != 1 || first.LeaseOwner != nil {
		t.Fatalf("after first live claim lost: streak=%d lease=%v, want 1 and nil", first.SupersedeStreak, first.LeaseOwner)
	}
	applyGuardTestInput(t, st, "inc-guard-2", "input-guard-2", now)
	if got := getSituationByID(t, st, situationID).SupersedeStreak; got != 1 {
		t.Fatalf("second input during same claim: streak=%d, want 1", got)
	}
	claimGuardTestSituation(t, st, now)
	applyGuardTestInput(t, st, "inc-guard-3", "input-guard-3", now)
	if got := getSituationByID(t, st, situationID).SupersedeStreak; got != 2 {
		t.Fatalf("after second live claim lost: streak=%d, want 2", got)
	}
	applyGuardTestInput(t, st, "inc-guard-4", "input-guard-4", now)
	if got := getSituationByID(t, st, situationID).SupersedeStreak; got != 2 {
		t.Fatalf("unclaimed input: streak=%d, want 2", got)
	}
}

func twoSupersedesFixture(t *testing.T) (*Store, string, time.Time) {
	t.Helper()
	st, situationID, _ := dueSituationFixture(t)
	now := time.Now().UTC().Add(2 * time.Second)
	claimGuardTestSituation(t, st, now)
	applyGuardTestInput(t, st, "inc-guard-a", "input-guard-a", now)
	claimGuardTestSituation(t, st, now)
	applyGuardTestInput(t, st, "inc-guard-b", "input-guard-b", now)
	if got := getSituationByID(t, st, situationID).SupersedeStreak; got != 2 {
		t.Fatalf("fixture streak=%d, want 2", got)
	}
	return st, situationID, now
}

func TestClaimProtectsAfterTwoSupersedes(t *testing.T) {
	st, situationID, now := twoSupersedesFixture(t)
	claim := claimGuardTestSituation(t, st, now)
	if claim.ID != situationID || !claim.LeaseProtected {
		t.Fatalf("claim Situation=%s protected=%v, want %s and true", claim.ID, claim.LeaseProtected, situationID)
	}
	if got := getSituationByID(t, st, situationID); !got.LeaseProtected {
		t.Fatal("durable lease protection is false after guarded claim")
	}
}

func TestProtectedClaimDefersJoin(t *testing.T) {
	st, situationID, now := twoSupersedesFixture(t)
	insertIncidentAndInput(t, st, "inc-guard-held", "input-guard-held", "service=due", now)
	inputClaim := claimOneInput(t, st, "input-worker", now)
	claimGuardTestSituation(t, st, now)
	before := getSituationByID(t, st, situationID)
	membersBefore := listSituationIncidentIDs(t, st, situationID)
	if err := st.ApplySituationInput(context.Background(), inputClaim); !errors.Is(err, ErrSituationProtected) {
		t.Fatalf("protected apply error = %v, want ErrSituationProtected", err)
	}
	after := getSituationByID(t, st, situationID)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("protected Situation changed: before=%+v after=%+v", before, after)
	}
	if got := listSituationIncidentIDs(t, st, situationID); !reflect.DeepEqual(got, membersBefore) {
		t.Fatalf("protected membership changed: before=%v after=%v", membersBefore, got)
	}
	var status string
	if err := st.db.QueryRowContext(context.Background(), `SELECT status FROM situation_input_outbox WHERE id = ?`, inputClaim.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "claimed" {
		t.Fatalf("protected input status = %q, want claimed", status)
	}
}

func TestHeldInputBatchDoesNotBlockAnotherSituation(t *testing.T) {
	st, _, now := twoSupersedesFixture(t)
	claimGuardTestSituation(t, st, now)

	for i := range 16 {
		insertIncidentAndInput(t, st,
			fmt.Sprintf("inc-held-%02d", i), fmt.Sprintf("input-held-%02d", i), "service=due", now)
	}
	insertIncidentAndInput(t, st, "inc-other", "input-other", "service=other", now.Add(time.Second))

	worker := situation.NewInputWorker(st, situation.WorkerConfig{
		Owner: "input-worker", Now: func() time.Time { return now.Add(2 * time.Second) },
	}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if handled, err := worker.Drain(ctx); err != nil || handled != 1 {
		t.Fatalf("drain = (%d, %v), want (1, nil)", handled, err)
	}

	rows, err := st.db.QueryContext(ctx, `
		SELECT id, status, attempt_count FROM situation_input_outbox
		WHERE id LIKE 'input-held-%' OR id = 'input-other'`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	held := 0
	otherApplied := false
	for rows.Next() {
		var id, status string
		var attempts int
		if err := rows.Scan(&id, &status, &attempts); err != nil {
			t.Fatal(err)
		}
		if id == "input-other" {
			otherApplied = status == "applied" && attempts == 1
			continue
		}
		if status != "pending" || attempts != 0 {
			t.Fatalf("held input %s = (%s, %d), want (pending, 0)", id, status, attempts)
		}
		held++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if held != 16 || !otherApplied {
		t.Fatalf("held = %d, other applied = %v; want 16 and true", held, otherApplied)
	}
}

type countingDeferStore struct {
	*Store

	deferCalls int
}

func (s *countingDeferStore) DeferSituationInput(ctx context.Context, claim SituationClaim, retryAt time.Time) error {
	s.deferCalls++
	return s.Store.DeferSituationInput(ctx, claim, retryAt)
}

func TestProtectedGroupInputsAreNotClaimed(t *testing.T) {
	st, _, now := twoSupersedesFixture(t)
	claimGuardTestSituation(t, st, now)
	for i := range 16 {
		insertIncidentAndInput(t, st,
			fmt.Sprintf("inc-unclaimed-%02d", i), fmt.Sprintf("input-unclaimed-%02d", i), "service=due", now)
	}
	insertIncidentAndInput(t, st, "inc-unclaimed-other", "input-unclaimed-other", "service=other", now.Add(time.Second))

	clock := now.Add(2 * time.Second)
	counting := &countingDeferStore{Store: st}
	worker := situation.NewInputWorker(counting, situation.WorkerConfig{
		Owner: "input-worker", Now: func() time.Time { return clock },
	}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if handled, err := worker.Drain(ctx); err != nil || handled != 1 {
		t.Fatalf("first drain = (%d, %v), want (1, nil)", handled, err)
	}
	clock = clock.Add(2 * time.Second)
	if handled, err := worker.Drain(ctx); err != nil || handled != 0 {
		t.Fatalf("second drain = (%d, %v), want (0, nil)", handled, err)
	}
	if counting.deferCalls != 0 {
		t.Fatalf("defer calls = %d, want 0", counting.deferCalls)
	}
	var unclaimed int
	if err := st.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM situation_input_outbox
		WHERE id LIKE 'input-unclaimed-%' AND id != 'input-unclaimed-other'
		  AND status = 'pending' AND claim_token = 0`,
	).Scan(&unclaimed); err != nil {
		t.Fatal(err)
	}
	if unclaimed != 16 {
		t.Fatalf("unclaimed protected inputs = %d, want 16", unclaimed)
	}
	var otherStatus string
	if err := st.db.QueryRowContext(ctx, `SELECT status FROM situation_input_outbox WHERE id = 'input-unclaimed-other'`).Scan(&otherStatus); err != nil {
		t.Fatal(err)
	}
	if otherStatus != "applied" {
		t.Fatalf("other input status = %q, want applied", otherStatus)
	}
}

func TestClaimSituationInputsScansOnlyOpenSituations(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	rows, err := st.db.QueryContext(ctx, `EXPLAIN QUERY PLAN `+claimSituationInputsQuery,
		"input-worker", "2026-09-25T12:05:00Z", "2026-09-25T12:00:00Z",
		"2026-09-25T12:00:00Z", "2026-09-25T12:00:00Z", 16)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, detail := range plan {
		if strings.Contains(detail, "SCAN situations") && !strings.Contains(detail, "USING INDEX") {
			t.Fatalf("input claim scans all Situation history: %s\n%s", detail, strings.Join(plan, "\n"))
		}
	}
}

func TestReleaseClearsProtectionKeepsStreak(t *testing.T) {
	for _, backoff := range []bool{false, true} {
		name := "plain"
		if backoff {
			name = "with_backoff"
		}
		t.Run(name, func(t *testing.T) {
			st, situationID, now := twoSupersedesFixture(t)
			claimed := claimGuardTestSituation(t, st, now)
			claim := situation.Claim{Situation: claimed, ClaimOwner: "controller", ClaimToken: claimed.ClaimToken}
			var retryAt *time.Time
			if backoff {
				at := now.Add(5 * time.Second)
				retryAt = &at
			}
			if err := st.ReleaseControllerWork(context.Background(), claim, now, retryAt, nil); err != nil {
				t.Fatalf("release protected controller claim: %v", err)
			}
			got := getSituationByID(t, st, situationID)
			if got.LeaseProtected || got.LeaseOwner != nil || got.SupersedeStreak != 2 {
				t.Fatalf("after release: protected=%v lease=%v streak=%d, want false, nil, 2", got.LeaseProtected, got.LeaseOwner, got.SupersedeStreak)
			}
		})
	}
}

func TestExpiredProtectedLeaseDoesNotHold(t *testing.T) {
	st, situationID, now := twoSupersedesFixture(t)
	claimGuardTestSituation(t, st, now)
	before := getSituationByID(t, st, situationID)
	expiredAt := time.Now().UTC().Add(-time.Second)
	if _, err := st.db.ExecContext(context.Background(), `UPDATE situations SET lease_expires_at = ? WHERE id = ?`, canonicalTime(expiredAt), situationID); err != nil {
		t.Fatal(err)
	}
	applyGuardTestInput(t, st, "inc-guard-expired", "input-guard-expired", now)
	after := getSituationByID(t, st, situationID)
	if after.InputVersion != before.InputVersion+1 || after.SupersedeStreak != 2 || after.LeaseProtected || after.LeaseOwner != nil {
		t.Fatalf("expired lease join: version=%d streak=%d protected=%v owner=%v, want version=%d streak=2 protected=false owner=nil",
			after.InputVersion, after.SupersedeStreak, after.LeaseProtected, after.LeaseOwner, before.InputVersion+1)
	}
}

func TestDeferSituationInputGivesBackTheAttempt(t *testing.T) {
	st := newTestStore(t)
	base := time.Now().UTC().Add(2 * time.Second)
	insertIncidentAndInput(t, st, "inc-deferred", "input-deferred", "service=deferred", base)
	if _, err := st.db.ExecContext(context.Background(), `UPDATE situation_input_outbox SET last_error_class = 'earlier_failure' WHERE id = 'input-deferred'`); err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		now := base.Add(time.Duration(i) * 2 * time.Second)
		claim := claimOneInput(t, st, "input-worker", now)
		if claim.AttemptCount != 1 {
			t.Fatalf("defer cycle %d claim attempt=%d, want 1", i, claim.AttemptCount)
		}
		if i == 0 {
			wrong := claim
			wrong.LeaseOwner = "other-worker"
			if err := st.DeferSituationInput(context.Background(), wrong, now.Add(time.Second)); !errors.Is(err, ErrSituationLeaseLost) {
				t.Fatalf("wrong owner defer error=%v, want lease lost", err)
			}
			wrong = claim
			wrong.ClaimToken++
			if err := st.DeferSituationInput(context.Background(), wrong, now.Add(time.Second)); !errors.Is(err, ErrSituationLeaseLost) {
				t.Fatalf("wrong token defer error=%v, want lease lost", err)
			}
		}
		retryAt := now.Add(time.Second)
		if err := st.DeferSituationInput(context.Background(), claim, retryAt); err != nil {
			t.Fatalf("defer cycle %d: %v", i, err)
		}
		var status, retryStr string
		var attempts int
		var lastError, leaseOwner sql.NullString
		if err := st.db.QueryRowContext(context.Background(), `
			SELECT status, attempt_count, retry_at, last_error_class, lease_owner
			FROM situation_input_outbox WHERE id = ?`, claim.ID).Scan(&status, &attempts, &retryStr, &lastError, &leaseOwner); err != nil {
			t.Fatal(err)
		}
		if status != "pending" || attempts != 0 || retryStr != canonicalTime(retryAt) || !lastError.Valid || lastError.String != "earlier_failure" || leaseOwner.Valid {
			t.Fatalf("defer cycle %d: status=%s attempts=%d retry=%s last_error=%v owner=%v", i, status, attempts, retryStr, lastError, leaseOwner)
		}
		if i == 0 {
			if err := st.DeferSituationInput(context.Background(), claim, retryAt); !errors.Is(err, ErrSituationLeaseLost) {
				t.Fatalf("stale defer error=%v, want lease lost", err)
			}
		}
	}
}

func TestCommitResetsStreakAndProtection(t *testing.T) {
	st, situationID, now := twoSupersedesFixture(t)
	insertIncidentAndInput(t, st, "inc-guard-after-commit", "input-guard-after-commit", "service=due", now)
	inputClaim := claimOneInput(t, st, "input-worker", now)
	claimed := claimGuardTestSituation(t, st, now)
	if err := st.ApplySituationInput(context.Background(), inputClaim); !errors.Is(err, ErrSituationProtected) {
		t.Fatalf("apply before protected commit = %v, want protected", err)
	}
	controllerClaim := situation.Claim{Situation: claimed, ClaimOwner: "controller", ClaimToken: claimed.ClaimToken}
	if err := st.CommitController(context.Background(), controllerClaim, basicControllerCommit(situationID, claimed.InputVersion, now)); err != nil {
		t.Fatalf("commit protected claim: %v", err)
	}
	afterCommit := getSituationByID(t, st, situationID)
	if afterCommit.SupersedeStreak != 0 || afterCommit.LeaseProtected || afterCommit.LeaseOwner != nil {
		t.Fatalf("after commit: streak=%d protected=%v owner=%v, want 0, false, nil", afterCommit.SupersedeStreak, afterCommit.LeaseProtected, afterCommit.LeaseOwner)
	}
	if err := st.ApplySituationInput(context.Background(), inputClaim); err != nil {
		t.Fatalf("apply formerly held input: %v", err)
	}
	afterInput := getSituationByID(t, st, situationID)
	if afterInput.InputVersion != afterCommit.InputVersion+1 {
		t.Fatalf("after held input: version=%d, want %d", afterInput.InputVersion, afterCommit.InputVersion+1)
	}
}

// ----------------------------------------------------------------------
// dueReasonForInputKind
// ----------------------------------------------------------------------

func TestDueReasonForInputKindMapsAllKnownKinds(t *testing.T) {
	cases := map[string]situationmodel.DueReason{
		"incident_created":             situationmodel.DueIncidentCreated,
		"membership_changed":           situationmodel.DueMembershipChanged,
		"incident_ready":               situationmodel.DueMembershipChanged,
		"finding_persisted":            situationmodel.DueNewSymptom,
		"triage_skipped":               situationmodel.DueTriageChanged,
		"triage_retry_changed":         situationmodel.DueTriageChanged,
		"triage_exhausted":             situationmodel.DueTriageChanged,
		"incident_resolved":            situationmodel.DueAlertResolved,
		"operator_annotation_recorded": situationmodel.DueOperatorArtifactRecorded,
		"captured_verdict_recorded":    situationmodel.DueOperatorArtifactRecorded,
	}
	for kind, want := range cases {
		got, err := dueReasonForInputKind(kind)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if got != want {
			t.Errorf("%s: got %s, want %s", kind, got, want)
		}
	}
}

func TestDueReasonForInputKindRejectsUnknown(t *testing.T) {
	if _, err := dueReasonForInputKind("bogus"); err == nil {
		t.Fatal("expected error for unknown kind")
	}
}

// ----------------------------------------------------------------------
// Step 1: owner-selection and idempotency (literal brief test plus the
// remaining enumerated properties)
// ----------------------------------------------------------------------

func TestApplySituationInputCreatesThenJoinsExactGroup(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)
	insertIncidentAndInput(t, st, "inc-1", "input-1", "service=api", now)
	claim1 := claimOneInput(t, st, "worker-a", now)
	if err := st.ApplySituationInput(context.Background(), claim1); err != nil {
		t.Fatal(err)
	}

	insertIncidentAndInput(t, st, "inc-2", "input-2", "service=api", now.Add(time.Second))
	claim2 := claimOneInput(t, st, "worker-a", now.Add(time.Second))
	if err := st.ApplySituationInput(context.Background(), claim2); err != nil {
		t.Fatal(err)
	}

	got := listSituations(t, st)
	if len(got) != 1 || got[0].InputVersion != 2 {
		t.Fatalf("situations = %+v", got)
	}
	if members := listSituationIncidentIDs(t, st, got[0].ID); !reflect.DeepEqual(members, []string{"inc-1", "inc-2"}) {
		t.Fatalf("members = %#v", members)
	}
}

func TestApplySituationInputSameIncidentNeverJoinsAnotherSituation(t *testing.T) {
	st := newTestStore(t)
	base := time.Date(2026, 9, 1, 14, 0, 0, 0, time.UTC)

	insertIncidentAndInput(t, st, "inc-1", "input-1", "service=same", base)
	claim1 := claimOneInput(t, st, "w", base)
	if err := st.ApplySituationInput(context.Background(), claim1); err != nil {
		t.Fatal(err)
	}
	first := listSituations(t, st)
	if len(first) != 1 {
		t.Fatalf("situations = %+v, want 1", first)
	}
	situationID := first[0].ID

	insertInputForExistingIncident(t, st, "inc-1", "input-2", "service=same", "triage_skipped", base.Add(time.Minute))
	claim2 := claimOneInput(t, st, "w", base.Add(time.Minute))
	if err := st.ApplySituationInput(context.Background(), claim2); err != nil {
		t.Fatal(err)
	}

	got := listSituations(t, st)
	if len(got) != 1 || got[0].ID != situationID || got[0].InputVersion != 2 {
		t.Fatalf("situations = %+v, want exactly one at id %s version 2", got, situationID)
	}
	if members := listSituationIncidentIDs(t, st, situationID); !reflect.DeepEqual(members, []string{"inc-1"}) {
		t.Fatalf("members = %v, want [inc-1]", members)
	}
}

func TestApplySituationInputAlreadyAppliedIsNoOp(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 15, 0, 0, 0, time.UTC)
	insertIncidentAndInput(t, st, "inc-1", "input-1", "service=noop", now)
	claim := claimOneInput(t, st, "w", now)
	if err := st.ApplySituationInput(context.Background(), claim); err != nil {
		t.Fatal(err)
	}

	before := listSituations(t, st)
	if err := st.ApplySituationInput(context.Background(), claim); err != nil {
		t.Fatalf("re-apply already-applied input: %v", err)
	}
	after := listSituations(t, st)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("re-apply changed state:\nbefore=%+v\nafter=%+v", before, after)
	}
}

func TestApplySituationInputCreatesNewSituationLinkedToTerminalPredecessor(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 16, 0, 0, 0, time.UTC)

	insertIncidentAndInput(t, st, "inc-1", "input-1", "service=term", now)
	claim1 := claimOneInput(t, st, "w", now)
	if err := st.ApplySituationInput(ctx, claim1); err != nil {
		t.Fatal(err)
	}
	first := listSituations(t, st)
	if len(first) != 1 {
		t.Fatalf("situations = %+v, want 1", first)
	}
	oldSituationID := first[0].ID

	terminalAt := now.Add(time.Hour)
	if _, err := st.db.ExecContext(ctx, `
		UPDATE situations SET lifecycle='closed_unknown', terminal_at=?, terminal_reason='resolution_missing', updated_at=?
		WHERE id=?`, canonicalTime(terminalAt), canonicalTime(terminalAt), oldSituationID); err != nil {
		t.Fatalf("terminalize fixture situation: %v", err)
	}

	insertIncidentAndInput(t, st, "inc-2", "input-2", "service=term", now.Add(2*time.Hour))
	claim2 := claimOneInput(t, st, "w", now.Add(2*time.Hour))
	if err := st.ApplySituationInput(ctx, claim2); err != nil {
		t.Fatal(err)
	}

	all := listSituations(t, st)
	if len(all) != 2 {
		t.Fatalf("situations = %+v, want 2", all)
	}
	var newSituation *situationmodel.Situation
	for i := range all {
		if all[i].ID != oldSituationID {
			newSituation = &all[i]
		}
	}
	if newSituation == nil {
		t.Fatal("no new situation found alongside the terminal one")
	}
	if newSituation.PreviousSituationID == nil || *newSituation.PreviousSituationID != oldSituationID {
		t.Fatalf("previous_situation_id = %v, want %s", newSituation.PreviousSituationID, oldSituationID)
	}
	if newSituation.Lifecycle != situationmodel.LifecycleActive {
		t.Fatalf("new situation lifecycle = %s, want active", newSituation.Lifecycle)
	}
	if newSituation.InputVersion != 1 {
		t.Fatalf("new situation input_version = %d, want 1", newSituation.InputVersion)
	}
}

func TestApplySituationInputDifferentGroupKeysNeverJoin(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 17, 0, 0, 0, time.UTC)

	insertIncidentAndInput(t, st, "inc-a", "input-a", "service=a", now)
	claimA := claimOneInput(t, st, "w", now)
	if err := st.ApplySituationInput(context.Background(), claimA); err != nil {
		t.Fatal(err)
	}

	insertIncidentAndInput(t, st, "inc-b", "input-b", "service=b", now.Add(time.Minute))
	claimB := claimOneInput(t, st, "w", now.Add(time.Minute))
	if err := st.ApplySituationInput(context.Background(), claimB); err != nil {
		t.Fatal(err)
	}

	got := listSituations(t, st)
	if len(got) != 2 {
		t.Fatalf("situations = %+v, want 2", got)
	}
	if got[0].GroupKey == got[1].GroupKey {
		t.Fatalf("group keys collided: %+v", got)
	}
}

// ----------------------------------------------------------------------
// Step 2: time, reason, and stale-claim tests
// ----------------------------------------------------------------------

func TestApplySituationInputComputesEarliestSourceTimesIndependently(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	// Delivery A: received earlier, but its own source start is the LATER
	// of the two. Delivery B: received later, but its source start is the
	// EARLIER of the two. This proves effective_started_at and
	// first_received_at are each computed as their own independent minimum,
	// not both tied to whichever delivery is "earliest overall".
	rA := time.Date(2026, 9, 1, 10, 5, 0, 0, time.UTC)
	tA := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	rB := time.Date(2026, 9, 1, 10, 10, 0, 0, time.UTC)
	tB := time.Date(2026, 9, 1, 9, 50, 0, 0, time.UTC)

	deliveryA := deliveryFixtureWithSource("d-a", "fp-a", rA, tA, situationmodel.SourceTimeBasisSourcePayload)
	deliveryB := deliveryFixtureWithSource("d-b", "fp-b", rB, tB, situationmodel.SourceTimeBasisSourcePayload)
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{deliveryA, deliveryB}); err != nil {
		t.Fatalf("accept deliveries: %v", err)
	}

	insertIncidentAndDeliveryInput(t, st, "inc-a", "input-a", "service=times", "d-a", rA)
	claimA := claimOneInput(t, st, "w", rA)
	if err := st.ApplySituationInput(ctx, claimA); err != nil {
		t.Fatal(err)
	}

	insertIncidentAndDeliveryInput(t, st, "inc-b", "input-b", "service=times", "d-b", rB)
	claimB := claimOneInput(t, st, "w", rB)
	if err := st.ApplySituationInput(ctx, claimB); err != nil {
		t.Fatal(err)
	}

	got := listSituations(t, st)
	if len(got) != 1 {
		t.Fatalf("situations = %+v, want 1", got)
	}
	if !got[0].EffectiveStartedAt.Equal(tB) {
		t.Errorf("effective_started_at = %v, want earliest source start %v", got[0].EffectiveStartedAt, tB)
	}
	if !got[0].FirstReceivedAt.Equal(rA) {
		t.Errorf("first_received_at = %v, want earliest receipt %v", got[0].FirstReceivedAt, rA)
	}
	if got[0].EffectiveStartedAtBasis != situationmodel.SourceTimeBasisSourcePayload {
		t.Errorf("effective_started_at_basis = %s, want source_payload (both agree)", got[0].EffectiveStartedAtBasis)
	}
}

func TestApplySituationInputMixedSourceBasisBecomesMixed(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	tC := time.Date(2026, 9, 1, 11, 0, 0, 0, time.UTC)
	rC := tC.Add(time.Minute)
	rD := tC.Add(2 * time.Minute)

	deliveryC := deliveryFixtureWithSource("d-c", "fp-c", rC, tC, situationmodel.SourceTimeBasisSourcePayload)
	// Delivery D deliberately carries basis "missing" with no source start —
	// proving the store maps "missing" (a value situations.effective_started_at_basis's
	// CHECK constraint does not accept) to receipt_fallback, which then still
	// mixes against delivery C's source_payload basis.
	deliveryD := deliveryFixture("d-d", "fp-d", rD)
	deliveryD.StartedAtBasis = situationmodel.SourceTimeBasisMissing

	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{deliveryC, deliveryD}); err != nil {
		t.Fatalf("accept deliveries: %v", err)
	}

	insertIncidentAndDeliveryInput(t, st, "inc-c", "input-c", "service=mix", "d-c", tC)
	claimC := claimOneInput(t, st, "w", tC)
	if err := st.ApplySituationInput(ctx, claimC); err != nil {
		t.Fatal(err)
	}

	insertIncidentAndDeliveryInput(t, st, "inc-d", "input-d", "service=mix", "d-d", tC.Add(time.Minute))
	claimD := claimOneInput(t, st, "w", tC.Add(time.Minute))
	if err := st.ApplySituationInput(ctx, claimD); err != nil {
		t.Fatal(err)
	}

	got := listSituations(t, st)
	if len(got) != 1 {
		t.Fatalf("situations = %+v, want 1", got)
	}
	if got[0].EffectiveStartedAtBasis != situationmodel.SourceTimeBasisMixed {
		t.Fatalf("effective_started_at_basis = %s, want mixed", got[0].EffectiveStartedAtBasis)
	}
}

func TestApplySituationInputNextAssessmentAtTakesEarlierTime(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	insertIncidentAndInput(t, st, "inc-1", "input-1", "service=sched", base.Add(5*time.Minute))
	claim1 := claimOneInput(t, st, "w", base)
	if err := st.ApplySituationInput(ctx, claim1); err != nil {
		t.Fatal(err)
	}
	sits := listSituations(t, st)
	situationID := sits[0].ID
	if !sits[0].NextAssessmentAt.Equal(base.Add(5 * time.Minute)) {
		t.Fatalf("next_assessment_at = %v, want %v", sits[0].NextAssessmentAt, base.Add(5*time.Minute))
	}

	insertIncidentAndInput(t, st, "inc-2", "input-2", "service=sched", base.Add(1*time.Minute))
	claim2 := claimOneInput(t, st, "w", base)
	if err := st.ApplySituationInput(ctx, claim2); err != nil {
		t.Fatal(err)
	}
	got := getSituationByID(t, st, situationID)
	if !got.NextAssessmentAt.Equal(base.Add(1 * time.Minute)) {
		t.Fatalf("next_assessment_at not pulled earlier: got %v, want %v", got.NextAssessmentAt, base.Add(1*time.Minute))
	}

	insertIncidentAndInput(t, st, "inc-3", "input-3", "service=sched", base.Add(10*time.Minute))
	claim3 := claimOneInput(t, st, "w", base)
	if err := st.ApplySituationInput(ctx, claim3); err != nil {
		t.Fatal(err)
	}
	got2 := getSituationByID(t, st, situationID)
	if !got2.NextAssessmentAt.Equal(base.Add(1 * time.Minute)) {
		t.Fatalf("next_assessment_at must not be pushed later: got %v, want unchanged %v", got2.NextAssessmentAt, base.Add(1*time.Minute))
	}
}

func TestApplySituationInputDueReasonsAreStableAndDeduplicated(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 9, 1, 13, 0, 0, 0, time.UTC)

	insertIncidentAndInput(t, st, "inc-1", "input-1", "service=reasons", base) // incident_created -> DueIncidentCreated
	claim1 := claimOneInput(t, st, "w", base)
	if err := st.ApplySituationInput(ctx, claim1); err != nil {
		t.Fatal(err)
	}
	sits := listSituations(t, st)
	situationID := sits[0].ID

	insertIncidentAndInputKind(t, st, "inc-2", "input-2", "service=reasons", "membership_changed", base.Add(time.Minute))
	claim2 := claimOneInput(t, st, "w", base.Add(time.Minute))
	if err := st.ApplySituationInput(ctx, claim2); err != nil {
		t.Fatal(err)
	}

	// Same incident, a DIFFERENT kind that maps to the SAME due reason
	// (DueMembershipChanged) already present — must not duplicate it.
	insertInputForExistingIncident(t, st, "inc-1", "input-3", "service=reasons", "incident_ready", base.Add(2*time.Minute))
	claim3 := claimOneInput(t, st, "w", base.Add(2*time.Minute))
	if err := st.ApplySituationInput(ctx, claim3); err != nil {
		t.Fatal(err)
	}

	got := getSituationByID(t, st, situationID)
	want := []situationmodel.DueReason{situationmodel.DueIncidentCreated, situationmodel.DueMembershipChanged}
	if !reflect.DeepEqual(got.DueReasons, want) {
		t.Fatalf("due_reasons = %v, want %v", got.DueReasons, want)
	}
}

func TestReclaimedSituationInputFencesOriginalOwner(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 18, 0, 0, 0, time.UTC)
	insertIncidentAndInput(t, st, "inc-1", "input-1", "service=stale", now)

	first, err := st.ClaimSituationInputs(context.Background(), "worker-a", now, time.Minute, 1)
	if err != nil || len(first) != 1 {
		t.Fatalf("first claim: %v, %v", first, err)
	}

	second, err := st.ClaimSituationInputs(context.Background(), "worker-b", now.Add(2*time.Minute), time.Minute, 1)
	if err != nil || len(second) != 1 {
		t.Fatalf("second claim: %v, %v", second, err)
	}
	if first[0].ClaimToken >= second[0].ClaimToken {
		t.Fatal("claim token did not advance")
	}

	if err := st.ApplySituationInput(context.Background(), first[0]); !errors.Is(err, ErrSituationLeaseLost) {
		t.Fatalf("stale apply = %v, want ErrSituationLeaseLost", err)
	}
	if err := st.RetrySituationInput(context.Background(), first[0], "transient", now.Add(3*time.Minute), false); !errors.Is(err, ErrSituationLeaseLost) {
		t.Fatalf("stale retry = %v, want ErrSituationLeaseLost", err)
	}
}

// TestSituationClaimTokenFencesStaleController is the literal brief test for
// the due-Situation claim: reclaiming an expired lease advances claim_token,
// and a stale release using the superseded token is rejected without
// disturbing the current owner.
func TestSituationClaimTokenFencesStaleController(t *testing.T) {
	st, situationID, now := dueSituationFixture(t)
	first, _ := st.ClaimDueSituations(context.Background(), "controller-a", now, time.Minute, 1)
	second, _ := st.ClaimDueSituations(context.Background(), "controller-b", now.Add(2*time.Minute), time.Minute, 1)
	if first[0].ClaimToken >= second[0].ClaimToken {
		t.Fatal("claim token did not advance")
	}
	if err := st.ReleaseSituationClaim(context.Background(), first[0], now.Add(3*time.Minute)); !errors.Is(err, ErrSituationLeaseLost) {
		t.Fatalf("stale release = %v", err)
	}
	assertSituationLeaseOwner(t, st, situationID, "controller-b")
}

// TestApplySituationInputClearsControllerLeaseFencingStaleRelease is the
// direct, end-to-end proof of the property this plan calls out by name: a
// controller that claimed a due Situation (a live ClaimDueSituations lease)
// cannot commit against it once ApplySituationInput has advanced that
// Situation's input_version — because joinSituationTx unconditionally clears
// lease_owner/lease_expires_at on every join, fencing the controller's now-
// stale claim out via ReleaseSituationClaim's own (lease_owner, claim_token)
// check, without needing any direct knowledge of input_version itself.
func TestApplySituationInputClearsControllerLeaseFencingStaleRelease(t *testing.T) {
	st, situationID, now := dueSituationFixture(t)

	controllerClaims, err := st.ClaimDueSituations(context.Background(), "controller-a", now, time.Minute, 1)
	if err != nil || len(controllerClaims) != 1 {
		t.Fatalf("claim due situation: %v, %v", controllerClaims, err)
	}
	staleClaim := controllerClaims[0]
	if staleClaim.ID != situationID {
		t.Fatalf("claimed situation id = %s, want %s", staleClaim.ID, situationID)
	}
	assertSituationLeaseOwner(t, st, situationID, "controller-a")

	// A same-group input arrives and joins the Situation the controller just
	// claimed. joinSituationTx must clear that lease so the controller's
	// now-stale claim can no longer commit against the advanced input_version.
	insertIncidentAndInput(t, st, "inc-second", "input-second", "service=due", now.Add(time.Minute))
	inputClaim := claimOneInput(t, st, "worker-a", now.Add(time.Minute))
	if err := st.ApplySituationInput(context.Background(), inputClaim); err != nil {
		t.Fatal(err)
	}

	got := getSituationByID(t, st, situationID)
	if got.InputVersion != 2 {
		t.Fatalf("input_version = %d, want 2 (same-group input applied)", got.InputVersion)
	}
	if got.LeaseOwner != nil {
		t.Fatalf("lease_owner = %q, want nil (cleared by joinSituationTx)", *got.LeaseOwner)
	}

	if err := st.ReleaseSituationClaim(context.Background(), staleClaim, now.Add(2*time.Minute)); !errors.Is(err, ErrSituationLeaseLost) {
		t.Fatalf("stale release after input-triggered lease clear = %v, want ErrSituationLeaseLost", err)
	}
}

func TestApplySituationInputResultReportsOnlyLiveSupersededClaim(t *testing.T) {
	st, situationID, _ := dueSituationFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()

	insertIncidentAndInput(t, st, "inc-idle", "input-idle", "service=due", now)
	idleClaim := claimOneInput(t, st, "input-worker", now)
	idleResult, err := st.ApplySituationInputResult(ctx, idleClaim)
	if err != nil {
		t.Fatal(err)
	}
	if idleResult.SituationID != situationID || idleResult.InputVersion != 2 || idleResult.SupersededClaimToken != 0 {
		t.Fatalf("idle apply result = %+v, want situation %s, version 2, no superseded token", idleResult, situationID)
	}

	controllerClaims, err := st.ClaimDueSituations(ctx, "controller", now, 5*time.Minute, 1)
	if err != nil || len(controllerClaims) != 1 {
		t.Fatalf("claim due situation: %v, %v", controllerClaims, err)
	}
	controllerToken := controllerClaims[0].ClaimToken
	insertIncidentAndInput(t, st, "inc-live", "input-live", "service=due", now.Add(time.Second))
	liveClaim := claimOneInput(t, st, "input-worker", now.Add(time.Second))
	liveResult, err := st.ApplySituationInputResult(ctx, liveClaim)
	if err != nil {
		t.Fatal(err)
	}
	if liveResult.SituationID != situationID || liveResult.InputVersion != 3 || liveResult.SupersededClaimToken != controllerToken {
		t.Fatalf("live apply result = %+v, want situation %s, version 3, superseded token %d", liveResult, situationID, controllerToken)
	}
}

// ----------------------------------------------------------------------
// Step 5 (R1/R2): ApplySituationInput's handling of the two durable
// operator artifact input kinds.
// ----------------------------------------------------------------------

// TestApplySituationInputArtifactAppliedToActiveOwnerMarksPending is the
// R1 "active owner" case: an artifact applied while its owner is
// active/recovery_pending joins normally — input_version bumps, the
// DueOperatorArtifactRecorded reason merges, and the outbox row is stamped
// journal_state='pending' plus the exact applied_input_version it landed at.
func TestApplySituationInputArtifactAppliedToActiveOwnerMarksPending(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 20, 0, 0, 0, time.UTC)

	insertIncidentAndInput(t, st, "inc-artifact-active", "input-artifact-active-seed", "service=artifact-active", now)
	seedClaim := claimOneInput(t, st, "w", now)
	if err := st.ApplySituationInput(ctx, seedClaim); err != nil {
		t.Fatalf("seed apply: %v", err)
	}
	sits := listSituations(t, st)
	if len(sits) != 1 || sits[0].InputVersion != 1 {
		t.Fatalf("seed situations = %+v, want exactly 1 at version 1", sits)
	}
	situationID := sits[0].ID

	annID, err := insertAnnotationRow(ctx, st, "inc-artifact-active")
	if err != nil {
		t.Fatalf("seed annotation: %v", err)
	}
	insertArtifactSituationInput(t, st, "inc-artifact-active", "input-artifact-active", "service=artifact-active", "operator_annotation_recorded", annID, nil, now.Add(time.Minute))
	artifactClaim := claimOneInput(t, st, "w", now.Add(time.Minute))
	if err := st.ApplySituationInput(ctx, artifactClaim); err != nil {
		t.Fatalf("apply artifact input: %v", err)
	}

	got := getSituationByID(t, st, situationID)
	if got.InputVersion != 2 {
		t.Fatalf("input_version = %d, want 2 (artifact bumped it)", got.InputVersion)
	}
	want := []situationmodel.DueReason{situationmodel.DueIncidentCreated, situationmodel.DueOperatorArtifactRecorded}
	if !reflect.DeepEqual(got.DueReasons, want) {
		t.Fatalf("due_reasons = %v, want %v", got.DueReasons, want)
	}

	var journalState string
	var appliedInputVersion sql.NullInt64
	var appliedSituationID sql.NullString
	if err := st.db.QueryRowContext(ctx, `SELECT journal_state, applied_input_version, applied_situation_id FROM situation_input_outbox WHERE id = ?`, "input-artifact-active").
		Scan(&journalState, &appliedInputVersion, &appliedSituationID); err != nil {
		t.Fatal(err)
	}
	if journalState != "pending" {
		t.Fatalf("journal_state = %q, want pending", journalState)
	}
	if !appliedInputVersion.Valid || appliedInputVersion.Int64 != 2 {
		t.Fatalf("applied_input_version = %v, want 2", appliedInputVersion)
	}
	if !appliedSituationID.Valid || appliedSituationID.String != situationID {
		t.Fatalf("applied_situation_id = %v, want %s", appliedSituationID, situationID)
	}
}

// TestApplySituationInputVerdictArtifactAppliedToActiveOwnerMarksPending
// proves the captured_verdict_recorded kind is treated identically to
// operator_annotation_recorded by isOperatorArtifactKind.
func TestApplySituationInputVerdictArtifactAppliedToActiveOwnerMarksPending(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)

	insertIncidentAndInput(t, st, "inc-verdict-active", "input-verdict-active-seed", "service=verdict-active", now)
	seedClaim := claimOneInput(t, st, "w", now)
	if err := st.ApplySituationInput(ctx, seedClaim); err != nil {
		t.Fatalf("seed apply: %v", err)
	}
	sits := listSituations(t, st)
	situationID := sits[0].ID

	verdID, err := insertVerdictRow(ctx, st, "inc-verdict-active", 1)
	if err != nil {
		t.Fatalf("seed verdict: %v", err)
	}
	insertArtifactSituationInput(t, st, "inc-verdict-active", "input-verdict-active", "service=verdict-active", "captured_verdict_recorded", nil, verdID, now.Add(time.Minute))
	claim := claimOneInput(t, st, "w", now.Add(time.Minute))
	if err := st.ApplySituationInput(ctx, claim); err != nil {
		t.Fatalf("apply verdict input: %v", err)
	}

	got := getSituationByID(t, st, situationID)
	if got.InputVersion != 2 {
		t.Fatalf("input_version = %d, want 2", got.InputVersion)
	}
	var journalState string
	if err := st.db.QueryRowContext(ctx, `SELECT journal_state FROM situation_input_outbox WHERE id = 'input-verdict-active'`).Scan(&journalState); err != nil {
		t.Fatal(err)
	}
	if journalState != "pending" {
		t.Fatalf("journal_state = %q, want pending", journalState)
	}
}

// TestApplySituationInputArtifactAppliedAfterTerminalOwnerMarksOwnerTerminal
// is the R2 case: an artifact applied after its owner already terminalized
// must not join — input_version and due_reasons_json stay exactly as they
// were, the outbox row is stamped journal_state='owner_terminal', and
// ClaimDueSituations never returns the terminalized owner.
func TestApplySituationInputArtifactAppliedAfterTerminalOwnerMarksOwnerTerminal(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 21, 0, 0, 0, time.UTC)

	insertIncidentAndInput(t, st, "inc-artifact-term", "input-artifact-term-seed", "service=artifact-term", now)
	seedClaim := claimOneInput(t, st, "w", now)
	if err := st.ApplySituationInput(ctx, seedClaim); err != nil {
		t.Fatalf("seed apply: %v", err)
	}
	sits := listSituations(t, st)
	situationID := sits[0].ID

	terminalAt := now.Add(time.Hour)
	if _, err := st.db.ExecContext(ctx, `
		UPDATE situations SET lifecycle='closed_unknown', terminal_at=?, terminal_reason='resolution_missing', updated_at=?
		WHERE id=?`, canonicalTime(terminalAt), canonicalTime(terminalAt), situationID); err != nil {
		t.Fatalf("terminalize fixture situation: %v", err)
	}
	before := getSituationByID(t, st, situationID)

	annID, err := insertAnnotationRow(ctx, st, "inc-artifact-term")
	if err != nil {
		t.Fatalf("seed annotation: %v", err)
	}
	insertArtifactSituationInput(t, st, "inc-artifact-term", "input-artifact-term", "service=artifact-term", "operator_annotation_recorded", annID, nil, now.Add(2*time.Hour))
	artifactClaim := claimOneInput(t, st, "w", now.Add(2*time.Hour))
	if err := st.ApplySituationInput(ctx, artifactClaim); err != nil {
		t.Fatalf("apply artifact input to terminal owner: %v", err)
	}

	after := getSituationByID(t, st, situationID)
	if after.InputVersion != before.InputVersion {
		t.Fatalf("input_version changed: before %d, after %d, want unchanged", before.InputVersion, after.InputVersion)
	}
	if !reflect.DeepEqual(after.DueReasons, before.DueReasons) {
		t.Fatalf("due_reasons changed: before %v, after %v, want unchanged", before.DueReasons, after.DueReasons)
	}

	var journalState string
	var appliedSituationID sql.NullString
	if err := st.db.QueryRowContext(ctx, `SELECT journal_state, applied_situation_id FROM situation_input_outbox WHERE id = ?`, "input-artifact-term").
		Scan(&journalState, &appliedSituationID); err != nil {
		t.Fatal(err)
	}
	if journalState != "owner_terminal" {
		t.Fatalf("journal_state = %q, want owner_terminal", journalState)
	}
	if !appliedSituationID.Valid || appliedSituationID.String != situationID {
		t.Fatalf("applied_situation_id = %v, want %s", appliedSituationID, situationID)
	}

	due, err := st.ClaimDueSituations(ctx, "controller-x", now.Add(3*time.Hour), time.Minute, 10)
	if err != nil {
		t.Fatalf("claim due situations: %v", err)
	}
	for _, d := range due {
		if d.ID == situationID {
			t.Fatalf("ClaimDueSituations returned terminalized situation %s", situationID)
		}
	}
}

// TestApplySituationInputLateNonArtifactAgainstTerminalOwnerNeverReopensLifecycle
// is S1-01's admission guard for the NON-artifact kinds (a plain
// membership/triage/resolution event, not operator_annotation_recorded or
// captured_verdict_recorded): situationOwnerForIncidentTx's membership link
// is immutable, so a late event for an Incident whose owner already
// terminalized resolves right back to that SAME terminal owner and takes
// the ordinary join path (isOperatorArtifactKind is false, so R2's
// owner-terminal branch never triggers for it — deliberate per
// isOperatorArtifactKind's doc comment). This does not claim the row is
// wholly immutable (plan.md: "Do not claim the entire terminal database row
// is immutable") — only the guard the slide actually requires: lifecycle
// itself must never flip back to active/recovery_pending, no second
// Situation is spuriously created for the same Incident, and the
// terminalized owner never becomes claimable for reconciliation again.
func TestApplySituationInputLateNonArtifactAgainstTerminalOwnerNeverReopensLifecycle(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 23, 0, 0, 0, time.UTC)

	insertIncidentAndInput(t, st, "inc-late-nonartifact", "input-late-nonartifact-seed", "service=late-nonartifact", now)
	seedClaim := claimOneInput(t, st, "w", now)
	if err := st.ApplySituationInput(ctx, seedClaim); err != nil {
		t.Fatalf("seed apply: %v", err)
	}
	sits := listSituations(t, st)
	if len(sits) != 1 {
		t.Fatalf("situations = %+v, want 1", sits)
	}
	situationID := sits[0].ID

	terminalAt := now.Add(time.Hour)
	if _, err := st.db.ExecContext(ctx, `
		UPDATE situations SET lifecycle='closed_unknown', terminal_at=?, terminal_reason='resolution_missing', updated_at=?
		WHERE id=?`, canonicalTime(terminalAt), canonicalTime(terminalAt), situationID); err != nil {
		t.Fatalf("terminalize fixture situation: %v", err)
	}

	insertInputForExistingIncident(t, st, "inc-late-nonartifact", "input-late-nonartifact", "service=late-nonartifact", "triage_skipped", now.Add(2*time.Hour))
	lateClaim := claimOneInput(t, st, "w", now.Add(2*time.Hour))
	if err := st.ApplySituationInput(ctx, lateClaim); err != nil {
		t.Fatalf("apply late non-artifact input against terminal owner: %v", err)
	}

	all := listSituations(t, st)
	if len(all) != 1 {
		t.Fatalf("situations = %+v, want still exactly 1 (no spurious new Situation for an Incident already attached)", all)
	}
	after := getSituationByID(t, st, situationID)
	if after.Lifecycle != situationmodel.LifecycleClosedUnknown {
		t.Fatalf("lifecycle = %s, want closed_unknown (terminal must never reopen on a late non-artifact event)", after.Lifecycle)
	}

	due, err := st.ClaimDueSituations(ctx, "controller-x", now.Add(3*time.Hour), time.Minute, 10)
	if err != nil {
		t.Fatalf("claim due situations: %v", err)
	}
	for _, d := range due {
		if d.ID == situationID {
			t.Fatalf("ClaimDueSituations returned terminalized situation %s after a late non-artifact input", situationID)
		}
	}
}

// TestApplySituationInputArtifactActiveOwnerReplayIsNoOp proves idempotent
// replay of the R1 active-owner path: re-applying an already-applied
// artifact claim changes nothing.
func TestApplySituationInputArtifactActiveOwnerReplayIsNoOp(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 22, 0, 0, 0, time.UTC)

	insertIncidentAndInput(t, st, "inc-artifact-replay", "input-artifact-replay-seed", "service=artifact-replay", now)
	seedClaim := claimOneInput(t, st, "w", now)
	if err := st.ApplySituationInput(ctx, seedClaim); err != nil {
		t.Fatalf("seed apply: %v", err)
	}

	annID, err := insertAnnotationRow(ctx, st, "inc-artifact-replay")
	if err != nil {
		t.Fatalf("seed annotation: %v", err)
	}
	insertArtifactSituationInput(t, st, "inc-artifact-replay", "input-artifact-replay", "service=artifact-replay", "operator_annotation_recorded", annID, nil, now.Add(time.Minute))
	claim := claimOneInput(t, st, "w", now.Add(time.Minute))
	if err := st.ApplySituationInput(ctx, claim); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	before := listSituations(t, st)

	if err := st.ApplySituationInput(ctx, claim); err != nil {
		t.Fatalf("replay apply: %v", err)
	}
	after := listSituations(t, st)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("replay changed situations:\nbefore=%+v\nafter=%+v", before, after)
	}
}

// TestApplySituationInputArtifactOwnerTerminalReplayIsNoOp proves idempotent
// replay of the R2 owner-terminal path.
func TestApplySituationInputArtifactOwnerTerminalReplayIsNoOp(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 23, 0, 0, 0, time.UTC)

	insertIncidentAndInput(t, st, "inc-artifact-term-replay", "input-artifact-term-replay-seed", "service=artifact-term-replay", now)
	seedClaim := claimOneInput(t, st, "w", now)
	if err := st.ApplySituationInput(ctx, seedClaim); err != nil {
		t.Fatalf("seed apply: %v", err)
	}
	sits := listSituations(t, st)
	situationID := sits[0].ID
	terminalAt := now.Add(time.Hour)
	if _, err := st.db.ExecContext(ctx, `
		UPDATE situations SET lifecycle='closed_unknown', terminal_at=?, terminal_reason='resolution_missing', updated_at=?
		WHERE id=?`, canonicalTime(terminalAt), canonicalTime(terminalAt), situationID); err != nil {
		t.Fatalf("terminalize fixture situation: %v", err)
	}

	annID, err := insertAnnotationRow(ctx, st, "inc-artifact-term-replay")
	if err != nil {
		t.Fatalf("seed annotation: %v", err)
	}
	insertArtifactSituationInput(t, st, "inc-artifact-term-replay", "input-artifact-term-replay", "service=artifact-term-replay", "operator_annotation_recorded", annID, nil, now.Add(2*time.Hour))
	claim := claimOneInput(t, st, "w", now.Add(2*time.Hour))
	if err := st.ApplySituationInput(ctx, claim); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	before := listSituations(t, st)

	if err := st.ApplySituationInput(ctx, claim); err != nil {
		t.Fatalf("replay apply: %v", err)
	}
	after := listSituations(t, st)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("replay changed situations:\nbefore=%+v\nafter=%+v", before, after)
	}
}

// ----------------------------------------------------------------------
// Task 9: read-only Situation views (ListSituations, GetSituation,
// GetSituationByHandle, ListSituationIncidents) — the exact surface the MCP
// Situation tools depend on.
// ----------------------------------------------------------------------

func TestListSituationsOrdersNewestUpdatedFirst(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 5, 0, 0, 0, time.UTC)

	insertIncidentAndInput(t, st, "inc-a", "input-a", "service=a", now)
	claimA := claimOneInput(t, st, "worker-a", now)
	if err := st.ApplySituationInput(context.Background(), claimA); err != nil {
		t.Fatal(err)
	}
	insertIncidentAndInput(t, st, "inc-b", "input-b", "service=b", now.Add(time.Minute))
	claimB := claimOneInput(t, st, "worker-a", now.Add(time.Minute))
	if err := st.ApplySituationInput(context.Background(), claimB); err != nil {
		t.Fatal(err)
	}

	// A second input against the FIRST situation's group advances its
	// updated_at past the second situation's, so newest-updated-first must
	// reorder it back to the front despite being created earlier.
	insertIncidentAndInput(t, st, "inc-a2", "input-a2", "service=a", now.Add(2*time.Minute))
	claimA2 := claimOneInput(t, st, "worker-a", now.Add(2*time.Minute))
	if err := st.ApplySituationInput(context.Background(), claimA2); err != nil {
		t.Fatal(err)
	}

	got, err := st.ListSituations(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("situations = %+v, want exactly 2", got)
	}
	if got[0].GroupKey != "service=a" || got[1].GroupKey != "service=b" {
		t.Fatalf("order = [%s, %s], want [service=a, service=b] (most recently updated first)", got[0].GroupKey, got[1].GroupKey)
	}
}

// insertRawSituation inserts one minimal, nonterminal "active" Situation
// row directly, bypassing ApplySituationInput/ReconstructSituation — the
// clamp test below only needs a large volume of distinct rows to list
// against, never their full lifecycle.
func insertRawSituation(t *testing.T, st *Store, id, groupKey string, updatedAt time.Time) {
	t.Helper()
	ts := canonicalTime(updatedAt)
	if _, err := st.db.ExecContext(context.Background(), `
		INSERT INTO situations (
			id, group_key, lifecycle, attention, input_version,
			opened_at, effective_started_at, effective_started_at_basis, first_received_at,
			last_lifecycle_observed_at, next_assessment_at, due_reasons_json, created_at, updated_at
		) VALUES (?, ?, 'active', 'observe', 1, ?, ?, 'receipt_fallback', ?, ?, ?, '[]', ?, ?)`,
		id, groupKey, ts, ts, ts, ts, ts, ts, ts); err != nil {
		t.Fatalf("insert raw situation %s: %v", id, err)
	}
}

func TestListSituationsClampsLimit(t *testing.T) {
	st := newTestStore(t)
	if _, err := st.ListSituations(context.Background(), 0); err != nil {
		t.Fatalf("limit 0 on empty store: %v", err)
	}
	if _, err := st.ListSituations(context.Background(), -5); err != nil {
		t.Fatalf("negative limit on empty store: %v", err)
	}

	// Seed more rows than maxSituationListLimit so a bad/missing clamp would
	// actually show up in len(got) — asserting only err == nil against an
	// empty store, as this test used to, is true regardless of whether the
	// clamp does anything at all.
	base := time.Date(2026, 9, 1, 5, 0, 0, 0, time.UTC)
	const seeded = maxSituationListLimit + 5
	for i := 0; i < seeded; i++ {
		insertRawSituation(t, st, fmt.Sprintf("sit-%04d", i), fmt.Sprintf("group-%04d", i), base.Add(time.Duration(i)*time.Second))
	}

	oversized, err := st.ListSituations(context.Background(), 10000)
	if err != nil {
		t.Fatalf("oversized limit: %v", err)
	}
	if len(oversized) != maxSituationListLimit {
		t.Fatalf("ListSituations(10000) returned %d rows, want the clamped max %d", len(oversized), maxSituationListLimit)
	}

	def, err := st.ListSituations(context.Background(), 0)
	if err != nil {
		t.Fatalf("default limit: %v", err)
	}
	if len(def) != defaultSituationListLimit {
		t.Fatalf("ListSituations(0) returned %d rows, want the documented default %d", len(def), defaultSituationListLimit)
	}

	negative, err := st.ListSituations(context.Background(), -5)
	if err != nil {
		t.Fatalf("negative limit: %v", err)
	}
	if len(negative) != defaultSituationListLimit {
		t.Fatalf("ListSituations(-5) returned %d rows, want the documented default %d", len(negative), defaultSituationListLimit)
	}
}

func TestGetSituationByID(t *testing.T) {
	st, situationID, _ := dueSituationFixture(t)

	got, err := st.GetSituation(context.Background(), situationID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != situationID {
		t.Fatalf("id = %s, want %s", got.ID, situationID)
	}
}

func TestGetSituationUnknownIDReturnsErrNotFound(t *testing.T) {
	st := newTestStore(t)
	if _, err := st.GetSituation(context.Background(), "does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestGetSituationByHandleCaseInsensitive(t *testing.T) {
	st, situationID, _ := dueSituationFixture(t)
	if _, err := st.db.ExecContext(context.Background(), `UPDATE situations SET public_handle = ? WHERE id = ?`, "INC-Api-42", situationID); err != nil {
		t.Fatalf("seed public_handle: %v", err)
	}

	got, err := st.GetSituationByHandle(context.Background(), "inc-api-42")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != situationID {
		t.Fatalf("id = %s, want %s", got.ID, situationID)
	}
}

func TestGetSituationByHandleUnknownReturnsErrNotFound(t *testing.T) {
	st := newTestStore(t)
	if _, err := st.GetSituationByHandle(context.Background(), "no-such-handle"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	// A Situation exists but has never been assigned a handle (public_handle
	// IS NULL) — SQL NULL never equals a bound parameter, so this must also
	// miss rather than falsely matching an empty-string lookup.
	st2, _, _ := dueSituationFixture(t)
	if _, err := st2.GetSituationByHandle(context.Background(), ""); err == nil {
		t.Fatal("expected an error for an empty handle")
	}
}

func TestListSituationIncidentsReturnsMembersInAttachmentOrder(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 6, 0, 0, 0, time.UTC)
	insertIncidentAndInput(t, st, "inc-1", "input-1", "service=members", now)
	claim1 := claimOneInput(t, st, "worker-a", now)
	if err := st.ApplySituationInput(context.Background(), claim1); err != nil {
		t.Fatal(err)
	}
	insertIncidentAndInput(t, st, "inc-2", "input-2", "service=members", now.Add(time.Second))
	claim2 := claimOneInput(t, st, "worker-a", now.Add(time.Second))
	if err := st.ApplySituationInput(context.Background(), claim2); err != nil {
		t.Fatal(err)
	}

	// insertIncidentAndInput's fixture helper already moves each Incident to
	// "ready" (see insertIncidentAndInputKind) so a same-group second fixture
	// doesn't collide on incidents_one_collecting_group_idx — both members
	// are expected at "ready" below, not "collecting".
	sits := listSituations(t, st)
	if len(sits) != 1 {
		t.Fatalf("situations = %+v, want exactly 1", sits)
	}

	got, err := st.ListSituationIncidents(context.Background(), sits[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	want := []SituationIncidentRef{
		{IncidentID: "inc-1", Status: "ready"},
		{IncidentID: "inc-2", Status: "ready"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("members = %+v, want %+v", got, want)
	}
}

func TestListSituationIncidentsEmptyForUnknownSituation(t *testing.T) {
	st := newTestStore(t)
	got, err := st.ListSituationIncidents(context.Background(), "no-such-situation")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("members = %+v, want empty", got)
	}
}
