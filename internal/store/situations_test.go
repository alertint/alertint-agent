// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

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

// ----------------------------------------------------------------------
// dueReasonForInputKind
// ----------------------------------------------------------------------

func TestDueReasonForInputKindMapsAllKnownKinds(t *testing.T) {
	cases := map[string]situationmodel.DueReason{
		"incident_created":     situationmodel.DueIncidentCreated,
		"membership_changed":   situationmodel.DueMembershipChanged,
		"incident_ready":       situationmodel.DueMembershipChanged,
		"finding_persisted":    situationmodel.DueNewSymptom,
		"triage_skipped":       situationmodel.DueTriageChanged,
		"triage_retry_changed": situationmodel.DueTriageChanged,
		"triage_exhausted":     situationmodel.DueTriageChanged,
		"incident_resolved":    situationmodel.DueAlertResolved,
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
