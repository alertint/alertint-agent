// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestInsertAndListIncidentAnnotations(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := readyIncident(t, s, "service=api") // helper: insert incident, mark ready

	a1, err := s.InsertIncidentAnnotation(ctx, id, "observation", "first note")
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if a1.ID == 0 || a1.Kind != "observation" || a1.CreatedAt.IsZero() {
		t.Fatalf("bad annotation: %+v", a1)
	}
	if _, err := s.InsertIncidentAnnotation(ctx, id, "correction", "second note"); err != nil {
		t.Fatalf("insert 2: %v", err)
	}
	got, err := s.ListIncidentAnnotations(ctx, id)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 || got[0].Note != "second note" { // newest-first
		t.Fatalf("want 2 newest-first, got %+v", got)
	}
}

func TestInsertIncidentAnnotation_Validation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := readyIncident(t, s, "service=api")

	if _, err := s.InsertIncidentAnnotation(ctx, "nope", "observation", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing incident: want ErrNotFound, got %v", err)
	}
	if _, err := s.InsertIncidentAnnotation(ctx, id, "opinion", "x"); err == nil {
		t.Fatal("bad kind accepted")
	}
	long := strings.Repeat("a", MaxAnnotationNoteChars+1)
	if _, err := s.InsertIncidentAnnotation(ctx, id, "observation", long); err == nil {
		t.Fatal("over-cap note accepted")
	}
	if _, err := s.InsertIncidentAnnotation(ctx, id, "observation", ""); err == nil {
		t.Fatal("empty note accepted")
	}
}

// TestInsertIncidentAnnotation_CapIsRunesNotBytes covers a note built from
// multi-byte UTF-8 characters (CJK, Cyrillic, emoji): the cap is documented
// as "max 2000 chars" and must be enforced in characters, not the larger
// UTF-8 byte count, or non-English operators get spuriously rejected under
// the advertised limit.
func TestInsertIncidentAnnotation_CapIsRunesNotBytes(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := readyIncident(t, s, "service=api")

	// 1000 three-byte runes ("世") = 3000 bytes but only 1000 characters —
	// well under the 2000-char cap, but over it if measured in bytes.
	note := strings.Repeat("世", 1000) //nolint:gosmopolitan // deliberate multi-byte rune fixture, not a stray hardcoded string
	if _, err := s.InsertIncidentAnnotation(ctx, id, "observation", note); err != nil {
		t.Fatalf("a 1000-character multi-byte note must be accepted (2000-char cap): %v", err)
	}
}

func TestOperatorAnnotations(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	a := readyIncident(t, s, "service=api")   // same key
	b := readyIncident(t, s, "service=api")   // same key
	c := readyIncident(t, s, "service=other") // different key
	for _, in := range []struct{ id, kind, note string }{
		{a, "correction", "on a"}, {b, "observation", "on b"}, {c, "observation", "on c"},
	} {
		if _, err := s.InsertIncidentAnnotation(ctx, in.id, in.kind, in.note); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.OperatorAnnotations(ctx, "service=api", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 annotations for the key, got %+v", got)
	}
	if !got[0].CreatedAt.After(got[1].CreatedAt) && got[0].CreatedAt != got[1].CreatedAt {
		t.Fatal("not newest-first")
	}
}

// TestOperatorAnnotations_Unbounded confirms the read has no time bound at
// all (R7: human writes are permanent, age-stamped rendering replaces
// decay) — an annotation inserted long ago still comes back.
func TestOperatorAnnotations_Unbounded(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := readyIncident(t, s, "service=checkout")
	if _, err := s.InsertIncidentAnnotation(ctx, id, "observation", "ancient but permanent"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	ops, err := s.OperatorAnnotations(ctx, "service=checkout", false)
	if err != nil || len(ops) != 1 {
		t.Fatalf("want 1 permanent annotation, got %d, %v", len(ops), err)
	}
}

// ----------------------------------------------------------------------
// Task 8: atomic write-back — an attributed annotation (and, in
// verdicts_test.go, a Captured verdict) atomically enqueues exactly one
// durable Situation input alongside the annotation/verdict row itself, but
// ONLY when the Incident currently belongs to a nonterminal Situation.
// ----------------------------------------------------------------------

// situationOwnedIncident builds one real Incident and durably attaches it to
// a brand-new, active Situation the same way the durable pipeline does —
// InsertIncident, a queued "incident_created" situation_input_outbox row,
// ClaimSituationInputs, ApplySituationInput — never an INSERT INTO
// situations by hand (mirrors internal/mcp's seedSituationForMCP). Returns
// the Incident id.
func situationOwnedIncident(t *testing.T, st *Store, groupKey string) string {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	incidentID := fmt.Sprintf("inc-%s-%d", groupKey, now.UnixNano())
	if err := st.InsertIncident(ctx, Incident{
		ID: incidentID, GroupKey: groupKey, FirstAlertAt: now, LastAlertAt: now, ReadyAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	if err := st.MarkIncidentReady(ctx, incidentID); err != nil {
		t.Fatalf("mark incident ready: %v", err)
	}
	inputID := "input-" + incidentID
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO situation_input_outbox (id, idempotency_key, incident_id, kind, group_key, occurred_at, status)
		VALUES (?, ?, ?, 'incident_created', ?, ?, 'pending')`,
		inputID, "idem:"+inputID, incidentID, groupKey, canonicalTime(now)); err != nil {
		t.Fatalf("seed situation input: %v", err)
	}
	claim := claimOneInput(t, st, "seed-"+incidentID, now)
	if err := st.ApplySituationInput(ctx, claim); err != nil {
		t.Fatalf("apply seed situation input: %v", err)
	}
	return incidentID
}

// situationIDForIncident reads the Situation id an Incident is durably
// attached to (situation_incidents is append-only — the link never changes
// even after the owner terminalizes).
func situationIDForIncident(t *testing.T, st *Store, incidentID string) string {
	t.Helper()
	var id string
	if err := st.db.QueryRowContext(context.Background(),
		`SELECT situation_id FROM situation_incidents WHERE incident_id = ?`, incidentID).Scan(&id); err != nil {
		t.Fatalf("situation id for incident %s: %v", incidentID, err)
	}
	return id
}

// terminalizeSituation marks situationID terminal (closed_unknown) directly,
// mirroring situations_test.go's own R2 fixture pattern.
func terminalizeSituation(t *testing.T, st *Store, situationID string, at time.Time) {
	t.Helper()
	if _, err := st.db.ExecContext(context.Background(), `
		UPDATE situations SET lifecycle='closed_unknown', terminal_at=?, terminal_reason='resolution_missing', updated_at=?
		WHERE id=?`, canonicalTime(at), canonicalTime(at), situationID); err != nil {
		t.Fatalf("terminalize situation %s: %v", situationID, err)
	}
}

// countOutboxRows counts situation_input_outbox rows of kind for incidentID —
// the write-time enqueue's own visible effect.
func countOutboxRows(t *testing.T, st *Store, incidentID, kind string) int {
	t.Helper()
	var n int
	if err := st.db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM situation_input_outbox WHERE incident_id = ? AND kind = ?`, incidentID, kind).Scan(&n); err != nil {
		t.Fatalf("count outbox rows: %v", err)
	}
	return n
}

// TestInsertIncidentAnnotation_EnqueuesOperatorAnnotationRecordedWhenOwnerActive
// proves Step 2's core contract: in the SAME transaction that persists the
// annotation, an active owning Situation gets exactly one
// operator_annotation_recorded situation_input_outbox row referencing the
// exact new annotation id, pending and ready for the input worker.
func TestInsertIncidentAnnotation_EnqueuesOperatorAnnotationRecordedWhenOwnerActive(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := situationOwnedIncident(t, s, "service=annotate-active")

	a, err := s.InsertIncidentAnnotation(ctx, id, "observation", "operator note")
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	if n := countOutboxRows(t, s, id, "operator_annotation_recorded"); n != 1 {
		t.Fatalf("operator_annotation_recorded inputs = %d, want 1", n)
	}
	var annotationID int64
	var status, journalState, groupKey string
	if err := s.db.QueryRowContext(ctx, `
		SELECT annotation_id, status, journal_state, group_key FROM situation_input_outbox
		WHERE incident_id = ? AND kind = 'operator_annotation_recorded'`, id).
		Scan(&annotationID, &status, &journalState, &groupKey); err != nil {
		t.Fatal(err)
	}
	if annotationID != a.ID {
		t.Fatalf("annotation_id = %d, want %d (the exact annotation this call persisted)", annotationID, a.ID)
	}
	if status != "pending" || journalState != "pending" {
		t.Fatalf("status=%q journal_state=%q, want pending/pending", status, journalState)
	}
	if groupKey != "service=annotate-active" {
		t.Fatalf("group_key = %q, want the incident's own", groupKey)
	}
}

// TestInsertIncidentAnnotation_NoEnqueueWithoutOwner proves the negative
// half of Step 2: an Incident with no owning Situation at all persists the
// annotation (still visible via ListIncidentAnnotations/Incident MCP) but
// enqueues no situation_input_outbox row whatsoever.
func TestInsertIncidentAnnotation_NoEnqueueWithoutOwner(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := readyIncident(t, s, "service=annotate-unowned")

	if _, err := s.InsertIncidentAnnotation(ctx, id, "observation", "operator note"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	anns, err := s.ListIncidentAnnotations(ctx, id)
	if err != nil || len(anns) != 1 {
		t.Fatalf("annotation must still be visible: anns=%+v err=%v", anns, err)
	}
	if n := countOutboxRows(t, s, id, "operator_annotation_recorded"); n != 0 {
		t.Fatalf("operator_annotation_recorded inputs = %d, want 0 (no owner at all)", n)
	}
}

// TestInsertIncidentAnnotation_NoEnqueueForTerminalOwner proves Step 4's
// "never enqueue for a terminal owner at write time": an Incident whose
// owning Situation has ALREADY reached a terminal lifecycle before the
// annotation is even written gets no outbox row — this is distinct from the
// R2 RACE (owner terminalizes strictly between enqueue and apply), covered
// separately below.
func TestInsertIncidentAnnotation_NoEnqueueForTerminalOwner(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := situationOwnedIncident(t, s, "service=annotate-terminal")
	situationID := situationIDForIncident(t, s, id)
	terminalizeSituation(t, s, situationID, time.Now().UTC().Add(time.Hour))

	if _, err := s.InsertIncidentAnnotation(ctx, id, "observation", "operator note"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	anns, err := s.ListIncidentAnnotations(ctx, id)
	if err != nil || len(anns) != 1 {
		t.Fatalf("annotation must still be visible: anns=%+v err=%v", anns, err)
	}
	if n := countOutboxRows(t, s, id, "operator_annotation_recorded"); n != 0 {
		t.Fatalf("operator_annotation_recorded inputs = %d, want 0 (owner already terminal at write time)", n)
	}
}

// TestInsertIncidentAnnotation_RetrySameAnnotationIDIsIdempotent proves the
// enqueue's own idempotency: replaying the write-back enqueue for the exact
// same already-persisted annotation id (the retry scenario Step 2 names)
// never creates a second situation_input_outbox row.
func TestInsertIncidentAnnotation_RetrySameAnnotationIDIsIdempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := situationOwnedIncident(t, s, "service=annotate-retry")
	annID, err := insertAnnotationRow(ctx, s, id)
	if err != nil {
		t.Fatalf("seed annotation: %v", err)
	}
	idempotencyKey := fmt.Sprintf("operator-annotation:%d", annID)

	for i := 0; i < 2; i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := enqueueOperatorArtifactInputTx(ctx, tx, id, "operator_annotation_recorded", idempotencyKey, annID, nil, time.Now().UTC()); err != nil {
			t.Fatalf("enqueue attempt %d: %v", i, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	if n := countOutboxRows(t, s, id, "operator_annotation_recorded"); n != 1 {
		t.Fatalf("operator_annotation_recorded inputs after retry = %d, want 1 (idempotent replay)", n)
	}
}

// TestInsertIncidentAnnotation_R2RaceOwnerTerminalizesBeforeApply is Step 4's
// full round trip: enqueue against an ACTIVE owner (this task's write path),
// terminalize the Situation, then run the input worker (Task 2's
// ApplySituationInput, already implemented) — the row lands owner_terminal,
// no Transition is ever created for it, input_version stays unchanged, and
// the annotation remains visible via Incident MCP/audit throughout.
func TestInsertIncidentAnnotation_R2RaceOwnerTerminalizesBeforeApply(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := situationOwnedIncident(t, s, "service=annotate-r2-race")
	situationID := situationIDForIncident(t, s, id)

	a, err := s.InsertIncidentAnnotation(ctx, id, "observation", "operator note")
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	before := getSituationByID(t, s, situationID)

	terminalizeSituation(t, s, situationID, time.Now().UTC().Add(time.Hour))

	claim := claimOneInput(t, s, "input-worker", time.Now().UTC().Add(2*time.Hour))
	if err := s.ApplySituationInput(ctx, claim); err != nil {
		t.Fatalf("apply artifact input to now-terminal owner: %v", err)
	}

	after := getSituationByID(t, s, situationID)
	if after.InputVersion != before.InputVersion {
		t.Fatalf("input_version changed: before %d, after %d, want unchanged", before.InputVersion, after.InputVersion)
	}

	var journalState string
	var annotationID int64
	if err := s.db.QueryRowContext(ctx, `
		SELECT journal_state, annotation_id FROM situation_input_outbox
		WHERE incident_id = ? AND kind = 'operator_annotation_recorded'`, id).Scan(&journalState, &annotationID); err != nil {
		t.Fatal(err)
	}
	if journalState != "owner_terminal" {
		t.Fatalf("journal_state = %q, want owner_terminal", journalState)
	}
	if annotationID != a.ID {
		t.Fatalf("annotation_id = %d, want %d", annotationID, a.ID)
	}

	var transitions int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_transitions WHERE situation_id = ?`, situationID).Scan(&transitions); err != nil {
		t.Fatal(err)
	}
	if transitions != 0 {
		t.Fatalf("situation_transitions for %s = %d, want 0 (owner_terminal is never journaled)", situationID, transitions)
	}

	anns, err := s.ListIncidentAnnotations(ctx, id)
	if err != nil || len(anns) != 1 {
		t.Fatalf("annotation must remain visible via Incident MCP/audit: anns=%+v err=%v", anns, err)
	}
}
