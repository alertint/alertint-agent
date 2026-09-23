// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestPersistVerdictCapture_VersionsAndAtomicity(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := readyIncident(t, s, "service=api")

	v1, a1, err := s.PersistVerdictCapture(ctx, VerdictCapture{
		IncidentID: id, Verdict: "correction",
		Source: VerdictSourceHuman, LabelConfidence: 1,
		ExpectationJSON:  `{"must_not_conclude":["AZ outage"]}`,
		WidenedJSON:      `[{"kind":"promql","source":"capture","expr":"node_network_up"}]`,
		CauseCategory:    "network-flap",
		AnnotationNote:   "corrected: not AZ outage",
		DemoteMarksFloor: 2,
	})
	if err != nil {
		t.Fatalf("persist: %v", err)
	}
	if v1.Version != 1 || v1.Verdict != "correction" || v1.Source != VerdictSourceHuman || v1.LabelConfidence != 1 {
		t.Fatalf("v1: %+v", v1)
	}
	if a1.Kind != "correction" {
		t.Fatalf("annotation kind: %+v", a1)
	}

	var marks int
	if err := s.DB().QueryRowContext(ctx, `SELECT memory_refute_marks FROM incidents WHERE id = ?`, id).Scan(&marks); err != nil {
		t.Fatal(err)
	}
	if marks != 2 {
		t.Fatalf("demotion floor not applied: %d", marks)
	}

	v2, _, err := s.PersistVerdictCapture(ctx, VerdictCapture{
		IncidentID: id, Verdict: "confirmation",
		Source: VerdictSourceHuman, LabelConfidence: 1,
		ExpectationJSON: `{"must_mention":["NIC"]}`, AnnotationNote: "confirmed",
	})
	if err != nil {
		t.Fatalf("persist v2: %v", err)
	}
	if v2.Version != 2 {
		t.Fatalf("want version 2, got %d", v2.Version)
	}

	latest, err := s.LatestIncidentVerdict(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if latest.Version != 2 || latest.Verdict != "confirmation" {
		t.Fatalf("latest: %+v", latest)
	}
	if latest.Source != VerdictSourceHuman || latest.LabelConfidence != 1 {
		t.Fatalf("latest provenance round-trip: %+v", latest)
	}
}

func TestPersistVerdictCapture_Validation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := readyIncident(t, s, "service=api")
	if _, _, err := s.PersistVerdictCapture(ctx, VerdictCapture{IncidentID: "nope", Verdict: "correction", Source: VerdictSourceHuman, LabelConfidence: 1, ExpectationJSON: "{}", AnnotationNote: "x"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if _, _, err := s.PersistVerdictCapture(ctx, VerdictCapture{IncidentID: id, Verdict: "observation", Source: VerdictSourceHuman, LabelConfidence: 1, ExpectationJSON: "{}", AnnotationNote: "x"}); err == nil {
		t.Fatal("bad verdict accepted")
	}
	// Provenance is mandatory: no source, zero-value confidence, and
	// out-of-range confidence are all rejected before anything is written.
	if _, _, err := s.PersistVerdictCapture(ctx, VerdictCapture{IncidentID: id, Verdict: "correction", LabelConfidence: 1, ExpectationJSON: "{}", AnnotationNote: "x"}); err == nil {
		t.Fatal("empty source accepted")
	}
	if _, _, err := s.PersistVerdictCapture(ctx, VerdictCapture{IncidentID: id, Verdict: "correction", Source: VerdictSourceHuman, ExpectationJSON: "{}", AnnotationNote: "x"}); err == nil {
		t.Fatal("zero label_confidence accepted")
	}
	if _, _, err := s.PersistVerdictCapture(ctx, VerdictCapture{IncidentID: id, Verdict: "correction", Source: VerdictSourceHuman, LabelConfidence: 1.5, ExpectationJSON: "{}", AnnotationNote: "x"}); err == nil {
		t.Fatal("label_confidence > 1 accepted")
	}
	// No verdict row may exist after any failed persist (atomicity).
	if v, _ := s.LatestIncidentVerdict(ctx, id); v != nil {
		t.Fatalf("failed persist leaked a verdict row: %+v", v)
	}
}

func TestLatestVerdictKinds(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	a := readyIncident(t, s, "service=a")
	b := readyIncident(t, s, "service=b")
	mustCapture := func(inc, verdict string) {
		t.Helper()
		if _, _, err := s.PersistVerdictCapture(ctx, VerdictCapture{IncidentID: inc, Verdict: verdict, Source: VerdictSourceHuman, LabelConfidence: 1, ExpectationJSON: "{}", AnnotationNote: "n"}); err != nil {
			t.Fatal(err)
		}
	}
	mustCapture(a, "correction")
	mustCapture(a, "confirmation") // v2 wins
	kinds, err := s.LatestVerdictKinds(ctx, []string{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if kinds[a] != "confirmation" {
		t.Fatalf("a: %q", kinds[a])
	}
	if _, ok := kinds[b]; ok {
		t.Fatal("b has no verdict")
	}
}

// mustCapture persists a verdict capture with a human source and full
// confidence, failing the test on error. Shared by the GoverningVerdict tests
// below.
func mustCapture(t *testing.T, s *Store, ctx context.Context, incID, verdict, expJSON, note string) *IncidentVerdict {
	t.Helper()
	v, _, err := s.PersistVerdictCapture(ctx, VerdictCapture{
		IncidentID: incID, Verdict: verdict, Source: VerdictSourceHuman,
		LabelConfidence: 1.0, ExpectationJSON: expJSON, AnnotationNote: note,
	})
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	return v
}

func TestGoverningVerdict_LatestAcrossIncidents(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	now := time.Now().UTC()
	// two incidents on one group key, one on another
	seedJudged(t, s, judged{id: "inc-a", groupKey: "service=checkout", createdAt: now})
	seedJudged(t, s, judged{id: "inc-b", groupKey: "service=checkout", createdAt: now})
	seedJudged(t, s, judged{id: "inc-x", groupKey: "service=other", createdAt: now})

	mustCapture(t, s, ctx, "inc-a", "correction", `{"must_mention":["queue"]}`, "older note")
	mustCapture(t, s, ctx, "inc-b", "confirmation", `{"must_mention":["ok"]}`, "newer note")
	mustCapture(t, s, ctx, "inc-x", "correction", `{"must_mention":["zzz"]}`, "other key")

	v, err := s.GoverningVerdict(ctx, "service=checkout", false)
	if err != nil {
		t.Fatalf("GoverningVerdict: %v", err)
	}
	if v == nil || v.IncidentID != "inc-b" || v.Verdict != "confirmation" {
		t.Fatalf("want newest capture on the key (inc-b confirmation), got %+v", v)
	}
	if v.Note != "newer note" {
		t.Fatalf("want the verdict's annotation note, got %q", v.Note)
	}
}

func TestGoverningVerdict_NoneIsNilNil(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	v, err := s.GoverningVerdict(ctx, "service=ghost", false)
	if err != nil || v != nil {
		t.Fatalf("want nil,nil for a key with no verdicts, got %+v, %v", v, err)
	}
}

// TestGoverningVerdict_LaterAnnotationDoesNotOverrideCapturedNote is a
// regression test: a plain alertint_incident_annotate call of the SAME kind
// on the SAME incident, made after a verdict capture, must never silently
// rewrite the captured verdict's rendered note (the note subquery's
// "a.created_at <= v.created_at" bound is what enforces this).
func TestGoverningVerdict_LaterAnnotationDoesNotOverrideCapturedNote(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	now := time.Now().UTC()
	seedJudged(t, s, judged{id: "inc-a", groupKey: "service=checkout", createdAt: now})

	mustCapture(t, s, ctx, "inc-a", "correction", `{"must_mention":["queue"]}`, "captured note")

	if _, err := s.InsertIncidentAnnotation(ctx, "inc-a", "correction", "a much later, unrelated note"); err != nil {
		t.Fatalf("insert later annotation: %v", err)
	}

	v, err := s.GoverningVerdict(ctx, "service=checkout", false)
	if err != nil {
		t.Fatalf("GoverningVerdict: %v", err)
	}
	if v == nil {
		t.Fatal("want a governing verdict, got nil")
	}
	if v.Note != "captured note" {
		t.Fatalf("a later plain annotation must not override the captured verdict's note, got %q", v.Note)
	}
}

func TestGoverningVerdict_DrillParity(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	now := time.Now().UTC()
	seedJudged(t, s, judged{id: "inc-d", groupKey: "service=checkout", createdAt: now, drill: true}) // alerts carry alertint_drill label
	seedJudged(t, s, judged{id: "inc-r", groupKey: "service=checkout", createdAt: now, drill: false})
	mustCapture(t, s, ctx, "inc-d", "correction", `{"must_mention":["drill"]}`, "drill note")

	// real triage never sees the drill verdict
	if v, err := s.GoverningVerdict(ctx, "service=checkout", false); err != nil || v != nil {
		t.Fatalf("real read must skip drill verdicts, got %+v, %v", v, err)
	}
	// drill triage sees it
	if v, err := s.GoverningVerdict(ctx, "service=checkout", true); err != nil || v == nil || v.IncidentID != "inc-d" {
		t.Fatalf("drill read must see the drill verdict, got %+v, %v", v, err)
	}
}

// ----------------------------------------------------------------------
// Task 8: atomic write-back — PersistVerdictCapture enqueues exactly one
// captured_verdict_recorded situation input (never an
// operator_annotation_recorded one, even though it also writes a matching
// incident_annotations row internally), under the same active/no-owner/
// terminal-owner rules as annotations_test.go's InsertIncidentAnnotation
// coverage. situationOwnedIncident/situationIDForIncident/
// terminalizeSituation/countOutboxRows are defined in annotations_test.go
// (same package).
// ----------------------------------------------------------------------

// TestPersistVerdictCapture_EnqueuesCapturedVerdictRecordedWhenOwnerActive
// proves Step 3's core contract and that the existing governing-verdict/
// Triage effect is unchanged: LatestIncidentVerdict/GoverningVerdict still
// see the captured verdict exactly as before — the new outbox row is a pure
// addition, not a substitute for the verdict/annotation rows themselves.
func TestPersistVerdictCapture_EnqueuesCapturedVerdictRecordedWhenOwnerActive(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := situationOwnedIncident(t, s, "service=verdict-active")

	v, ann, err := s.PersistVerdictCapture(ctx, VerdictCapture{
		IncidentID: id, Verdict: "correction",
		Source: VerdictSourceHuman, LabelConfidence: 1,
		ExpectationJSON: `{"must_not_conclude":["AZ outage"]}`,
		AnnotationNote:  "corrected: not AZ outage",
	})
	if err != nil {
		t.Fatalf("persist: %v", err)
	}

	if n := countOutboxRows(t, s, id, "captured_verdict_recorded"); n != 1 {
		t.Fatalf("captured_verdict_recorded inputs = %d, want 1", n)
	}
	// Never a separate operator_annotation_recorded input for the same
	// event: PersistVerdictCapture's internal annotation write is not itself
	// a plain-annotate write-back.
	if n := countOutboxRows(t, s, id, "operator_annotation_recorded"); n != 0 {
		t.Fatalf("operator_annotation_recorded inputs = %d, want 0 (captured verdict must not also enqueue an annotation input)", n)
	}
	var verdictID int64
	var status, journalState string
	if err := s.db.QueryRowContext(ctx, `
		SELECT verdict_id, status, journal_state FROM situation_input_outbox
		WHERE incident_id = ? AND kind = 'captured_verdict_recorded'`, id).
		Scan(&verdictID, &status, &journalState); err != nil {
		t.Fatal(err)
	}
	if verdictID != v.ID {
		t.Fatalf("verdict_id = %d, want %d (the exact verdict this call persisted)", verdictID, v.ID)
	}
	if status != "pending" || journalState != "pending" {
		t.Fatalf("status=%q journal_state=%q, want pending/pending", status, journalState)
	}

	// Existing governing-verdict/Triage effect is unchanged.
	latest, err := s.LatestIncidentVerdict(ctx, id)
	if err != nil || latest == nil || latest.Version != 1 || latest.Verdict != "correction" {
		t.Fatalf("latest verdict unaffected: %+v, %v", latest, err)
	}
	gov, err := s.GoverningVerdict(ctx, "service=verdict-active", false)
	if err != nil || gov == nil || gov.IncidentID != id {
		t.Fatalf("governing verdict unaffected: %+v, %v", gov, err)
	}
	if ann.Kind != "correction" {
		t.Fatalf("matching annotation row unaffected: %+v", ann)
	}
}

// TestPersistVerdictCapture_NoEnqueueWithoutOwner mirrors
// TestInsertIncidentAnnotation_NoEnqueueWithoutOwner for the verdict path.
func TestPersistVerdictCapture_NoEnqueueWithoutOwner(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := readyIncident(t, s, "service=verdict-unowned")

	if _, _, err := s.PersistVerdictCapture(ctx, VerdictCapture{
		IncidentID: id, Verdict: "correction",
		Source: VerdictSourceHuman, LabelConfidence: 1,
		ExpectationJSON: `{}`, AnnotationNote: "note",
	}); err != nil {
		t.Fatalf("persist: %v", err)
	}
	if v, err := s.LatestIncidentVerdict(ctx, id); err != nil || v == nil {
		t.Fatalf("verdict must still be visible: v=%+v err=%v", v, err)
	}
	if n := countOutboxRows(t, s, id, "captured_verdict_recorded"); n != 0 {
		t.Fatalf("captured_verdict_recorded inputs = %d, want 0 (no owner at all)", n)
	}
}

// TestPersistVerdictCapture_NoEnqueueForTerminalOwner mirrors
// TestInsertIncidentAnnotation_NoEnqueueForTerminalOwner for the verdict
// path.
func TestPersistVerdictCapture_NoEnqueueForTerminalOwner(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := situationOwnedIncident(t, s, "service=verdict-terminal")
	situationID := situationIDForIncident(t, s, id)
	terminalizeSituation(t, s, situationID, time.Now().UTC().Add(time.Hour))

	if _, _, err := s.PersistVerdictCapture(ctx, VerdictCapture{
		IncidentID: id, Verdict: "correction",
		Source: VerdictSourceHuman, LabelConfidence: 1,
		ExpectationJSON: `{}`, AnnotationNote: "note",
	}); err != nil {
		t.Fatalf("persist: %v", err)
	}
	if v, err := s.LatestIncidentVerdict(ctx, id); err != nil || v == nil {
		t.Fatalf("verdict must still be visible: v=%+v err=%v", v, err)
	}
	if n := countOutboxRows(t, s, id, "captured_verdict_recorded"); n != 0 {
		t.Fatalf("captured_verdict_recorded inputs = %d, want 0 (owner already terminal at write time)", n)
	}
}

// TestPersistVerdictCapture_RetrySameVerdictIDIsIdempotent mirrors
// TestInsertIncidentAnnotation_RetrySameAnnotationIDIsIdempotent for the
// verdict path's own idempotency-key derivation.
func TestPersistVerdictCapture_RetrySameVerdictIDIsIdempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := situationOwnedIncident(t, s, "service=verdict-retry")
	verdictID, err := insertVerdictRow(ctx, s, id, 1)
	if err != nil {
		t.Fatalf("seed verdict: %v", err)
	}
	idempotencyKey := fmt.Sprintf("captured-verdict:%d", verdictID)

	for i := 0; i < 2; i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := enqueueOperatorArtifactInputTx(ctx, tx, id, "captured_verdict_recorded", idempotencyKey, nil, verdictID, time.Now().UTC()); err != nil {
			t.Fatalf("enqueue attempt %d: %v", i, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	if n := countOutboxRows(t, s, id, "captured_verdict_recorded"); n != 1 {
		t.Fatalf("captured_verdict_recorded inputs after retry = %d, want 1 (idempotent replay)", n)
	}
}

// TestPersistVerdictCapture_R2RaceOwnerTerminalizesBeforeApply mirrors
// TestInsertIncidentAnnotation_R2RaceOwnerTerminalizesBeforeApply for the
// verdict path's full round trip through Task 2's already-implemented
// ApplySituationInput R2 handling.
func TestPersistVerdictCapture_R2RaceOwnerTerminalizesBeforeApply(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := situationOwnedIncident(t, s, "service=verdict-r2-race")
	situationID := situationIDForIncident(t, s, id)

	v, _, err := s.PersistVerdictCapture(ctx, VerdictCapture{
		IncidentID: id, Verdict: "correction",
		Source: VerdictSourceHuman, LabelConfidence: 1,
		ExpectationJSON: `{}`, AnnotationNote: "note",
	})
	if err != nil {
		t.Fatalf("persist: %v", err)
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
	var verdictID int64
	if err := s.db.QueryRowContext(ctx, `
		SELECT journal_state, verdict_id FROM situation_input_outbox
		WHERE incident_id = ? AND kind = 'captured_verdict_recorded'`, id).Scan(&journalState, &verdictID); err != nil {
		t.Fatal(err)
	}
	if journalState != "owner_terminal" {
		t.Fatalf("journal_state = %q, want owner_terminal", journalState)
	}
	if verdictID != v.ID {
		t.Fatalf("verdict_id = %d, want %d", verdictID, v.ID)
	}

	var transitions int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_transitions WHERE situation_id = ?`, situationID).Scan(&transitions); err != nil {
		t.Fatal(err)
	}
	if transitions != 0 {
		t.Fatalf("situation_transitions for %s = %d, want 0 (owner_terminal is never journaled)", situationID, transitions)
	}

	if latest, err := s.LatestIncidentVerdict(ctx, id); err != nil || latest == nil {
		t.Fatalf("verdict must remain visible via Incident MCP/audit: latest=%+v err=%v", latest, err)
	}
}
