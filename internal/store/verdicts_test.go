// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"errors"
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
