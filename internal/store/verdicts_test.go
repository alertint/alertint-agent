// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"errors"
	"testing"
)

func TestPersistVerdictCapture_VersionsAndAtomicity(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := readyIncident(t, s, "service=api")

	v1, a1, err := s.PersistVerdictCapture(ctx, VerdictCapture{
		IncidentID: id, Verdict: "correction",
		ExpectationJSON:  `{"must_not_conclude":["AZ outage"]}`,
		WidenedJSON:      `[{"kind":"promql","source":"capture","expr":"node_network_up"}]`,
		CauseCategory:    "network-flap",
		AnnotationNote:   "corrected: not AZ outage",
		DemoteMarksFloor: 2,
	})
	if err != nil {
		t.Fatalf("persist: %v", err)
	}
	if v1.Version != 1 || v1.Verdict != "correction" {
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
}

func TestPersistVerdictCapture_Validation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := readyIncident(t, s, "service=api")
	if _, _, err := s.PersistVerdictCapture(ctx, VerdictCapture{IncidentID: "nope", Verdict: "correction", ExpectationJSON: "{}", AnnotationNote: "x"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if _, _, err := s.PersistVerdictCapture(ctx, VerdictCapture{IncidentID: id, Verdict: "observation", ExpectationJSON: "{}", AnnotationNote: "x"}); err == nil {
		t.Fatal("bad verdict accepted")
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
		if _, _, err := s.PersistVerdictCapture(ctx, VerdictCapture{IncidentID: inc, Verdict: verdict, ExpectationJSON: "{}", AnnotationNote: "n"}); err != nil {
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
