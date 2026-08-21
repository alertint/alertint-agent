// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"errors"
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

// TestAnnotationOrderingSurvivesTrimmedTimestamps pins the newest-first
// contract against the exact hazard that made it intermittent: created_at is
// RFC3339Nano TEXT, which trims trailing zeros, so a later instant can sort
// BELOW an earlier one under SQLite's lexical comparison (".0111Z" < ".011Z").
// Ordering by the monotonic rowid is immune, so this is deterministic.
func TestAnnotationOrderingSurvivesTrimmedTimestamps(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedIncident(t, s, "inc-order", "service=api", "analyzed", time.Now().UTC())

	for _, note := range []string{"first", "second", "third"} {
		if _, err := s.InsertIncidentAnnotation(ctx, "inc-order", "observation", note); err != nil {
			t.Fatal(err)
		}
	}
	// Force the adversarial pair: the newest row's timestamp sorts lexically
	// below its predecessor's, exactly as RFC3339Nano trimming produces.
	if _, err := s.DB().ExecContext(ctx,
		`UPDATE incident_annotations SET created_at = '2026-08-21T14:33:08.011Z' WHERE note = 'second'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().ExecContext(ctx,
		`UPDATE incident_annotations SET created_at = '2026-08-21T14:33:08.0111Z' WHERE note = 'third'`); err != nil {
		t.Fatal(err)
	}

	got, err := s.ListIncidentAnnotations(ctx, "inc-order")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"third", "second", "first"}
	if len(got) != len(want) {
		t.Fatalf("annotations=%d, want %d", len(got), len(want))
	}
	for i, note := range want {
		if got[i].Note != note {
			t.Fatalf("annotations[%d]=%q, want %q (order=%v)", i, got[i].Note, note, notes(got))
		}
	}
}

func notes(in []IncidentAnnotation) []string {
	out := make([]string, 0, len(in))
	for _, a := range in {
		out = append(out, a.Note)
	}
	return out
}
