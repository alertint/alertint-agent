// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"errors"
	"strings"
	"testing"
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

func TestSetRefuteMarksFloor(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := readyIncident(t, s, "service=api")

	if err := s.SetRefuteMarksFloor(ctx, id, 2); err != nil {
		t.Fatalf("floor: %v", err)
	}
	// Floor is MAX(current, floor): raising past it via Increment then re-flooring must not lower.
	if _, err := s.IncrementRefuteMarks(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.IncrementRefuteMarks(ctx, id); err != nil {
		t.Fatal(err)
	} // now 4
	if err := s.SetRefuteMarksFloor(ctx, id, 2); err != nil {
		t.Fatal(err)
	}
	var marks int
	if err := s.DB().QueryRowContext(ctx, `SELECT memory_refute_marks FROM incidents WHERE id = ?`, id).Scan(&marks); err != nil {
		t.Fatal(err)
	}
	if marks != 4 {
		t.Fatalf("floor lowered marks: got %d want 4", marks)
	}
	if err := s.SetRefuteMarksFloor(ctx, "nope", 2); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing incident: want ErrNotFound, got %v", err)
	}
}
