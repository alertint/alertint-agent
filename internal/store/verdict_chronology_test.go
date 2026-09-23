// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"testing"
	"time"
)

// Verdict and annotation times are stored as RFC3339Nano text, and Go's
// formatter trims trailing zeros from the fraction. So the stored width
// varies row by row: ".2378Z", ".237872Z", ".1Z" and a bare "Z" all occur in
// databases written by earlier releases. Text order is NOT chronological
// order across those widths — a shorter value's "Z" sorts above the next
// digit of a longer one — so every comparison and every ordering of these
// values has to happen on parsed instants.
//
// The tests below stamp exact stored text rather than relying on whatever
// fraction time.Now() happens to produce, which is what made the
// pre-existing note regression fail only about once in every 75 runs.

func stampVerdictCreatedAt(t *testing.T, s *Store, incidentID, text string) {
	t.Helper()
	if _, err := s.db.ExecContext(context.Background(), `UPDATE incident_verdicts SET created_at = ? WHERE incident_id = ?`, text, incidentID); err != nil {
		t.Fatalf("stamp verdict created_at: %v", err)
	}
}

func stampAnnotationCreatedAt(t *testing.T, s *Store, incidentID, note, text string) {
	t.Helper()
	res, err := s.db.ExecContext(context.Background(), `UPDATE incident_annotations SET created_at = ? WHERE incident_id = ? AND note = ?`, text, incidentID, note)
	if err != nil {
		t.Fatalf("stamp annotation created_at: %v", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		t.Fatalf("stamp annotation rows: %v", err)
	}
	if n != 1 {
		t.Fatalf("stamp annotation %q: %d rows, want 1", note, n)
	}
}

// TestGoverningVerdictNoteBoundIsChronological drives the note bound with
// stored rows whose fractional precision differs, which is the shape every
// real database already holds. The captured note must survive a later plain
// annotation of the same kind, and must not be discarded when its own text
// happens to sort above the verdict's.
func TestGoverningVerdictNoteBoundIsChronological(t *testing.T) {
	cases := []struct {
		name              string
		verdictAt         string
		capturedAt        string
		laterAt           string
		want              string
		wantCreatedAtNano int
	}{
		{
			name:              "later annotation carries more fractional digits",
			verdictAt:         "2026-09-09T19:22:23.2378Z",
			capturedAt:        "2026-09-09T19:22:23.2377Z",
			laterAt:           "2026-09-09T19:22:23.237872Z",
			want:              "captured note",
			wantCreatedAtNano: 237800000,
		},
		{
			name:              "verdict fraction was written with a trimmed trailing zero",
			verdictAt:         "2026-09-09T19:22:23.1Z",
			capturedAt:        "2026-09-09T19:22:23.05Z",
			laterAt:           "2026-09-09T19:22:23.12Z",
			want:              "captured note",
			wantCreatedAtNano: 100000000,
		},
		{
			name:              "captured note's own text sorts above the verdict's",
			verdictAt:         "2026-09-09T19:22:23.24Z",
			capturedAt:        "2026-09-09T19:22:23.2Z",
			laterAt:           "2026-09-09T19:22:23.3Z",
			want:              "captured note",
			wantCreatedAtNano: 240000000,
		},
		{
			name:              "verdict landed on an exact second",
			verdictAt:         "2026-09-09T19:22:23Z",
			capturedAt:        "2026-09-09T19:22:22.999Z",
			laterAt:           "2026-09-09T19:22:23.5Z",
			want:              "captured note",
			wantCreatedAtNano: 0,
		},
		{
			// Nothing distinguishes the two annotations in time, so the
			// newest stored row still wins. Pinned so the repair keeps a
			// deterministic answer instead of an arbitrary one.
			name:              "equal instants fall back to the newest stored row",
			verdictAt:         "2026-09-09T19:22:23.5Z",
			capturedAt:        "2026-09-09T19:22:23.5Z",
			laterAt:           "2026-09-09T19:22:23.5Z",
			want:              "later note",
			wantCreatedAtNano: 500000000,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s := newTestStore(t)
			seedJudged(t, s, judged{id: "inc-a", groupKey: "service=checkout", createdAt: time.Now().UTC()})
			mustCapture(t, s, ctx, "inc-a", "correction", `{"must_mention":["queue"]}`, "captured note")
			if _, err := s.InsertIncidentAnnotation(ctx, "inc-a", "correction", "later note"); err != nil {
				t.Fatalf("insert later annotation: %v", err)
			}
			stampVerdictCreatedAt(t, s, "inc-a", tc.verdictAt)
			stampAnnotationCreatedAt(t, s, "inc-a", "captured note", tc.capturedAt)
			stampAnnotationCreatedAt(t, s, "inc-a", "later note", tc.laterAt)

			v, err := s.GoverningVerdict(ctx, "service=checkout", false)
			if err != nil {
				t.Fatalf("GoverningVerdict: %v", err)
			}
			if v == nil {
				t.Fatal("want a governing verdict, got nil")
			}
			if v.Note != tc.want {
				t.Fatalf("note = %q, want %q (verdict %s, captured %s, later %s)", v.Note, tc.want, tc.verdictAt, tc.capturedAt, tc.laterAt)
			}
			if got := v.CreatedAt.Nanosecond(); got != tc.wantCreatedAtNano {
				t.Fatalf("verdict CreatedAt nanosecond = %d, want %d — the stored fraction must survive the read", got, tc.wantCreatedAtNano)
			}
		})
	}
}

// TestGoverningVerdictOrdersCandidatesChronologically covers the second half
// of the same defect: which verdict governs at all. Two incidents share the
// group key, and the newer capture's text sorts below the older one's.
func TestGoverningVerdictOrdersCandidatesChronologically(t *testing.T) {
	cases := []struct {
		name             string
		earlierAt, later string
	}{
		{
			name:      "newer capture carries more fractional digits",
			earlierAt: "2026-09-09T19:22:23.2378Z",
			later:     "2026-09-09T19:22:23.237872Z",
		},
		{
			name:      "older capture landed on an exact second",
			earlierAt: "2026-09-09T19:22:23Z",
			later:     "2026-09-09T19:22:23.5Z",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s := newTestStore(t)
			now := time.Now().UTC()
			seedJudged(t, s, judged{id: "inc-old", groupKey: "service=checkout", createdAt: now})
			seedJudged(t, s, judged{id: "inc-new", groupKey: "service=checkout", createdAt: now})
			mustCapture(t, s, ctx, "inc-old", "correction", `{"must_mention":["old"]}`, "older note")
			mustCapture(t, s, ctx, "inc-new", "confirmation", `{"must_mention":["new"]}`, "newer note")

			stampVerdictCreatedAt(t, s, "inc-old", tc.earlierAt)
			stampAnnotationCreatedAt(t, s, "inc-old", "older note", tc.earlierAt)
			stampVerdictCreatedAt(t, s, "inc-new", tc.later)
			stampAnnotationCreatedAt(t, s, "inc-new", "newer note", tc.later)

			v, err := s.GoverningVerdict(ctx, "service=checkout", false)
			if err != nil {
				t.Fatalf("GoverningVerdict: %v", err)
			}
			if v == nil {
				t.Fatal("want a governing verdict, got nil")
			}
			if v.IncidentID != "inc-new" {
				t.Fatalf("governing verdict = %s (%s at %s), want inc-new captured at %s", v.IncidentID, v.Verdict, tc.earlierAt, tc.later)
			}
			if v.Note != "newer note" {
				t.Fatalf("note = %q, want the governing capture's own note", v.Note)
			}
		})
	}
}

// TestAnnotationRecallOrdersOnInstantsNotText covers the same stored-text
// defect on the recall path. Which notes reach a triage prompt depends on
// this order: steering.go keeps the first maxHistoryNotes and only counts the
// rest. The three stamped fractions sort one way as text and another way in
// time.
func TestAnnotationRecallOrdersOnInstantsNotText(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedJudged(t, s, judged{id: "inc-a", groupKey: "service=checkout", createdAt: time.Now().UTC()})

	stamps := []struct{ note, at string }{
		{"newest", "2026-09-09T19:22:23.24Z"},     // 240ms
		{"middle", "2026-09-09T19:22:23.237872Z"}, // 237.872ms
		{"oldest", "2026-09-09T19:22:23.2378Z"},   // 237.8ms — sorts above "middle" as text
	}
	for _, st := range stamps {
		if _, err := s.InsertIncidentAnnotation(ctx, "inc-a", "observation", st.note); err != nil {
			t.Fatalf("insert %s: %v", st.note, err)
		}
		stampAnnotationCreatedAt(t, s, "inc-a", st.note, st.at)
	}
	want := []string{"newest", "middle", "oldest"}

	listed, err := s.ListIncidentAnnotations(ctx, "inc-a")
	if err != nil {
		t.Fatalf("ListIncidentAnnotations: %v", err)
	}
	got := make([]string, len(listed))
	for i, a := range listed {
		got[i] = a.Note
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("ListIncidentAnnotations order = %v, want %v", got, want)
	}

	recalled, err := s.OperatorAnnotations(ctx, "service=checkout", false)
	if err != nil {
		t.Fatalf("OperatorAnnotations: %v", err)
	}
	got = make([]string, len(recalled))
	for i, a := range recalled {
		got[i] = a.Note
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("OperatorAnnotations order = %v, want %v", got, want)
	}
}
