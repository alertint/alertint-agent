// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

// seedIncident inserts an incident row directly in the requested status so
// occurrence tests can attach to analyzed/resolved parents without driving the
// full collecting->ready->analyzed lifecycle.
func seedIncident(t *testing.T, s *Store, id, groupKey, status string, createdAt time.Time) {
	t.Helper()
	ts := createdAt.UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(context.Background(), `
		INSERT INTO incidents
			(id, group_key, status, first_alert_at, last_alert_at, ready_at, alert_count, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
	`, id, groupKey, status, ts, ts, ts, ts, ts)
	if err != nil {
		t.Fatalf("seed incident %s: %v", id, err)
	}
}

func sampleOccurrence(incidentID string, occurredAt time.Time) Occurrence {
	return Occurrence{
		IncidentID:   incidentID,
		OccurredAt:   occurredAt,
		LastSeen:     occurredAt,
		Fingerprints: []string{"fp-" + occurredAt.Format("150405")},
		Payload: []OccurrenceMember{{
			Fingerprint: "fp-" + occurredAt.Format("150405"),
			Labels:      map[string]string{"alertname": "ResourceQuotaExhausted", "severity": "warning"},
			Annotations: map[string]string{"summary": "quota exhausted"},
		}},
		TriggerKind: "none",
	}
}

func TestInsertOccurrence_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 7, 8, 15, 6, 12, 0, time.UTC)
	seedIncident(t, s, "inc_0042", "cluster=prod/ns=batch/svc=report-gen", "analyzed", base)

	occ := sampleOccurrence("inc_0042", base.Add(5*time.Minute))
	id, err := s.InsertOccurrence(ctx, occ)
	if err != nil {
		t.Fatalf("InsertOccurrence: %v", err)
	}
	if id <= 0 {
		t.Fatalf("InsertOccurrence returned id %d, want > 0", id)
	}

	got, err := s.LatestOccurrence(ctx, "inc_0042")
	if err != nil {
		t.Fatalf("LatestOccurrence: %v", err)
	}
	if got.ID != id {
		t.Errorf("LatestOccurrence id = %d, want %d", got.ID, id)
	}
	if !got.OccurredAt.Equal(occ.OccurredAt) {
		t.Errorf("OccurredAt = %v, want %v", got.OccurredAt, occ.OccurredAt)
	}
	if len(got.Fingerprints) != 1 || got.Fingerprints[0] != occ.Fingerprints[0] {
		t.Errorf("Fingerprints = %v, want %v", got.Fingerprints, occ.Fingerprints)
	}
	if len(got.Payload) != 1 || got.Payload[0].Labels["alertname"] != "ResourceQuotaExhausted" {
		t.Errorf("Payload round-trip mismatch: %+v", got.Payload)
	}
	if got.TriggerKind != "none" {
		t.Errorf("TriggerKind = %q, want none", got.TriggerKind)
	}
}

func TestLatestOccurrence_ReturnsMostRecent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 7, 8, 15, 6, 0, 0, time.UTC)
	seedIncident(t, s, "inc_1", "k", "analyzed", base)

	for i := 1; i <= 3; i++ {
		if _, err := s.InsertOccurrence(ctx, sampleOccurrence("inc_1", base.Add(time.Duration(i)*time.Minute))); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	got, err := s.LatestOccurrence(ctx, "inc_1")
	if err != nil {
		t.Fatalf("LatestOccurrence: %v", err)
	}
	if !got.OccurredAt.Equal(base.Add(3 * time.Minute)) {
		t.Errorf("latest OccurredAt = %v, want %v", got.OccurredAt, base.Add(3*time.Minute))
	}
}

func TestLatestOccurrence_NoneReturnsErrNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedIncident(t, s, "inc_empty", "k", "analyzed", time.Now())
	if _, err := s.LatestOccurrence(ctx, "inc_empty"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("LatestOccurrence on empty incident err = %v, want ErrNotFound", err)
	}
}

func TestInsertOccurrence_RejectsUnknownTriggerKind(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedIncident(t, s, "inc_1", "k", "analyzed", time.Now())
	occ := sampleOccurrence("inc_1", time.Now())
	occ.TriggerKind = "bogus"
	if _, err := s.InsertOccurrence(ctx, occ); err == nil {
		t.Fatal("InsertOccurrence accepted an invalid trigger_kind, want error")
	}
}

func TestGetRecentJudgedIncidentByGroupKey_SkipsNewerUnjudged(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 7, 8, 2, 0, 0, 0, time.UTC)
	// analyzed (judged) first, then a NEWER ready row that never analyzed.
	seedIncident(t, s, "inc_judged", "k", "analyzed", base)
	seedIncident(t, s, "inc_ready", "k", "ready", base.Add(1*time.Minute))

	got, err := s.GetRecentJudgedIncidentByGroupKey(ctx, "k")
	if err != nil {
		t.Fatalf("GetRecentJudgedIncidentByGroupKey: %v", err)
	}
	if got.ID != "inc_judged" {
		t.Errorf("got %s, want inc_judged (the trailing ready row must not shadow a judged one)", got.ID)
	}
	if got.LastJudgedAt != nil {
		t.Errorf("LastJudgedAt = %v, want nil when never set", got.LastJudgedAt)
	}
}

func TestGetRecentJudgedIncidentByGroupKey_MostRecentAmongJudged(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 7, 8, 2, 0, 0, 0, time.UTC)
	seedIncident(t, s, "inc_old", "k", "analyzed", base)
	seedIncident(t, s, "inc_recent", "k", "analyzed", base.Add(24*time.Hour))

	got, err := s.GetRecentJudgedIncidentByGroupKey(ctx, "k")
	if err != nil {
		t.Fatalf("GetRecentJudgedIncidentByGroupKey: %v", err)
	}
	if got.ID != "inc_recent" {
		t.Errorf("got %s, want inc_recent (most recent judged)", got.ID)
	}
}

func TestGetRecentJudgedIncidentByGroupKey_NoneJudged(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	base := time.Now().UTC()
	seedIncident(t, s, "inc_collecting", "k", "collecting", base)
	seedIncident(t, s, "inc_ready", "k", "ready", base)
	seedIncident(t, s, "inc_failed", "k", "failed", base)

	if _, err := s.GetRecentJudgedIncidentByGroupKey(ctx, "k"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound when no analyzed/resolved row exists", err)
	}
}

func TestGetRecentJudgedIncidentByGroupKey_ReturnsResolved(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedIncident(t, s, "inc_resolved", "k", "resolved", time.Now().UTC())

	got, err := s.GetRecentJudgedIncidentByGroupKey(ctx, "k")
	if err != nil {
		t.Fatalf("GetRecentJudgedIncidentByGroupKey: %v", err)
	}
	if got.ID != "inc_resolved" {
		t.Errorf("got %s, want inc_resolved (resolved is still a judged status)", got.ID)
	}
}

func TestTouchOccurrenceLastSeen_UpdatesWithoutNewRow(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 7, 8, 15, 0, 0, 0, time.UTC)
	seedIncident(t, s, "inc_1", "k", "analyzed", base)
	id, err := s.InsertOccurrence(ctx, sampleOccurrence("inc_1", base))
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	touched := base.Add(35 * time.Minute)
	if err := s.TouchOccurrenceLastSeen(ctx, id, touched); err != nil {
		t.Fatalf("TouchOccurrenceLastSeen: %v", err)
	}

	stats, err := s.OccurrenceStatsByIncident(ctx, []string{"inc_1"})
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats["inc_1"].Count != 1 {
		t.Errorf("count after touch = %d, want 1 (touch must not add a row)", stats["inc_1"].Count)
	}
	got, err := s.LatestOccurrence(ctx, "inc_1")
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if !got.LastSeen.Equal(touched) {
		t.Errorf("last_seen = %v, want %v", got.LastSeen, touched)
	}
	if !got.OccurredAt.Equal(base) {
		t.Errorf("occurred_at moved to %v, want unchanged %v", got.OccurredAt, base)
	}
}

func TestOccurrenceStatsByIncident_CountFirstLast(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 7, 8, 15, 0, 0, 0, time.UTC)
	seedIncident(t, s, "inc_1", "k", "analyzed", base)
	seedIncident(t, s, "inc_2", "k2", "analyzed", base)
	seedIncident(t, s, "inc_none", "k3", "analyzed", base)

	for i := 1; i <= 3; i++ {
		if _, err := s.InsertOccurrence(ctx, sampleOccurrence("inc_1", base.Add(time.Duration(i)*time.Minute))); err != nil {
			t.Fatalf("insert inc_1 %d: %v", i, err)
		}
	}
	if _, err := s.InsertOccurrence(ctx, sampleOccurrence("inc_2", base.Add(10*time.Minute))); err != nil {
		t.Fatalf("insert inc_2: %v", err)
	}

	stats, err := s.OccurrenceStatsByIncident(ctx, []string{"inc_1", "inc_2", "inc_none"})
	if err != nil {
		t.Fatalf("OccurrenceStatsByIncident: %v", err)
	}
	if stats["inc_1"].Count != 3 {
		t.Errorf("inc_1 count = %d, want 3", stats["inc_1"].Count)
	}
	if !stats["inc_1"].FirstOccurredAt.Equal(base.Add(1 * time.Minute)) {
		t.Errorf("inc_1 first = %v, want %v", stats["inc_1"].FirstOccurredAt, base.Add(1*time.Minute))
	}
	if !stats["inc_1"].LastSeen.Equal(base.Add(3 * time.Minute)) {
		t.Errorf("inc_1 last_seen = %v, want %v", stats["inc_1"].LastSeen, base.Add(3*time.Minute))
	}
	if stats["inc_2"].Count != 1 {
		t.Errorf("inc_2 count = %d, want 1", stats["inc_2"].Count)
	}
	if _, ok := stats["inc_none"]; ok {
		t.Errorf("inc_none present in stats, want absent (no occurrences)")
	}
}

func TestOccurrenceStatsByIncident_EmptyIDs(t *testing.T) {
	s := newTestStore(t)
	stats, err := s.OccurrenceStatsByIncident(context.Background(), nil)
	if err != nil {
		t.Fatalf("OccurrenceStatsByIncident(nil): %v", err)
	}
	if len(stats) != 0 {
		t.Errorf("stats for empty ids = %v, want empty map", stats)
	}
}

func TestKeyEpisodeTimes_UnionSortedWithinLookback(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 7, 8, 2, 0, 0, 0, time.UTC)
	// Three nightly incidents for the same key, each a separate episode.
	seedIncident(t, s, "inc_n1", "nightly", "analyzed", base)
	seedIncident(t, s, "inc_n2", "nightly", "analyzed", base.Add(24*time.Hour))
	seedIncident(t, s, "inc_n3", "nightly", "analyzed", base.Add(48*time.Hour))
	// A different key must not leak in.
	seedIncident(t, s, "inc_other", "other", "analyzed", base.Add(1*time.Hour))
	// Two re-fire occurrences on the middle incident.
	if _, err := s.InsertOccurrence(ctx, sampleOccurrence("inc_n2", base.Add(24*time.Hour+10*time.Minute))); err != nil {
		t.Fatalf("occ1: %v", err)
	}
	if _, err := s.InsertOccurrence(ctx, sampleOccurrence("inc_n2", base.Add(24*time.Hour+20*time.Minute))); err != nil {
		t.Fatalf("occ2: %v", err)
	}

	times, err := s.KeyEpisodeTimes(ctx, "nightly", base.Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("KeyEpisodeTimes: %v", err)
	}
	// 3 incident first-fires + 2 occurrences = 5, ascending.
	want := []time.Time{
		base,
		base.Add(24 * time.Hour),
		base.Add(24*time.Hour + 10*time.Minute),
		base.Add(24*time.Hour + 20*time.Minute),
		base.Add(48 * time.Hour),
	}
	if len(times) != len(want) {
		t.Fatalf("got %d episode times, want %d: %v", len(times), len(want), times)
	}
	for i := range want {
		if !times[i].Equal(want[i]) {
			t.Errorf("episode[%d] = %v, want %v", i, times[i], want[i])
		}
	}
}

func TestKeyEpisodeTimes_ExcludesOutsideLookback(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC)
	seedIncident(t, s, "inc_old", "k", "analyzed", now.Add(-100*24*time.Hour))
	seedIncident(t, s, "inc_recent", "k", "analyzed", now.Add(-1*24*time.Hour))

	times, err := s.KeyEpisodeTimes(ctx, "k", now.Add(-90*24*time.Hour))
	if err != nil {
		t.Fatalf("KeyEpisodeTimes: %v", err)
	}
	if len(times) != 1 || !times[0].Equal(now.Add(-1*24*time.Hour)) {
		t.Errorf("got %v, want only the within-lookback incident first-fire", times)
	}
}

func TestReplaceIncidentOutput_AnalyzedKeepsStatusSetsJudged(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedIncident(t, s, "inc_1", "k", "analyzed", time.Now().UTC())

	before := time.Now().UTC().Add(-time.Second)
	err := s.ReplaceIncidentOutput(ctx, "inc_1", `{"root_cause":"quota"}`, "new summary", "quota raised", 0.85, `{"logs":"x"}`)
	if err != nil {
		t.Fatalf("ReplaceIncidentOutput: %v", err)
	}
	got, err := s.GetIncidentByID(ctx, "inc_1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != "analyzed" {
		t.Errorf("status = %q, want analyzed (replace must not change status)", got.Status)
	}
	if got.Summary != "new summary" || got.RootCause != "quota raised" || got.Confidence != 0.85 {
		t.Errorf("fields not replaced: %+v", got)
	}
	if got.OutputJSON != `{"root_cause":"quota"}` || got.EnrichmentJSON != `{"logs":"x"}` {
		t.Errorf("output/enrichment not replaced: output=%q enrichment=%q", got.OutputJSON, got.EnrichmentJSON)
	}
	if got.LastJudgedAt == nil || got.LastJudgedAt.Before(before) {
		t.Errorf("last_judged_at = %v, want set to ~now", got.LastJudgedAt)
	}
}

func TestReplaceIncidentOutput_ResolvedKeepsStatus(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedIncident(t, s, "inc_r", "k", "resolved", time.Now().UTC())

	if err := s.ReplaceIncidentOutput(ctx, "inc_r", `{}`, "s", "rc", 0.5, ""); err != nil {
		t.Fatalf("ReplaceIncidentOutput on resolved: %v", err)
	}
	got, err := s.GetIncidentByID(ctx, "inc_r")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != "resolved" {
		t.Errorf("status = %q, want resolved unchanged", got.Status)
	}
	if got.LastJudgedAt == nil {
		t.Error("last_judged_at not set on resolved re-judgment")
	}
}

func TestReplaceIncidentOutput_RejectsUnjudgedStatus(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedIncident(t, s, "inc_ready", "k", "ready", time.Now().UTC())
	seedIncident(t, s, "inc_coll", "k2", "collecting", time.Now().UTC())

	for _, id := range []string{"inc_ready", "inc_coll"} {
		if err := s.ReplaceIncidentOutput(ctx, id, `{}`, "s", "rc", 0.5, ""); !errors.Is(err, ErrNotFound) {
			t.Errorf("ReplaceIncidentOutput(%s) err = %v, want ErrNotFound (zero-row must not be silent success)", id, err)
		}
	}
}

func TestReplaceIncidentOutput_EmptyEnrichmentStoresNull(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedIncident(t, s, "inc_1", "k", "analyzed", time.Now().UTC())
	if err := s.ReplaceIncidentOutput(ctx, "inc_1", `{}`, "s", "rc", 0.5, ""); err != nil {
		t.Fatalf("replace: %v", err)
	}
	var enrichment sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT enrichment_json FROM incidents WHERE id = ?`, "inc_1").Scan(&enrichment); err != nil {
		t.Fatalf("read enrichment: %v", err)
	}
	if enrichment.Valid {
		t.Errorf("enrichment_json = %q, want SQL NULL for empty input", enrichment.String)
	}
}

func TestSaveIncidentOutput_SetsLastJudgedAt(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	// Drive collecting -> ready so SaveIncidentOutput's ('ready','processing') guard passes.
	now := time.Now().UTC()
	if err := s.InsertIncident(ctx, Incident{ID: "inc_1", GroupKey: "k", FirstAlertAt: now, LastAlertAt: now, ReadyAt: now, AlertCount: 1}); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	if err := s.MarkIncidentReady(ctx, "inc_1"); err != nil {
		t.Fatalf("mark ready: %v", err)
	}
	before := time.Now().UTC().Add(-time.Second)
	if err := s.SaveIncidentOutput(ctx, "inc_1", `{}`, "s", "rc", 0.7, ""); err != nil {
		t.Fatalf("SaveIncidentOutput: %v", err)
	}
	got, err := s.GetIncidentByID(ctx, "inc_1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.LastJudgedAt == nil || got.LastJudgedAt.Before(before) {
		t.Errorf("last_judged_at = %v, want set to ~now on the initial judgment", got.LastJudgedAt)
	}
}

func TestPruneOccurrences_DeletesOldInBatchesKeepsIncident(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC)
	seedIncident(t, s, "inc_1", "k", "analyzed", now.Add(-200*24*time.Hour))

	// 5 occurrences older than the 90d cutoff, 2 within.
	for i := 0; i < 5; i++ {
		if _, err := s.InsertOccurrence(ctx, sampleOccurrence("inc_1", now.Add(-120*24*time.Hour).Add(time.Duration(i)*time.Minute))); err != nil {
			t.Fatalf("insert old %d: %v", i, err)
		}
	}
	for i := 0; i < 2; i++ {
		if _, err := s.InsertOccurrence(ctx, sampleOccurrence("inc_1", now.Add(-1*24*time.Hour).Add(time.Duration(i)*time.Minute))); err != nil {
			t.Fatalf("insert recent %d: %v", i, err)
		}
	}

	cutoff := now.Add(-90 * 24 * time.Hour)
	deleted, err := s.PruneOccurrences(ctx, cutoff, 2) // batch size 2 exercises the loop
	if err != nil {
		t.Fatalf("PruneOccurrences: %v", err)
	}
	if deleted != 5 {
		t.Errorf("deleted = %d, want 5 (only rows older than cutoff)", deleted)
	}
	stats, err := s.OccurrenceStatsByIncident(ctx, []string{"inc_1"})
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats["inc_1"].Count != 2 {
		t.Errorf("remaining occurrences = %d, want 2", stats["inc_1"].Count)
	}
	if got, err := s.GetIncidentByID(ctx, "inc_1"); err != nil || got == nil {
		t.Errorf("incident row must survive prune: got=%v err=%v", got, err)
	}
}

func TestPruneOccurrences_NothingOldReturnsZero(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedIncident(t, s, "inc_1", "k", "analyzed", now)
	if _, err := s.InsertOccurrence(ctx, sampleOccurrence("inc_1", now)); err != nil {
		t.Fatalf("insert: %v", err)
	}
	deleted, err := s.PruneOccurrences(ctx, now.Add(-90*24*time.Hour), 0)
	if err != nil {
		t.Fatalf("PruneOccurrences: %v", err)
	}
	if deleted != 0 {
		t.Errorf("deleted = %d, want 0", deleted)
	}
}

func TestOccurrences_CascadeDeleteWithIncident(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	base := time.Now().UTC()
	seedIncident(t, s, "inc_del", "k", "analyzed", base)
	if _, err := s.InsertOccurrence(ctx, sampleOccurrence("inc_del", base)); err != nil {
		t.Fatalf("insert: %v", err)
	}

	if _, err := s.db.ExecContext(ctx, `DELETE FROM incidents WHERE id = ?`, "inc_del"); err != nil {
		t.Fatalf("delete incident: %v", err)
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM incident_occurrences WHERE incident_id = ?`, "inc_del").Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("occurrences after incident delete = %d, want 0 (ON DELETE CASCADE)", n)
	}
}
