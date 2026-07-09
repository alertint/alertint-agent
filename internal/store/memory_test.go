// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// judged describes a seeded, already-analyzed incident carrying a finding, an
// optional drill/real member alert, refute marks, and a persisted enrichment
// envelope — everything MemoryView reads.
type judged struct {
	id, groupKey, status string
	createdAt            time.Time
	lastJudgedAt         time.Time // zero -> NULL
	confidence           float64
	rootCause, summary   string
	enrichmentJSON       string
	marks                int
	drill                bool
}

func seedJudged(t *testing.T, s *Store, j judged) {
	t.Helper()
	ctx := context.Background()
	if j.status == "" {
		j.status = "analyzed"
	}
	ts := j.createdAt.UTC().Format(time.RFC3339Nano)
	var judgedAt any
	if !j.lastJudgedAt.IsZero() {
		judgedAt = j.lastJudgedAt.UTC().Format(time.RFC3339Nano)
	}
	var enrichment any
	if j.enrichmentJSON != "" {
		enrichment = j.enrichmentJSON
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO incidents
			(id, group_key, status, first_alert_at, last_alert_at, ready_at, alert_count,
			 summary, root_cause, confidence, output_json, enrichment_json,
			 created_at, updated_at, last_judged_at, memory_refute_marks)
		VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, '{}', ?, ?, ?, ?, ?)
	`, j.id, j.groupKey, j.status, ts, ts, ts,
		j.summary, j.rootCause, j.confidence, enrichment,
		ts, ts, judgedAt, j.marks)
	if err != nil {
		t.Fatalf("seed judged %s: %v", j.id, err)
	}

	// A member alert so IncidentDrillFlags can classify the incident's drill-ness.
	labels := map[string]string{"alertname": "DiskFill", "service": "backup-agent"}
	if j.drill {
		labels[DrillMarkerLabel] = DrillMarkerValue
	}
	a := Alert{
		ID:          uuid.NewString(),
		Fingerprint: "fp-" + j.id,
		Status:      "firing",
		Labels:      labels,
		Annotations: map[string]string{"summary": "disk filling"},
		StartsAt:    j.createdAt,
		ReceivedAt:  j.createdAt,
	}
	if _, err := s.UpsertAlertByFingerprint(ctx, a); err != nil {
		t.Fatalf("seed member alert for %s: %v", j.id, err)
	}
	if err := s.AddAlertToIncident(ctx, j.id, a.ID, j.createdAt); err != nil {
		t.Fatalf("attach member alert for %s: %v", j.id, err)
	}
}

// addOccurrences inserts n occurrence rows on incident id, one per step starting
// at first+step.
func addOccurrences(t *testing.T, s *Store, id string, first time.Time, n int, step time.Duration) {
	t.Helper()
	ctx := context.Background()
	for i := 1; i <= n; i++ {
		occ := sampleOccurrence(id, first.Add(time.Duration(i)*step))
		if _, err := s.InsertOccurrence(ctx, occ); err != nil {
			t.Fatalf("insert occurrence %d on %s: %v", i, id, err)
		}
	}
}

func TestMemoryView_SameKeyFoldsCountsAndCadence(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 9, 2, 0, 0, 0, time.UTC)
	since := now.AddDate(0, 0, -90)
	key := "cluster=prod-eu1,namespace=backups,service=backup-agent"

	// One prior incident, first fire 4 days ago + 3 daily occurrences → 4 episodes.
	base := now.AddDate(0, 0, -4)
	seedJudged(t, s, judged{id: "inc_prior", groupKey: key, createdAt: base,
		lastJudgedAt: base, confidence: 0.70, rootCause: "backup rotation misconfigured", summary: "backup-disk-fill"})
	addOccurrences(t, s, "inc_prior", base, 3, 24*time.Hour)

	v, err := s.MemoryView(ctx, key, "inc_current", false, since)
	if err != nil {
		t.Fatalf("MemoryView: %v", err)
	}
	if len(v.PriorFindings) != 1 {
		t.Fatalf("prior findings = %d, want 1", len(v.PriorFindings))
	}
	if v.Episodes != 4 {
		t.Errorf("folded Episodes = %d, want 4", v.Episodes)
	}
	if got := v.CadenceMedian; got != 24*time.Hour {
		t.Errorf("CadenceMedian = %v, want 24h", got)
	}
	pf := v.PriorFindings[0]
	if pf.IncidentID != "inc_prior" || pf.Confidence != 0.70 || pf.RootCause != "backup rotation misconfigured" {
		t.Errorf("prior finding fields wrong: %+v", pf)
	}
	if pf.Episodes != 4 {
		t.Errorf("prior Episodes = %d, want 4", pf.Episodes)
	}
	if !v.FirstSeen.Equal(base) || !v.LastSeen.Equal(base.AddDate(0, 0, 3)) {
		t.Errorf("first/last = %v/%v", v.FirstSeen, v.LastSeen)
	}
}

func TestMemoryView_FirstFireBeforeLookbackStillCountsAsEpisode(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 9, 2, 0, 0, 0, time.UTC)
	since := now.AddDate(0, 0, -90)
	key := "cluster=prod,namespace=web,service=api"

	// A prior created inside the lookback but whose first alert (an old StartsAt)
	// predates the cutoff, with no in-window occurrences. Its founding episode must
	// still count so the render never shows "[folded ×0]".
	created := now.AddDate(0, 0, -2)
	oldFirstFire := since.AddDate(0, 0, -5) // before the cutoff
	ts := created.UTC().Format(time.RFC3339Nano)
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO incidents (id, group_key, status, first_alert_at, last_alert_at, ready_at, alert_count,
			summary, root_cause, confidence, output_json, created_at, updated_at, last_judged_at, memory_refute_marks)
		VALUES ('inc_old_fire', ?, 'analyzed', ?, ?, ?, 1, 's', 'rc', 0.6, '{}', ?, ?, ?, 0)
	`, key, oldFirstFire.UTC().Format(time.RFC3339Nano), ts, ts, ts, ts, ts); err != nil {
		t.Fatalf("seed: %v", err)
	}

	v, err := s.MemoryView(ctx, key, "inc_current", false, since)
	if err != nil {
		t.Fatalf("MemoryView: %v", err)
	}
	if len(v.PriorFindings) != 1 {
		t.Fatalf("want 1 prior, got %d", len(v.PriorFindings))
	}
	if v.Episodes < 1 {
		t.Errorf("Episodes = %d, want >= 1 (the founding fire must count, never ×0)", v.Episodes)
	}
}

func TestMemoryView_KeyWithNoOccurrencesRecallsPriorWithCount1(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 9, 2, 0, 0, 0, time.UTC)
	since := now.AddDate(0, 0, -90)
	key := "cluster=prod,namespace=web,service=api"
	seedJudged(t, s, judged{id: "inc_lonely", groupKey: key, createdAt: now.AddDate(0, 0, -1), confidence: 0.5, rootCause: "one-off"})

	v, err := s.MemoryView(ctx, key, "inc_current", false, since)
	if err != nil {
		t.Fatalf("MemoryView: %v", err)
	}
	if len(v.PriorFindings) != 1 || v.PriorFindings[0].Episodes != 1 {
		t.Fatalf("want 1 prior with Episodes 1, got %+v", v.PriorFindings)
	}
	if v.Episodes != 1 {
		t.Errorf("folded Episodes = %d, want 1 (the first fire)", v.Episodes)
	}
	if v.CadenceMedian != 0 {
		t.Errorf("CadenceMedian = %v, want 0 for a single episode", v.CadenceMedian)
	}
}

func TestMemoryView_ExcludesCurrentIncident(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 9, 2, 0, 0, 0, time.UTC)
	since := now.AddDate(0, 0, -90)
	key := "cluster=prod,namespace=web,service=api"
	seedJudged(t, s, judged{id: "inc_self", groupKey: key, createdAt: now.AddDate(0, 0, -1), rootCause: "self"})

	v, err := s.MemoryView(ctx, key, "inc_self", false, since)
	if err != nil {
		t.Fatalf("MemoryView: %v", err)
	}
	if len(v.PriorFindings) != 0 {
		t.Errorf("current incident must not appear in its own view, got %+v", v.PriorFindings)
	}
}

func TestMemoryView_LookbackExcludesOldPrior(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 9, 2, 0, 0, 0, time.UTC)
	since := now.AddDate(0, 0, -90)
	key := "cluster=prod,namespace=web,service=api"
	seedJudged(t, s, judged{id: "inc_old", groupKey: key, createdAt: now.AddDate(0, 0, -91), rootCause: "ancient"})
	seedJudged(t, s, judged{id: "inc_recent", groupKey: key, createdAt: now.AddDate(0, 0, -2), rootCause: "recent"})

	v, err := s.MemoryView(ctx, key, "inc_current", false, since)
	if err != nil {
		t.Fatalf("MemoryView: %v", err)
	}
	if len(v.PriorFindings) != 1 || v.PriorFindings[0].IncidentID != "inc_recent" {
		t.Errorf("91-day-old prior must be absent; got %+v", v.PriorFindings)
	}
}

func TestMemoryView_DrillParityBidirectional(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 9, 2, 0, 0, 0, time.UTC)
	since := now.AddDate(0, 0, -90)
	key := "cluster=prod,namespace=web,service=api"
	seedJudged(t, s, judged{id: "inc_real", groupKey: key, createdAt: now.AddDate(0, 0, -1), rootCause: "real", drill: false})
	seedJudged(t, s, judged{id: "inc_drill", groupKey: key, createdAt: now.AddDate(0, 0, -2), rootCause: "drill", drill: true})

	// A real triage recalls only the real prior, and marks that a drill prior was filtered.
	realView, err := s.MemoryView(ctx, key, "inc_current", false, since)
	if err != nil {
		t.Fatalf("MemoryView(real): %v", err)
	}
	if len(realView.PriorFindings) != 1 || realView.PriorFindings[0].IncidentID != "inc_real" {
		t.Errorf("real view must exclude drill priors, got %+v", realView.PriorFindings)
	}
	if !realView.DrillFiltered {
		t.Error("real view should record that a drill prior was filtered")
	}
	// A drill triage recalls only the drill prior.
	drill, err := s.MemoryView(ctx, key, "inc_current", true, since)
	if err != nil {
		t.Fatalf("MemoryView(drill): %v", err)
	}
	if len(drill.PriorFindings) != 1 || drill.PriorFindings[0].IncidentID != "inc_drill" {
		t.Errorf("drill view must exclude real priors, got %+v", drill.PriorFindings)
	}
}

func TestMemoryView_CorroboratingIssueIDsFromEnrichment(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 9, 2, 0, 0, 0, time.UTC)
	since := now.AddDate(0, 0, -90)
	key := "cluster=prod,namespace=web,service=api"
	env := `{"sentry":{"reconciliation":{"tag":"matched","corroborating_issue_ids":["ISSUE-1","ISSUE-2"]}}}`
	seedJudged(t, s, judged{id: "inc_sentry", groupKey: key, createdAt: now.AddDate(0, 0, -1), rootCause: "err", enrichmentJSON: env})

	v, err := s.MemoryView(ctx, key, "inc_current", false, since)
	if err != nil {
		t.Fatalf("MemoryView: %v", err)
	}
	if len(v.PriorFindings) != 1 {
		t.Fatalf("want 1 prior, got %d", len(v.PriorFindings))
	}
	got := v.PriorFindings[0].CorroboratingIssueIDs
	if len(got) != 2 || got[0] != "ISSUE-1" || got[1] != "ISSUE-2" {
		t.Errorf("corroborating ids = %v, want [ISSUE-1 ISSUE-2]", got)
	}
}

func TestMemoryView_ExposesRefuteMarks(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 9, 2, 0, 0, 0, time.UTC)
	since := now.AddDate(0, 0, -90)
	key := "cluster=prod,namespace=web,service=api"
	seedJudged(t, s, judged{id: "inc_marked", groupKey: key, createdAt: now.AddDate(0, 0, -1), rootCause: "stale", marks: 2})

	v, err := s.MemoryView(ctx, key, "inc_current", false, since)
	if err != nil {
		t.Fatalf("MemoryView: %v", err)
	}
	if len(v.PriorFindings) != 1 || v.PriorFindings[0].ContradictionMarks != 2 {
		t.Errorf("want ContradictionMarks 2, got %+v", v.PriorFindings)
	}
}

func TestRefuteMarks_IncrementAndClear(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedJudged(t, s, judged{id: "inc_m", groupKey: "k=v", createdAt: now, rootCause: "x"})

	n, err := s.IncrementRefuteMarks(ctx, "inc_m")
	if err != nil || n != 1 {
		t.Fatalf("increment #1 = %d, %v; want 1", n, err)
	}
	n, err = s.IncrementRefuteMarks(ctx, "inc_m")
	if err != nil || n != 2 {
		t.Fatalf("increment #2 = %d, %v; want 2", n, err)
	}
	if err := s.ClearRefuteMarks(ctx, "inc_m"); err != nil {
		t.Fatalf("clear: %v", err)
	}
	n, err = s.IncrementRefuteMarks(ctx, "inc_m")
	if err != nil || n != 1 {
		t.Fatalf("increment after clear = %d, %v; want 1", n, err)
	}
	if _, err := s.IncrementRefuteMarks(ctx, "nope"); err != ErrNotFound {
		t.Errorf("increment on missing incident = %v, want ErrNotFound", err)
	}
}

func TestMemoryPrefilter_DiffersInExactlyOne(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 9, 2, 0, 0, 0, time.UTC)
	since := now.AddDate(0, 0, -90)
	current := "cluster=prod,namespace=storage,service=nfs-01"

	// exact match — excluded (that's rung 1/2, not the prefilter)
	seedJudged(t, s, judged{id: "inc_exact", groupKey: current, createdAt: now.AddDate(0, 0, -1), rootCause: "exact"})
	// differs in exactly one value (service) — a weak candidate
	seedJudged(t, s, judged{id: "inc_one", groupKey: "cluster=prod,namespace=storage,service=nfs-02", createdAt: now.AddDate(0, 0, -2), rootCause: "one-off"})
	// differs in two values (namespace + service) — excluded
	seedJudged(t, s, judged{id: "inc_two", groupKey: "cluster=prod,namespace=batch,service=report-gen", createdAt: now.AddDate(0, 0, -3), rootCause: "two-off"})
	// different key set (extra label) — excluded
	seedJudged(t, s, judged{id: "inc_shape", groupKey: "cluster=prod,namespace=storage,service=nfs-01,team=sre", createdAt: now.AddDate(0, 0, -4), rootCause: "shape"})

	got, err := s.MemoryPrefilter(ctx, current, "inc_current", false, since, 3)
	if err != nil {
		t.Fatalf("MemoryPrefilter: %v", err)
	}
	if len(got) != 1 || got[0].IncidentID != "inc_one" {
		t.Fatalf("want only inc_one, got %+v", got)
	}
}

func TestMemoryPrefilter_CapAtLimitMostRecent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 9, 2, 0, 0, 0, time.UTC)
	since := now.AddDate(0, 0, -90)
	current := "cluster=prod,namespace=storage,service=nfs-01"
	// Five one-label-off candidates at decreasing recency; cap 3 keeps the newest 3.
	for i := 1; i <= 5; i++ {
		seedJudged(t, s, judged{
			id:        "inc_c" + string(rune('0'+i)),
			groupKey:  "cluster=prod,namespace=storage,service=nfs-0" + string(rune('0'+i+1)),
			createdAt: now.AddDate(0, 0, -i),
			rootCause: "candidate",
		})
	}
	got, err := s.MemoryPrefilter(ctx, current, "inc_current", false, since, 3)
	if err != nil {
		t.Fatalf("MemoryPrefilter: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("cap = %d, want 3", len(got))
	}
	// Most-recent-first: inc_c1 (1 day ago) .. inc_c3 (3 days ago).
	if got[0].IncidentID != "inc_c1" || got[2].IncidentID != "inc_c3" {
		t.Errorf("cap should keep the 3 most recent, got %s..%s", got[0].IncidentID, got[2].IncidentID)
	}
}
