// SPDX-License-Identifier: FSL-1.1-ALv2

package correlator

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/google/uuid"
)

// --- test doubles ---

type fakeOccNotifier struct {
	mu    sync.Mutex
	calls []notify.RecurrenceEvent
}

func (f *fakeOccNotifier) OnOccurrenceAttached(_ context.Context, ev notify.RecurrenceEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, ev)
	return nil
}
func (f *fakeOccNotifier) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }

type auditRow struct {
	kind    string
	trigger string
}
type fakeAuditor struct {
	mu   sync.Mutex
	rows []auditRow
}

func (a *fakeAuditor) Append(_ context.Context, _, kind string, payload any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	trig := ""
	if m, ok := payload.(map[string]any); ok {
		trig, _ = m["trigger"].(string)
	}
	a.rows = append(a.rows, auditRow{kind: kind, trigger: trig})
	return nil
}
func (a *fakeAuditor) occurrenceAttachedCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, r := range a.rows {
		if r.kind == "incident.occurrence_attached" {
			n++
		}
	}
	return n
}

type fakeRejudger struct {
	mu       sync.Mutex
	triggers []string
}

func (r *fakeRejudger) Rejudge(_ context.Context, _ store.Incident, trigger string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.triggers = append(r.triggers, trigger)
	return nil
}
func (r *fakeRejudger) count() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.triggers) }

type testDoubles struct {
	notif *fakeOccNotifier
	aud   *fakeAuditor
	rej   *fakeRejudger
}

// --- helpers ---

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// newCorrelatorFor builds a non-started correlator wired with the three test
// doubles, grouping on the "service" label.
func newCorrelatorFor(t *testing.T, st *store.Store) (*Correlator, *testDoubles) {
	t.Helper()
	c := New(Config{GroupLabels: []string{"service"}}, st, NopIncidentSink{}, nil)
	td := &testDoubles{notif: &fakeOccNotifier{}, aud: &fakeAuditor{}, rej: &fakeRejudger{}}
	c.SetOccurrenceNotifier(td.notif)
	c.SetAuditor(td.aud)
	c.SetRejudger(td.rej)
	return c, td
}

const gkAPI = "service=api"

func firingAlert(fp, alertname, sev string, at time.Time, drill bool) store.Alert {
	labels := map[string]string{"service": "api", "alertname": alertname, "severity": sev}
	if drill {
		labels[store.DrillMarkerLabel] = store.DrillMarkerValue
	}
	return store.Alert{
		ID:          uuid.NewString(),
		Fingerprint: fp,
		Status:      "firing",
		Labels:      labels,
		Annotations: map[string]string{"summary": "disk filling"},
		StartsAt:    at,
		ReceivedAt:  at,
	}
}

// seedJudged inserts a judged incident for the shared key with one member alert,
// at the given last-activity and last-judged timestamps.
func seedJudged(t *testing.T, st *store.Store, id, status string, lastActivity, lastJudged time.Time, member store.Alert) {
	t.Helper()
	ctx := context.Background()
	ts := func(x time.Time) string { return x.UTC().Format(time.RFC3339Nano) }
	_, err := st.DB().ExecContext(ctx, `
		INSERT INTO incidents
			(id, group_key, status, first_alert_at, last_alert_at, ready_at, alert_count, last_judged_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
	`, id, gkAPI, status, ts(lastActivity), ts(lastActivity), ts(lastActivity), ts(lastJudged), ts(lastActivity), ts(lastActivity))
	if err != nil {
		t.Fatalf("seed incident: %v", err)
	}
	if _, err := st.UpsertAlertByFingerprint(ctx, member); err != nil {
		t.Fatalf("seed member: %v", err)
	}
	if err := st.AddAlertToIncident(ctx, id, member.ID, member.ReceivedAt); err != nil {
		t.Fatalf("link member: %v", err)
	}
}

func occCount(t *testing.T, st *store.Store, id string) int {
	t.Helper()
	m, err := st.OccurrenceStatsByIncident(context.Background(), []string{id})
	if err != nil {
		t.Fatalf("occ stats: %v", err)
	}
	return m[id].Count
}

func memberCount(t *testing.T, st *store.Store, id string) int {
	t.Helper()
	alerts, err := st.GetIncidentAlerts(context.Background(), id)
	if err != nil {
		t.Fatalf("members: %v", err)
	}
	return len(alerts)
}

// --- tests ---

func TestMaybeAttach_PlainAttach(t *testing.T) {
	st := openStore(t)
	c, td := newCorrelatorFor(t, st)
	ctx := context.Background()
	now := time.Date(2026, 7, 8, 15, 30, 0, 0, time.UTC)
	member := firingAlert("fp-orig", "DiskFull", "warning", now.Add(-5*time.Minute), false)
	seedJudged(t, st, "inc_1", "analyzed", now.Add(-5*time.Minute), now.Add(-10*time.Minute), member)

	incoming := firingAlert("fp-new", "DiskFull", "warning", now, false)
	if _, err := st.UpsertAlertByFingerprint(ctx, incoming); err != nil {
		t.Fatalf("upsert incoming: %v", err)
	}
	handled, err := c.maybeAttachOccurrence(ctx, incoming, gkAPI)
	if err != nil || !handled {
		t.Fatalf("maybeAttachOccurrence = (%v, %v), want (true, nil)", handled, err)
	}
	if occCount(t, st, "inc_1") != 1 {
		t.Errorf("occurrences = %d, want 1", occCount(t, st, "inc_1"))
	}
	if memberCount(t, st, "inc_1") != 2 {
		t.Errorf("members = %d, want 2 (occurrence alert joined)", memberCount(t, st, "inc_1"))
	}
	if td.aud.occurrenceAttachedCount() != 1 {
		t.Errorf("audit rows = %d, want 1", td.aud.occurrenceAttachedCount())
	}
	if td.notif.count() != 1 || td.notif.calls[0].Stats.Count != 1 {
		t.Errorf("notifier calls = %d (%v), want 1 (count=1)", td.notif.count(), td.notif.calls)
	}
	if td.rej.count() != 0 {
		t.Errorf("rejudger called %d times, want 0 (plain attach, no LLM)", td.rej.count())
	}
}

func TestMaybeAttach_NoJudgedCandidate(t *testing.T) {
	st := openStore(t)
	c, _ := newCorrelatorFor(t, st)
	incoming := firingAlert("fp-new", "DiskFull", "warning", time.Now(), false)
	handled, err := c.maybeAttachOccurrence(context.Background(), incoming, gkAPI)
	if err != nil || handled {
		t.Fatalf("maybeAttachOccurrence = (%v, %v), want (false, nil) — new-incident path", handled, err)
	}
}

func TestMaybeAttach_FailSafeOnLookupError(t *testing.T) {
	st := openStore(t)
	c, _ := newCorrelatorFor(t, st)
	now := time.Now().UTC()
	seedJudged(t, st, "inc_1", "analyzed", now, now, firingAlert("fp-orig", "DiskFull", "warning", now, false))
	_ = st.Close() // force every subsequent read to error

	incoming := firingAlert("fp-new", "DiskFull", "warning", now, false)
	handled, err := c.maybeAttachOccurrence(context.Background(), incoming, gkAPI)
	if err != nil || handled {
		t.Fatalf("maybeAttachOccurrence on a store error = (%v, %v), want (false, nil) — fail-safe to a new incident", handled, err)
	}
}

func TestMaybeAttach_DrillParityMismatch(t *testing.T) {
	now := time.Now().UTC()

	t.Run("drill incoming, real incident", func(t *testing.T) {
		st := openStore(t)
		c, _ := newCorrelatorFor(t, st)
		seedJudged(t, st, "inc_real", "analyzed", now, now, firingAlert("fp-real", "DiskFull", "warning", now, false))
		incoming := firingAlert("fp-drill", "DiskFull", "warning", now, true)
		handled, err := c.maybeAttachOccurrence(context.Background(), incoming, gkAPI)
		if err != nil || handled {
			t.Fatalf("drill alert vs real incident = (%v, %v), want (false, nil)", handled, err)
		}
		if occCount(t, st, "inc_real") != 0 {
			t.Errorf("occurrences = %d, want 0 (no cross-drill attach)", occCount(t, st, "inc_real"))
		}
	})

	t.Run("real incoming, drill incident", func(t *testing.T) {
		st := openStore(t)
		c, _ := newCorrelatorFor(t, st)
		seedJudged(t, st, "inc_drill", "analyzed", now, now, firingAlert("fp-drill", "DiskFull", "warning", now, true))
		incoming := firingAlert("fp-real", "DiskFull", "warning", now, false)
		handled, err := c.maybeAttachOccurrence(context.Background(), incoming, gkAPI)
		if err != nil || handled {
			t.Fatalf("real alert vs drill incident = (%v, %v), want (false, nil)", handled, err)
		}
	})
}

func TestMaybeAttach_RepeatTouchNoOccurrence(t *testing.T) {
	st := openStore(t)
	c, td := newCorrelatorFor(t, st)
	ctx := context.Background()
	now := time.Date(2026, 7, 8, 15, 30, 0, 0, time.UTC)
	member := firingAlert("fp-orig", "DiskFull", "warning", now.Add(-20*time.Minute), false)
	seedJudged(t, st, "inc_1", "analyzed", now.Add(-20*time.Minute), now.Add(-25*time.Minute), member)

	// Same fingerprint re-fires (an unchanged repeat).
	repeat := member
	repeat.ReceivedAt = now
	if _, err := st.UpsertAlertByFingerprint(ctx, repeat); err != nil {
		t.Fatalf("upsert repeat: %v", err)
	}
	handled, err := c.maybeAttachOccurrence(ctx, repeat, gkAPI)
	if err != nil || !handled {
		t.Fatalf("repeat = (%v, %v), want (true, nil)", handled, err)
	}
	if occCount(t, st, "inc_1") != 0 {
		t.Errorf("occurrences = %d, want 0 (a repeat mints no episode)", occCount(t, st, "inc_1"))
	}
	if td.notif.count() != 0 {
		t.Errorf("notifier called %d times on a repeat, want 0", td.notif.count())
	}
	// Clock A slid: last_alert_at advanced to the repeat time.
	inc, _ := st.GetIncidentByID(ctx, "inc_1")
	if !inc.LastAlertAt.Equal(now) {
		t.Errorf("last_alert_at = %v, want %v (repeat slides Clock A)", inc.LastAlertAt, now)
	}
}

func TestMaybeAttach_RepeatTouchesOccurrenceLastSeen(t *testing.T) {
	st := openStore(t)
	c, _ := newCorrelatorFor(t, st)
	ctx := context.Background()
	now := time.Date(2026, 7, 8, 15, 30, 0, 0, time.UTC)
	member := firingAlert("fp-orig", "DiskFull", "warning", now.Add(-40*time.Minute), false)
	seedJudged(t, st, "inc_1", "analyzed", now.Add(-40*time.Minute), now.Add(-45*time.Minute), member)

	// A prior distinct-fingerprint episode created an occurrence.
	occAt := now.Add(-35 * time.Minute)
	occID, err := st.InsertOccurrence(ctx, store.Occurrence{IncidentID: "inc_1", OccurredAt: occAt, LastSeen: occAt, Fingerprints: []string{"fp-ep1"}})
	if err != nil {
		t.Fatalf("seed occurrence: %v", err)
	}
	// The original member repeats now (unchanged) -> touch the occurrence last_seen.
	repeat := member
	repeat.ReceivedAt = now
	if _, err := st.UpsertAlertByFingerprint(ctx, repeat); err != nil {
		t.Fatalf("upsert repeat: %v", err)
	}
	if _, err := c.maybeAttachOccurrence(ctx, repeat, gkAPI); err != nil {
		t.Fatalf("repeat: %v", err)
	}
	got, err := st.LatestOccurrence(ctx, "inc_1")
	if err != nil {
		t.Fatalf("latest occ: %v", err)
	}
	if got.ID != occID || !got.LastSeen.Equal(now) {
		t.Errorf("occurrence last_seen = %v (id %d), want %v (id %d)", got.LastSeen, got.ID, now, occID)
	}
	if occCount(t, st, "inc_1") != 1 {
		t.Errorf("occurrences = %d, want 1 (touch adds no row)", occCount(t, st, "inc_1"))
	}
}

// runRejudgeCase seeds a standard analyzed incident (member: warning/DiskFull,
// active 5m ago, judged at lastJudged) and feeds one incoming firing alert,
// returning the store and doubles. It factors the shared shape of the
// escalation-trigger tests.
func runRejudgeCase(t *testing.T, incoming store.Alert, lastJudged time.Time) (*store.Store, *testDoubles) {
	t.Helper()
	st := openStore(t)
	c, td := newCorrelatorFor(t, st)
	ctx := context.Background()
	now := incoming.ReceivedAt
	member := firingAlert("fp-orig", "DiskFull", "warning", now.Add(-5*time.Minute), false)
	seedJudged(t, st, "inc_1", "analyzed", now.Add(-5*time.Minute), lastJudged, member)
	if _, err := st.UpsertAlertByFingerprint(ctx, incoming); err != nil {
		t.Fatalf("upsert incoming: %v", err)
	}
	if _, err := c.maybeAttachOccurrence(ctx, incoming, gkAPI); err != nil {
		t.Fatalf("attach: %v", err)
	}
	return st, td
}

func TestMaybeAttach_SeverityRejudge(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 30, 0, 0, time.UTC)
	_, td := runRejudgeCase(t, firingAlert("fp-new", "DiskFull", "critical", now, false), now.Add(-10*time.Minute))
	if td.rej.count() != 1 || td.rej.triggers[0] != "severity" {
		t.Errorf("rejudger triggers = %v, want [severity]", td.rej.triggers)
	}
}

func TestMaybeAttach_NewAlertnameRejudge(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 30, 0, 0, time.UTC)
	_, td := runRejudgeCase(t, firingAlert("fp-new", "OOMKilled", "warning", now, false), now.Add(-10*time.Minute))
	if td.rej.count() != 1 || td.rej.triggers[0] != "new_alertname" {
		t.Errorf("rejudger triggers = %v, want [new_alertname]", td.rej.triggers)
	}
}

func TestMaybeAttach_CeilingRejudge(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 30, 0, 0, time.UTC)
	// Recent activity (inside Clock A) but judged 5h ago (past the 4h ceiling).
	st, td := runRejudgeCase(t, firingAlert("fp-new", "DiskFull", "warning", now, false), now.Add(-5*time.Hour))
	if td.rej.count() != 1 || td.rej.triggers[0] != "ceiling" {
		t.Errorf("rejudger triggers = %v, want [ceiling]", td.rej.triggers)
	}
	latest, _ := st.LatestOccurrence(context.Background(), "inc_1")
	if latest.TriggerKind != "ceiling" {
		t.Errorf("occurrence trigger_kind = %q, want ceiling", latest.TriggerKind)
	}
	if td.aud.rows[0].trigger != "ceiling" {
		t.Errorf("audit trigger = %q, want ceiling", td.aud.rows[0].trigger)
	}
}

// TestMaybeAttach_AttachToResolvedKeepsStatus covers R1: a firing re-fire whose
// condition had fully recovered attaches to the resolved incident (a new
// episode) without reversing its status.
func TestMaybeAttach_AttachToResolvedKeepsStatus(t *testing.T) {
	st := openStore(t)
	c, _ := newCorrelatorFor(t, st)
	ctx := context.Background()
	now := time.Date(2026, 7, 8, 15, 30, 0, 0, time.UTC)
	member := firingAlert("fp-orig", "DiskFull", "warning", now.Add(-5*time.Minute), false)
	seedJudged(t, st, "inc_1", "resolved", now.Add(-5*time.Minute), now.Add(-10*time.Minute), member)

	incoming := firingAlert("fp-back", "DiskFull", "warning", now, false)
	if _, err := st.UpsertAlertByFingerprint(ctx, incoming); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	handled, err := c.maybeAttachOccurrence(ctx, incoming, gkAPI)
	if err != nil || !handled {
		t.Fatalf("attach to resolved = (%v, %v), want (true, nil)", handled, err)
	}
	if occCount(t, st, "inc_1") != 1 {
		t.Errorf("occurrences = %d, want 1 (a resolved incident still collects occurrences)", occCount(t, st, "inc_1"))
	}
	inc, _ := st.GetIncidentByID(ctx, "inc_1")
	if inc.Status != "resolved" {
		t.Errorf("status = %q, want resolved (an attach never reverses status)", inc.Status)
	}
}

// TestMaybeAttach_CollapseArithmetic covers AE1's decision half: N in-horizon
// re-fires with distinct fingerprints collapse into 1 incident with N
// occurrences, N audit rows, and 0 triage calls.
func TestMaybeAttach_CollapseArithmetic(t *testing.T) {
	st := openStore(t)
	c, td := newCorrelatorFor(t, st)
	ctx := context.Background()
	start := time.Date(2026, 7, 8, 15, 0, 0, 0, time.UTC)
	member := firingAlert("fp-orig", "DiskFull", "warning", start, false)
	seedJudged(t, st, "inc_1", "analyzed", start, start, member)

	const n = 8
	at := start
	for i := 0; i < n; i++ {
		at = at.Add(5 * time.Minute)
		incoming := firingAlert("fp-"+time.Duration(i).String(), "DiskFull", "warning", at, false)
		if _, err := st.UpsertAlertByFingerprint(ctx, incoming); err != nil {
			t.Fatalf("upsert %d: %v", i, err)
		}
		handled, err := c.maybeAttachOccurrence(ctx, incoming, gkAPI)
		if err != nil || !handled {
			t.Fatalf("attach %d = (%v, %v), want (true, nil)", i, handled, err)
		}
	}
	if occCount(t, st, "inc_1") != n {
		t.Errorf("occurrences = %d, want %d", occCount(t, st, "inc_1"), n)
	}
	if td.aud.occurrenceAttachedCount() != n {
		t.Errorf("audit rows = %d, want %d", td.aud.occurrenceAttachedCount(), n)
	}
	if td.notif.count() != n {
		t.Errorf("notifier calls = %d, want %d", td.notif.count(), n)
	}
	if td.rej.count() != 0 {
		t.Errorf("rejudger calls = %d, want 0 (steady cadence, no trigger)", td.rej.count())
	}
	var incidents int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM incidents WHERE group_key = ?`, gkAPI).Scan(&incidents); err != nil {
		t.Fatalf("count incidents: %v", err)
	}
	if incidents != 1 {
		t.Errorf("incidents for key = %d, want 1", incidents)
	}
}

// TestMaybeAttach_CadenceRejudge covers AE3: a slow (nightly) key suddenly
// firing fast trips the cadence trigger.
func TestMaybeAttach_CadenceRejudge(t *testing.T) {
	st := openStore(t)
	c, td := newCorrelatorFor(t, st)
	ctx := context.Background()
	now := time.Date(2026, 7, 8, 2, 20, 0, 0, time.UTC)
	// Four prior nightly incidents (episode times ~24h apart) for the key, the
	// most recent at `base` (20m before the fast re-fire) so it is the candidate
	// and inside Clock A.
	base := now.Add(-20 * time.Minute)
	for i, id := range []string{"inc_n1", "inc_n2", "inc_n3", "inc_n4"} {
		at := base.Add(-time.Duration(3-i) * 24 * time.Hour)
		seedJudged(t, st, id, "analyzed", at, at, firingAlert("fp-"+id, "DiskFull", "warning", at, false))
	}
	incoming := firingAlert("fp-fast", "DiskFull", "warning", now, false)
	if _, err := st.UpsertAlertByFingerprint(ctx, incoming); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if _, err := c.maybeAttachOccurrence(ctx, incoming, gkAPI); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if td.rej.count() != 1 || td.rej.triggers[0] != "cadence" {
		t.Errorf("rejudger triggers = %v, want [cadence]", td.rej.triggers)
	}
}

func TestFlushExpired_PrunesOnSchedule(t *testing.T) {
	st := openStore(t)
	c, _ := newCorrelatorFor(t, st)
	ctx := context.Background()
	c.cfg.Lookback = 90 * 24 * time.Hour
	c.pruneEvery = 1 // prune every flush for the test

	nowUTC := time.Now().UTC()
	seedJudged(t, st, "inc_1", "analyzed", nowUTC, nowUTC,
		firingAlert("fp-orig", "DiskFull", "warning", nowUTC, false))
	// One occurrence well past the lookback, one recent.
	old := nowUTC.Add(-120 * 24 * time.Hour)
	if _, err := st.InsertOccurrence(ctx, store.Occurrence{IncidentID: "inc_1", OccurredAt: old, LastSeen: old, Fingerprints: []string{"fp-old"}}); err != nil {
		t.Fatalf("seed old occ: %v", err)
	}
	recent := nowUTC.Add(-1 * time.Hour)
	if _, err := st.InsertOccurrence(ctx, store.Occurrence{IncidentID: "inc_1", OccurredAt: recent, LastSeen: recent, Fingerprints: []string{"fp-recent"}}); err != nil {
		t.Fatalf("seed recent occ: %v", err)
	}

	if err := c.flushExpired(ctx); err != nil {
		t.Fatalf("flushExpired: %v", err)
	}
	if occCount(t, st, "inc_1") != 1 {
		t.Errorf("occurrences after prune = %d, want 1 (old pruned, recent kept)", occCount(t, st, "inc_1"))
	}
}

func TestMaybeAttach_EventCarriesSeverityDelta(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 30, 0, 0, time.UTC)
	_, td := runRejudgeCase(t, firingAlert("fp-new", "DiskFull", "critical", now, false), now.Add(-10*time.Minute))
	if td.notif.count() != 1 {
		t.Fatalf("notifier calls = %d, want 1", td.notif.count())
	}
	ev := td.notif.calls[0]
	if ev.Trigger != "severity" || ev.NewSeverity != "critical" || ev.PriorSeverity != "warning" {
		t.Errorf("severity event = {trigger:%q new:%q prior:%q}, want {severity critical warning}",
			ev.Trigger, ev.NewSeverity, ev.PriorSeverity)
	}
	if ev.Stats.Count != 1 {
		t.Errorf("stats.Count = %d, want 1", ev.Stats.Count)
	}
}

func TestMaybeAttach_EventCarriesNewAlertname(t *testing.T) {
	now := time.Date(2026, 7, 8, 15, 30, 0, 0, time.UTC)
	_, td := runRejudgeCase(t, firingAlert("fp-new", "OOMKilled", "warning", now, false), now.Add(-10*time.Minute))
	ev := td.notif.calls[0]
	if ev.Trigger != "new_alertname" || ev.NewAlertname != "OOMKilled" {
		t.Errorf("new_alertname event = {trigger:%q name:%q}, want {new_alertname OOMKilled}", ev.Trigger, ev.NewAlertname)
	}
}

func TestMaybeAttach_EventCarriesCadenceDelta(t *testing.T) {
	st := openStore(t)
	c, td := newCorrelatorFor(t, st)
	ctx := context.Background()
	now := time.Date(2026, 7, 8, 2, 20, 0, 0, time.UTC)
	base := now.Add(-20 * time.Minute)
	for i, id := range []string{"inc_n1", "inc_n2", "inc_n3", "inc_n4"} {
		at := base.Add(-time.Duration(3-i) * 24 * time.Hour)
		seedJudged(t, st, id, "analyzed", at, at, firingAlert("fp-"+id, "DiskFull", "warning", at, false))
	}
	incoming := firingAlert("fp-fast", "DiskFull", "warning", now, false)
	if _, err := st.UpsertAlertByFingerprint(ctx, incoming); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if _, err := c.maybeAttachOccurrence(ctx, incoming, gkAPI); err != nil {
		t.Fatalf("attach: %v", err)
	}
	ev := td.notif.calls[0]
	if ev.Trigger != "cadence" {
		t.Fatalf("trigger = %q, want cadence", ev.Trigger)
	}
	if ev.NewInterval <= 0 || ev.PriorMedian <= 0 || ev.NewInterval*8 >= ev.PriorMedian {
		t.Errorf("cadence delta = {new:%s median:%s}, want new*8 < median with both > 0", ev.NewInterval, ev.PriorMedian)
	}
}
