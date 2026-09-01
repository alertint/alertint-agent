// SPDX-License-Identifier: FSL-1.1-ALv2

package correlator

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

// deliveryInputFor builds one DeliveryInput ready for AcceptDeliveries,
// carrying groupKey as the Receiver grouping identity and status ("firing"
// or "resolved") on its Alert.
func deliveryInputFor(id, fingerprint, groupKey, status string, now time.Time) store.DeliveryInput {
	return store.DeliveryInput{
		ID: id,
		Alert: store.Alert{
			ID:          "alert-" + fingerprint,
			Fingerprint: fingerprint,
			Status:      status,
			Labels:      map[string]string{"alertname": "test", "fp": fingerprint},
			Annotations: map[string]string{"summary": "test alert"},
			StartsAt:    now,
			ReceivedAt:  now,
		},
		Source:                   "alertmanager",
		SourceEpisodeKey:         "alertmanager:" + fingerprint + ":" + now.UTC().Format(time.RFC3339Nano),
		StartedAtBasis:           situationmodel.SourceTimeBasisSourcePayload,
		ResolvedAtBasis:          situationmodel.SourceTimeBasisMissing,
		ReceiverGroupingIdentity: groupKey,
		PayloadDigest:            "sha256:" + id,
		SourceProvenance:         store.SourceProvenance{AcquisitionMode: store.SourceAcquisitionWebhook},
	}
}

// claimOneDelivery accepts in and claims it under a fixed test owner,
// returning its claimed store.AlertDispatch.
func claimOneDelivery(t *testing.T, st *store.Store, in store.DeliveryInput, now time.Time) store.AlertDispatch {
	t.Helper()
	ctx := context.Background()
	if _, err := st.AcceptDeliveries(ctx, []store.DeliveryInput{in}); err != nil {
		t.Fatalf("accept delivery %s: %v", in.ID, err)
	}
	claims, err := st.ClaimAlertDispatches(ctx, "worker-a", now, time.Minute, 1)
	if err != nil {
		t.Fatalf("claim delivery %s: %v", in.ID, err)
	}
	for _, c := range claims {
		if c.Delivery.ID == in.ID {
			return c
		}
	}
	t.Fatalf("delivery %s not among claimed dispatches", in.ID)
	return store.AlertDispatch{}
}

// dispatchStatus reads back "d1"'s dispatch status — every test in this
// file claims its delivery under that fixed id.
func dispatchStatus(t *testing.T, st *store.Store) string {
	t.Helper()
	var status string
	if err := st.DB().QueryRowContext(context.Background(), `SELECT status FROM alert_delivery_dispatches WHERE delivery_id = 'd1'`).Scan(&status); err != nil {
		t.Fatalf("read dispatch status: %v", err)
	}
	return status
}

func situationInputKinds(t *testing.T, st *store.Store, incidentID string) []string {
	t.Helper()
	rows, err := st.DB().QueryContext(context.Background(), `SELECT kind FROM situation_input_outbox WHERE incident_id = ? ORDER BY rowid`, incidentID)
	if err != nil {
		t.Fatalf("read situation inputs: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			t.Fatal(err)
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate situation inputs: %v", err)
	}
	return out
}

// insertBackoffIncident creates a "ready"/backoff-phase Incident for
// groupKey — the target of retry-aware attachment (issue 60) — by walking
// the same triage-lease transitions production code uses: seed the initial
// pending row, begin the attempt (ready -> processing), then back off
// (processing -> ready, phase -> backoff).
func insertBackoffIncident(t *testing.T, st *store.Store, id, groupKey string, at time.Time, member store.Alert) {
	t.Helper()
	ctx := context.Background()
	if err := st.InsertIncident(ctx, store.Incident{ID: id, GroupKey: groupKey, FirstAlertAt: at, LastAlertAt: at, ReadyAt: at}); err != nil {
		t.Fatalf("insert backoff incident: %v", err)
	}
	if _, err := st.UpsertAlertByFingerprint(ctx, member); err != nil {
		t.Fatalf("seed backoff member: %v", err)
	}
	if err := st.AddAlertToIncident(ctx, id, member.ID, member.ReceivedAt); err != nil {
		t.Fatalf("link backoff member: %v", err)
	}
	if err := st.MarkIncidentReady(ctx, id); err != nil {
		t.Fatalf("mark backoff incident ready: %v", err)
	}
	if err := st.SeedIncidentTriage(ctx, id, at); err != nil {
		t.Fatalf("seed backoff triage: %v", err)
	}
	if _, err := st.BeginIncidentTriage(ctx, id, at); err != nil {
		t.Fatalf("begin backoff triage: %v", err)
	}
	if err := st.BackoffIncidentTriage(ctx, id, at.Add(time.Hour), "transient", "simulated failure"); err != nil {
		t.Fatalf("back off triage: %v", err)
	}
}

func TestApplyDelivery_OpensFreshIncidentAndAppliesDispatch(t *testing.T) {
	st := openStore(t)
	c := New(Config{}, st, NopIncidentSink{}, nil)
	now := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)

	claim := claimOneDelivery(t, st, deliveryInputFor("d1", "fp1", "group:fp1", "firing", now), now)
	if err := c.ApplyDelivery(context.Background(), claim); err != nil {
		t.Fatal(err)
	}

	if dispatchStatus(t, st) != "applied" {
		t.Fatalf("dispatch status = %q, want applied", dispatchStatus(t, st))
	}
	inc, err := st.GetCollectingIncident(context.Background(), "group:fp1")
	if err != nil {
		t.Fatalf("get collecting incident: %v", err)
	}
	kinds := situationInputKinds(t, st, inc.ID)
	if len(kinds) != 1 || kinds[0] != "incident_created" {
		t.Fatalf("situation input kinds = %v, want [incident_created]", kinds)
	}
}

func TestApplyDelivery_FixedWindowSetsReadyAt(t *testing.T) {
	st := openStore(t)
	c := New(Config{WindowSeconds: 90}, st, NopIncidentSink{}, nil)
	now := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)

	claim := claimOneDelivery(t, st, deliveryInputFor("d1", "fp1", "group:fp1", "firing", now), now)
	if err := c.ApplyDelivery(context.Background(), claim); err != nil {
		t.Fatal(err)
	}
	inc, err := st.GetCollectingIncident(context.Background(), "group:fp1")
	if err != nil {
		t.Fatal(err)
	}
	want := now.Add(90 * time.Second)
	if !inc.ReadyAt.Equal(want) {
		t.Fatalf("ready_at = %v, want %v", inc.ReadyAt, want)
	}
}

func TestApplyDelivery_GroupLabelOverrideFallsBackWhenLabelsMiss(t *testing.T) {
	st := openStore(t)
	c := New(Config{GroupLabels: []string{"service"}}, st, NopIncidentSink{}, nil)
	now := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)

	// The configured override label ("service") is absent from this
	// delivery's labels — groupKeySelection must fall back safely (never an
	// empty group key) rather than crash or silently drop the delivery.
	in := deliveryInputFor("d1", "fp1", "receiver-identity-ignored", "firing", now)
	claim := claimOneDelivery(t, st, in, now)
	if err := c.ApplyDelivery(context.Background(), claim); err != nil {
		t.Fatal(err)
	}
	if dispatchStatus(t, st) != "applied" {
		t.Fatal("delivery with a group-label override miss was not applied via the safety fallback")
	}
}

func TestApplyDelivery_JoinsExistingCollectingIncident(t *testing.T) {
	st := openStore(t)
	c := New(Config{WindowSeconds: 300}, st, NopIncidentSink{}, nil)
	now := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)

	first := claimOneDelivery(t, st, deliveryInputFor("d1", "fp1", "group:x", "firing", now), now)
	if err := c.ApplyDelivery(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second := claimOneDelivery(t, st, deliveryInputFor("d2", "fp2", "group:x", "firing", now.Add(time.Second)), now.Add(time.Second))
	if err := c.ApplyDelivery(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	inc, err := st.GetCollectingIncident(context.Background(), "group:x")
	if err != nil {
		t.Fatal(err)
	}
	if inc.AlertCount != 2 {
		t.Fatalf("alert_count = %d, want 2", inc.AlertCount)
	}
	kinds := situationInputKinds(t, st, inc.ID)
	if len(kinds) != 2 || kinds[0] != "incident_created" || kinds[1] != "membership_changed" {
		t.Fatalf("situation input kinds = %v, want [incident_created membership_changed]", kinds)
	}
}

func TestApplyDelivery_RetryAttachBeforeRecurrence(t *testing.T) {
	st := openStore(t)
	c := New(Config{}, st, NopIncidentSink{}, nil)
	aud := &fakeAuditor{}
	c.SetAuditor(aud)
	now := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)
	member := firingAlert("fp-orig", "DiskFull", "warning", now.Add(-time.Hour), false)
	insertBackoffIncident(t, st, "inc-backoff", gkAPI, now.Add(-time.Hour), member)

	claim := claimOneDelivery(t, st, deliveryInputFor("d1", "fp-new", gkAPI, "firing", now), now)
	if err := c.ApplyDelivery(context.Background(), claim); err != nil {
		t.Fatal(err)
	}

	// The delivery must have attached to the existing backoff Incident — not
	// opened a new collecting window.
	if _, err := st.GetCollectingIncident(context.Background(), gkAPI); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a new collecting incident was opened during retry backoff: err=%v", err)
	}
	inc, err := st.GetIncidentByID(context.Background(), "inc-backoff")
	if err != nil {
		t.Fatal(err)
	}
	if inc.AlertCount != 2 {
		t.Fatalf("backoff incident alert_count = %d, want 2", inc.AlertCount)
	}
	kinds := situationInputKinds(t, st, "inc-backoff")
	if len(kinds) != 1 || kinds[0] != "membership_changed" {
		t.Fatalf("situation input kinds = %v, want [membership_changed]", kinds)
	}
	// The durable path re-emits the triage_member_attached audit event
	// retry_attach.go's legacy path used to write.
	rows := aud.rowsOfKind("incident.triage_member_attached")
	if len(rows) != 1 {
		t.Fatalf("triage_member_attached audit rows = %d, want 1", len(rows))
	}
	if rows[0].payload["incident_id"] != "inc-backoff" || rows[0].payload["group_key"] != gkAPI || rows[0].payload["alert_id"] != claim.Delivery.Alert.ID {
		t.Fatalf("triage_member_attached audit payload = %+v, want incident_id=inc-backoff group_key=%s alert_id=%s",
			rows[0].payload, gkAPI, claim.Delivery.Alert.ID)
	}
	if mc, ok := rows[0].payload["member_count"].(int); !ok || mc != 2 {
		t.Fatalf("triage_member_attached audit member_count = %v, want 2", rows[0].payload["member_count"])
	}
}

func TestApplyDelivery_RetryAttachDrillParityMismatchFallsThrough(t *testing.T) {
	st := openStore(t)
	c := New(Config{}, st, NopIncidentSink{}, nil)
	now := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)
	member := firingAlert("fp-orig", "DiskFull", "warning", now.Add(-time.Hour), false)
	insertBackoffIncident(t, st, "inc-backoff", gkAPI, now.Add(-time.Hour), member)

	drillIn := deliveryInputFor("d1", "fp-drill", gkAPI, "firing", now)
	drillIn.Alert.Labels[store.DrillMarkerLabel] = store.DrillMarkerValue
	claim := claimOneDelivery(t, st, drillIn, now)
	if err := c.ApplyDelivery(context.Background(), claim); err != nil {
		t.Fatal(err)
	}

	// A Drill delivery must never attach to a real backoff Incident — it
	// opens (or joins) its own fresh window instead.
	inc, err := st.GetIncidentByID(context.Background(), "inc-backoff")
	if err != nil {
		t.Fatal(err)
	}
	if inc.AlertCount != 1 {
		t.Fatalf("backoff incident alert_count = %d, want 1 (untouched by the drill delivery)", inc.AlertCount)
	}
	if _, err := st.GetCollectingIncident(context.Background(), gkAPI); err != nil {
		t.Fatalf("drill delivery did not open its own collecting incident: %v", err)
	}
}

func TestApplyDelivery_TerminalIncidentExcludedFromRetryAttach(t *testing.T) {
	st := openStore(t)
	c := New(Config{}, st, NopIncidentSink{}, nil)
	now := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)
	member := firingAlert("fp-orig", "DiskFull", "warning", now.Add(-time.Hour), false)
	insertBackoffIncident(t, st, "inc-backoff", gkAPI, now.Add(-time.Hour), member)
	if err := st.MarkIncidentFailed(context.Background(), "inc-backoff"); err != nil {
		t.Fatalf("mark backoff incident failed: %v", err)
	}

	claim := claimOneDelivery(t, st, deliveryInputFor("d1", "fp-new", gkAPI, "firing", now), now)
	if err := c.ApplyDelivery(context.Background(), claim); err != nil {
		t.Fatal(err)
	}

	inc, err := st.GetIncidentByID(context.Background(), "inc-backoff")
	if err != nil {
		t.Fatal(err)
	}
	if inc.AlertCount != 1 {
		t.Fatalf("failed incident alert_count = %d, want 1 (excluded from retry attach)", inc.AlertCount)
	}
	if _, err := st.GetCollectingIncident(context.Background(), gkAPI); err != nil {
		t.Fatalf("delivery did not open a fresh incident once the candidate went terminal: %v", err)
	}
}

func TestApplyDelivery_RecurrenceCollapseAttachesOccurrenceAndNotifies(t *testing.T) {
	st := openStore(t)
	c := New(Config{}, st, NopIncidentSink{}, nil)
	notifier := &fakeOccNotifier{}
	rejudger := &fakeRejudger{}
	aud := &fakeAuditor{}
	c.SetOccurrenceNotifier(notifier)
	c.SetRejudger(rejudger)
	c.SetAuditor(aud)
	now := time.Date(2026, 7, 8, 15, 30, 0, 0, time.UTC)
	member := firingAlert("fp-orig", "DiskFull", "warning", now.Add(-5*time.Minute), false)
	seedJudged(t, st, "inc_1", "analyzed", now.Add(-5*time.Minute), now.Add(-10*time.Minute), member)

	claim := claimOneDelivery(t, st, deliveryInputFor("d1", "fp-new", gkAPI, "firing", now), now)
	if err := c.ApplyDelivery(context.Background(), claim); err != nil {
		t.Fatal(err)
	}

	if memberCount(t, st, "inc_1") != 2 {
		t.Fatalf("members = %d, want 2 (occurrence alert joined)", memberCount(t, st, "inc_1"))
	}
	if occCount(t, st, "inc_1") != 1 {
		t.Fatalf("occurrences = %d, want 1", occCount(t, st, "inc_1"))
	}
	kinds := situationInputKinds(t, st, "inc_1")
	if len(kinds) != 1 || kinds[0] != "membership_changed" {
		t.Fatalf("situation input kinds = %v, want [membership_changed]", kinds)
	}
	if notifier.count() != 1 {
		t.Fatalf("occurrence notifier calls = %d, want 1", notifier.count())
	}
	// Re-judgment is deliberately not invoked for durable deliveries: an LLM
	// call has no place inside or synchronously after a dispatch commit.
	if rejudger.count() != 0 {
		t.Fatalf("rejudger calls = %d, want 0 (delivery path never re-judges inline)", rejudger.count())
	}
	// The durable path re-emits the occurrence-attach audit event
	// attach.go's legacy path used to write — see docs/concepts/
	// incident-memory.md's "Measuring memory" analyses_avoided query, which
	// counts exactly this event kind with trigger='none'.
	rows := aud.rowsOfKind("incident.occurrence_attached")
	if len(rows) != 1 {
		t.Fatalf("occurrence_attached audit rows = %d, want 1", len(rows))
	}
	if rows[0].payload["incident_id"] != "inc_1" || rows[0].payload["group_key"] != gkAPI || rows[0].trigger != "new_alertname" {
		t.Fatalf("occurrence_attached audit payload = %+v, want incident_id=inc_1 group_key=%s trigger=new_alertname", rows[0].payload, gkAPI)
	}
}

// TestApplyDelivery_RecurrenceCollapseAuditsPlainAttachAsTriggerNone proves
// the durable path's re-emitted occurrence_attached audit event carries
// trigger="none" for a plain, non-escalating attach — exactly what docs/
// concepts/incident-memory.md's "Measuring memory" analyses_avoided query
// (kind='incident.occurrence_attached' AND payload trigger='none') counts.
func TestApplyDelivery_RecurrenceCollapseAuditsPlainAttachAsTriggerNone(t *testing.T) {
	st := openStore(t)
	c := New(Config{}, st, NopIncidentSink{}, nil)
	aud := &fakeAuditor{}
	c.SetAuditor(aud)
	now := time.Date(2026, 7, 8, 15, 30, 0, 0, time.UTC)
	member := firingAlert("fp-orig", "DiskFull", "warning", now.Add(-5*time.Minute), false)
	seedJudged(t, st, "inc_1", "analyzed", now.Add(-5*time.Minute), now.Add(-10*time.Minute), member)

	// Same alertname, same severity as the baseline member — a new episode
	// inside the horizon with no escalation trigger.
	in := deliveryInputFor("d1", "fp-new", gkAPI, "firing", now)
	in.Alert.Labels["alertname"] = "DiskFull"
	in.Alert.Labels["severity"] = "warning"
	claim := claimOneDelivery(t, st, in, now)
	if err := c.ApplyDelivery(context.Background(), claim); err != nil {
		t.Fatal(err)
	}

	rows := aud.rowsOfKind("incident.occurrence_attached")
	if len(rows) != 1 || rows[0].trigger != "none" {
		t.Fatalf("occurrence_attached audit rows = %+v, want exactly one row with trigger=none", rows)
	}
}

func TestApplyDelivery_RecurrenceEscalationCarriesTriggerFacts(t *testing.T) {
	st := openStore(t)
	c := New(Config{}, st, NopIncidentSink{}, nil)
	notifier := &fakeOccNotifier{}
	c.SetOccurrenceNotifier(notifier)
	now := time.Date(2026, 7, 8, 15, 30, 0, 0, time.UTC)
	member := firingAlert("fp-orig", "DiskFull", "warning", now.Add(-5*time.Minute), false)
	seedJudged(t, st, "inc_1", "analyzed", now.Add(-5*time.Minute), now.Add(-10*time.Minute), member)

	in := deliveryInputFor("d1", "fp-new", gkAPI, "firing", now)
	in.Alert.Labels["alertname"] = "DiskFull"
	in.Alert.Labels["severity"] = "critical" // escalates past the "warning" baseline
	claim := claimOneDelivery(t, st, in, now)
	if err := c.ApplyDelivery(context.Background(), claim); err != nil {
		t.Fatal(err)
	}

	if notifier.count() != 1 {
		t.Fatalf("occurrence notifier calls = %d, want 1", notifier.count())
	}
	ev := notifier.calls[0]
	if ev.Trigger != "severity" || ev.PriorSeverity != "warning" || ev.NewSeverity != "critical" {
		t.Fatalf("recurrence event = %+v, want trigger=severity prior=warning new=critical", ev)
	}

	// The durable trigger linkage a future Situation controller reconstructs
	// "this needed re-judgment" from (instead of the delivery path calling
	// Rejudge inline): the occurrence's trigger_kind and the delivery's
	// stamped occurrence_id, queried directly off the ledger tables.
	var triggerKind string
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT trigger_kind FROM incident_occurrences WHERE incident_id = ?`, "inc_1").Scan(&triggerKind); err != nil {
		t.Fatalf("read occurrence trigger_kind: %v", err)
	}
	if triggerKind != "severity" {
		t.Fatalf("incident_occurrences.trigger_kind = %q, want severity", triggerKind)
	}
	var occurrenceID sql.NullInt64
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT occurrence_id FROM incident_alert_deliveries WHERE delivery_id = ?`, "d1").Scan(&occurrenceID); err != nil {
		t.Fatalf("read delivery occurrence_id: %v", err)
	}
	if !occurrenceID.Valid {
		t.Fatal("incident_alert_deliveries.occurrence_id was not stamped for the collapsing delivery")
	}
}

func TestApplyDelivery_RecurrenceRepeatTouchDoesNotCreateOccurrence(t *testing.T) {
	st := openStore(t)
	c := New(Config{}, st, NopIncidentSink{}, nil)
	notifier := &fakeOccNotifier{}
	c.SetOccurrenceNotifier(notifier)
	now := time.Date(2026, 7, 8, 15, 30, 0, 0, time.UTC)
	member := firingAlert("fp-same", "DiskFull", "warning", now.Add(-5*time.Minute), false)
	seedJudged(t, st, "inc_1", "analyzed", now.Add(-5*time.Minute), now.Add(-10*time.Minute), member)

	// Same fingerprint, still firing, still a member — an unchanged repeat,
	// not a new episode: no new occurrence, no notification.
	claim := claimOneDelivery(t, st, deliveryInputFor("d1", "fp-same", gkAPI, "firing", now), now)
	if err := c.ApplyDelivery(context.Background(), claim); err != nil {
		t.Fatal(err)
	}

	if occCount(t, st, "inc_1") != 0 {
		t.Fatalf("occurrences = %d, want 0 (unchanged repeat)", occCount(t, st, "inc_1"))
	}
	if notifier.count() != 0 {
		t.Fatalf("occurrence notifier calls = %d, want 0 (unchanged repeat)", notifier.count())
	}
	if dispatchStatus(t, st) != "applied" {
		t.Fatal("repeat delivery's dispatch was not applied")
	}
}

func TestApplyDelivery_RecurrenceDrillParityMismatchFallsThrough(t *testing.T) {
	st := openStore(t)
	c := New(Config{}, st, NopIncidentSink{}, nil)
	now := time.Date(2026, 7, 8, 15, 30, 0, 0, time.UTC)
	member := firingAlert("fp-orig", "DiskFull", "warning", now.Add(-5*time.Minute), false)
	seedJudged(t, st, "inc_1", "analyzed", now.Add(-5*time.Minute), now.Add(-10*time.Minute), member)

	drillIn := deliveryInputFor("d1", "fp-drill", gkAPI, "firing", now)
	drillIn.Alert.Labels[store.DrillMarkerLabel] = store.DrillMarkerValue
	claim := claimOneDelivery(t, st, drillIn, now)
	if err := c.ApplyDelivery(context.Background(), claim); err != nil {
		t.Fatal(err)
	}

	if occCount(t, st, "inc_1") != 0 {
		t.Fatalf("occurrences = %d, want 0 (no cross-drill attach)", occCount(t, st, "inc_1"))
	}
	if _, err := st.GetCollectingIncident(context.Background(), gkAPI); err != nil {
		t.Fatalf("drill delivery did not open its own collecting incident: %v", err)
	}
}

func TestApplyDelivery_ResolvedDeliveryResolvesIncidentAndNotifies(t *testing.T) {
	st := openStore(t)
	c := New(Config{}, st, NopIncidentSink{}, nil)
	resolved := &captureResolutionNotifier{}
	c.SetResolutionNotifier(resolved)
	now := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)
	member := firingAlert("fp-only", "DiskFull", "warning", now.Add(-time.Hour), false)
	seedJudged(t, st, "inc_1", "ready", now.Add(-time.Hour), now.Add(-time.Hour), member)
	// A judged (analyzed) Incident's real finding must survive into the
	// resolution notification — not fall back to a generic placeholder.
	if err := st.SaveIncidentOutput(context.Background(), "inc_1", "{}", "Disk Full Alert", "disk usage exceeded threshold", 0.87, ""); err != nil {
		t.Fatalf("save incident output: %v", err)
	}

	claim := claimOneDelivery(t, st, deliveryInputFor("d1", "fp-only", gkAPI, "resolved", now), now)
	if err := c.ApplyDelivery(context.Background(), claim); err != nil {
		t.Fatal(err)
	}

	inc, err := st.GetIncidentByID(context.Background(), "inc_1")
	if err != nil {
		t.Fatal(err)
	}
	if inc.Status != "resolved" {
		t.Fatalf("incident status = %q, want resolved", inc.Status)
	}
	kinds := situationInputKinds(t, st, "inc_1")
	if len(kinds) != 1 || kinds[0] != "incident_resolved" {
		t.Fatalf("situation input kinds = %v, want [incident_resolved]", kinds)
	}
	if resolved.count() != 1 {
		t.Fatalf("resolution notifier calls = %d, want 1", resolved.count())
	}
	notified := resolved.calls[0]
	if notified.Summary != "Disk Full Alert" || notified.RootCause != "disk usage exceeded threshold" || notified.Confidence != 0.87 {
		t.Fatalf("resolution notifier incident = %+v, want the analyzed Incident's real Summary/RootCause/Confidence preserved", notified)
	}
}

func TestApplyDelivery_ResolvedDeliveryWithNoPriorIncidentOpensFresh(t *testing.T) {
	st := openStore(t)
	c := New(Config{}, st, NopIncidentSink{}, nil)
	now := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)

	claim := claimOneDelivery(t, st, deliveryInputFor("d1", "fp-orphan", "group:orphan", "resolved", now), now)
	if err := c.ApplyDelivery(context.Background(), claim); err != nil {
		t.Fatal(err)
	}
	inc, err := st.GetCollectingIncident(context.Background(), "group:orphan")
	if err != nil {
		t.Fatalf("resolved delivery with no prior incident did not open a fresh one: %v", err)
	}
	if inc.AlertCount != 1 {
		t.Fatalf("alert_count = %d, want 1", inc.AlertCount)
	}
}

func TestApplyDelivery_InvalidDeliveryRejected(t *testing.T) {
	st := openStore(t)
	c := New(Config{}, st, NopIncidentSink{}, nil)
	claim := store.AlertDispatch{} // missing every required field
	if err := c.ApplyDelivery(context.Background(), claim); !errors.Is(err, ErrInvalidDelivery) {
		t.Fatalf("err = %v, want ErrInvalidDelivery", err)
	}
}

func TestFlushExpiredUsesMarkIncidentReadyWithSituationInput(t *testing.T) {
	st := openStore(t)
	c := New(Config{WindowSeconds: 1}, st, NopIncidentSink{}, nil)
	now := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }

	claim := claimOneDelivery(t, st, deliveryInputFor("d1", "fp1", "group:flush", "firing", now.Add(-time.Hour)), now.Add(-time.Hour))
	if err := c.ApplyDelivery(context.Background(), claim); err != nil {
		t.Fatal(err)
	}
	inc, err := st.GetCollectingIncident(context.Background(), "group:flush")
	if err != nil {
		t.Fatal(err)
	}

	if err := c.flushExpired(context.Background()); err != nil {
		t.Fatal(err)
	}

	got, err := st.GetIncidentByID(context.Background(), inc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "ready" {
		t.Fatalf("incident status = %q, want ready", got.Status)
	}
	var count int
	if err := st.DB().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM situation_input_outbox WHERE idempotency_key=? AND kind='incident_ready'`, "incident-ready:"+inc.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("incident_ready situation inputs = %d, want 1", count)
	}
}

// captureResolutionNotifier records every OnIncidentResolved call.
type captureResolutionNotifier struct {
	calls []store.Incident
}

func (r *captureResolutionNotifier) OnIncidentResolved(_ context.Context, inc store.Incident) error {
	r.calls = append(r.calls, inc)
	return nil
}
func (r *captureResolutionNotifier) count() int { return len(r.calls) }

var _ ResolutionNotifier = (*captureResolutionNotifier)(nil)

// seedTerminalSituationOwner gives incidentID a terminal ("closed_unknown")
// owning Situation — what a future controller's termination leaves behind.
// Correlation must then refuse to collapse later same-group work into that
// Incident: a later firing never crosses a terminal Situation boundary.
func seedTerminalSituationOwner(t *testing.T, st *store.Store, situationID, incidentID, groupKey string, at time.Time) {
	t.Helper()
	ctx := context.Background()
	ts := at.UTC().Format(time.RFC3339Nano)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO situations (id, group_key, lifecycle, attention, input_version, opened_at,
			effective_started_at, effective_started_at_basis, first_received_at,
			last_lifecycle_observed_at, terminal_at, terminal_reason,
			next_assessment_at, due_reasons_json, created_at, updated_at)
		VALUES (?, ?, 'closed_unknown', 'observe', 1, ?, ?, 'receipt_fallback', ?, ?, ?, 'resolution_missing', ?, '[]', ?, ?)`,
		situationID, groupKey, ts, ts, ts, ts, ts, ts, ts, ts); err != nil {
		t.Fatalf("seed terminal situation: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO situation_incidents (situation_id, incident_id, attached_at) VALUES (?, ?, ?)`,
		situationID, incidentID, ts); err != nil {
		t.Fatalf("attach incident to terminal situation: %v", err)
	}
}

// TestApplyDelivery_TerminalSituationOwnerOpensFreshIncident: the spec's
// terminal-boundary rule end to end on the durable path. A judged
// same-group Incident inside the collapse horizon would normally absorb
// this delivery as an occurrence; because its owning Situation is terminal,
// the store rejects the collapse inside the mutation and the correlator
// falls through to a fresh Incident instead. The fresh Incident's
// "incident_created" input is what later opens a linked new Situation —
// covered by the store's
// TestApplySituationInputCreatesNewSituationLinkedToTerminalPredecessor.
func TestApplyDelivery_TerminalSituationOwnerOpensFreshIncident(t *testing.T) {
	st := openStore(t)
	c := New(Config{}, st, NopIncidentSink{}, nil)
	aud := &fakeAuditor{}
	c.SetAuditor(aud)
	now := time.Date(2026, 7, 8, 15, 30, 0, 0, time.UTC)
	member := firingAlert("fp-orig", "DiskFull", "warning", now.Add(-5*time.Minute), false)
	seedJudged(t, st, "inc_1", "analyzed", now.Add(-5*time.Minute), now.Add(-10*time.Minute), member)
	seedTerminalSituationOwner(t, st, "sit_1", "inc_1", gkAPI, now.Add(-4*time.Minute))

	claim := claimOneDelivery(t, st, deliveryInputFor("d1", "fp-new", gkAPI, "firing", now), now)
	if err := c.ApplyDelivery(context.Background(), claim); err != nil {
		t.Fatal(err)
	}

	if got := occCount(t, st, "inc_1"); got != 0 {
		t.Fatalf("occurrences on inc_1 = %d, want 0 (terminal episode must not absorb new work)", got)
	}
	if got := memberCount(t, st, "inc_1"); got != 1 {
		t.Fatalf("members on inc_1 = %d, want 1 (unchanged)", got)
	}
	var owner string
	if err := st.DB().QueryRowContext(context.Background(), `SELECT incident_id FROM incident_alert_deliveries WHERE delivery_id = 'd1'`).Scan(&owner); err != nil {
		t.Fatalf("read delivery ownership: %v", err)
	}
	if owner == "inc_1" {
		t.Fatal("delivery attached to inc_1 across a terminal Situation boundary; want a fresh Incident")
	}
	kinds := situationInputKinds(t, st, owner)
	if len(kinds) != 1 || kinds[0] != "incident_created" {
		t.Fatalf("situation input kinds for fresh incident = %v, want [incident_created]", kinds)
	}
	if rows := aud.rowsOfKind("incident.occurrence_attached"); len(rows) != 0 {
		t.Fatalf("occurrence_attached audit rows = %d, want 0", len(rows))
	}
	if got := dispatchStatus(t, st); got != "applied" {
		t.Fatalf("dispatch status = %q, want applied", got)
	}
}
