// SPDX-License-Identifier: FSL-1.1-ALv2

// package situation_test (external test package), not package situation:
// this file drives *store.Store end to end, and internal/store now imports
// internal/situation (Task 3, situation_controller.go) for the controller's
// transport-neutral types — an internal (same-package) test file here that
// also imported internal/store would create the exact "import cycle not
// allowed in test" Go forbids for a package's own test files. See the Task
// 3 report for the full rationale. fixedClock is a local duplicate of
// input_worker_test.go's package-private helper of the same name, needed
// because this file can no longer see that unexported symbol from outside
// package situation.
package situation_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/correlator"
	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

// fixedClock is a deterministic clock for tests that must not depend on
// wall-clock timing — a local duplicate of input_worker_test.go's
// package-private helper of the same name (see the package doc comment
// above for why this file cannot import that one directly).
func fixedClock() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}

// ----------------------------------------------------------------------
// Fixtures
// ----------------------------------------------------------------------

// callCounter is a fake correlator.IncidentSink + correlator.ResolutionNotifier
// + correlator.OccurrenceNotifier that counts every call — reconstruction
// wires it in as a canary: if anything on the reconstruction path ever
// reached an outward notification surface, Calls would go non-zero.
type callCounter struct {
	Calls int
}

func (c *callCounter) OnIncidentReady(context.Context, store.Incident) error {
	c.Calls++
	return nil
}

func (c *callCounter) OnIncidentResolved(context.Context, store.Incident) error {
	c.Calls++
	return nil
}

func (c *callCounter) OnOccurrenceAttached(context.Context, notify.RecurrenceEvent) error {
	c.Calls++
	return nil
}

func firingDeliveryFixture(id, fingerprint, groupIdentity string, at time.Time) store.DeliveryInput {
	return deliveryFixtureForReconstruction(id, fingerprint, groupIdentity, "firing", at)
}

// deliveryFixtureForReconstruction builds one DeliveryInput ready for
// AcceptDeliveries, carrying groupIdentity as the Receiver grouping
// identity and an explicit status ("firing" or "resolved") on its Alert —
// the status firingDeliveryFixture always hardcodes to "firing".
func deliveryFixtureForReconstruction(id, fingerprint, groupIdentity, status string, at time.Time) store.DeliveryInput {
	return store.DeliveryInput{
		ID: id,
		Alert: store.Alert{
			ID:          "alert-" + fingerprint,
			Fingerprint: fingerprint,
			Status:      status,
			Labels:      map[string]string{"alertname": "test", "fp": fingerprint},
			Annotations: map[string]string{"summary": "test alert"},
			StartsAt:    at,
			ReceivedAt:  at,
		},
		Source:                   "alertmanager",
		SourceEpisodeKey:         "alertmanager:" + fingerprint + ":" + at.UTC().Format(time.RFC3339Nano),
		StartedAtBasis:           model.SourceTimeBasisReceiptFallback,
		ResolvedAtBasis:          model.SourceTimeBasisMissing,
		ReceiverGroupingIdentity: groupIdentity,
		PayloadDigest:            "sha256:" + id,
		SourceProvenance: store.SourceProvenance{
			AcquisitionMode: store.SourceAcquisitionWebhook,
		},
	}
}

// seedJudgedIncidentForReconstruction inserts a judged Incident with one
// member alert directly — mirroring internal/correlator's own unexported
// seedJudged/firingAlert test helpers, which this package cannot import —
// for building resolved/recurrence-collapse scenarios a Reconstructor.Run
// pass can reach via dispatch.Drain -> Correlator.ApplyDelivery.
func seedJudgedIncidentForReconstruction(t *testing.T, st *store.Store, id, groupKey, status string, lastActivity, lastJudged time.Time, member store.Alert) {
	t.Helper()
	ctx := context.Background()
	ts := func(x time.Time) string { return x.UTC().Format(time.RFC3339Nano) }
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO incidents
			(id, group_key, status, first_alert_at, last_alert_at, ready_at, alert_count, last_judged_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
	`, id, groupKey, status, ts(lastActivity), ts(lastActivity), ts(lastActivity), ts(lastJudged), ts(lastActivity), ts(lastActivity)); err != nil {
		t.Fatalf("seed judged incident %s: %v", id, err)
	}
	if _, err := st.UpsertAlertByFingerprint(ctx, member); err != nil {
		t.Fatalf("seed member alert for %s: %v", id, err)
	}
	if err := st.AddAlertToIncident(ctx, id, member.ID, member.ReceivedAt); err != nil {
		t.Fatalf("link member alert for %s: %v", id, err)
	}
}

func insertRawIncidentForReconstruction(t *testing.T, st *store.Store, id, groupKey, status string, at time.Time) {
	t.Helper()
	ts := at.UTC().Format(time.RFC3339Nano)
	if _, err := st.DB().ExecContext(context.Background(), `
		INSERT INTO incidents (id, group_key, status, first_alert_at, last_alert_at, ready_at, alert_count, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)`,
		id, groupKey, status, ts, ts, ts, ts, ts); err != nil {
		t.Fatalf("insert raw incident %s: %v", id, err)
	}
}

// reconstructionFixture builds a file-backed Store containing exactly the
// pre-restart state Step 1 of this task's plan calls for: one accepted
// pending delivery, one expired claimed delivery, one expired claimed
// Situation input, one expired Situation claim, and one incident per
// operational status plus one settled resolved incident, none of them
// owned by a Situation yet. It returns the store plus a DispatchWorker and
// situation.InputWorker wired to it (and to a Correlator whose sink/resolution
// notifier is the returned callCounter canary), ready for
// Reconstructor.WithReplay.
func reconstructionFixture(t *testing.T) (*store.Store, *correlator.DispatchWorker, *situation.InputWorker, *callCounter) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "reconstruction.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	// One accepted pending delivery, one expired claimed delivery — both
	// firing, on distinct groups, so dispatch.Drain opens two fresh
	// incidents rather than colliding on incidents_one_collecting_group_idx.
	if _, err := st.AcceptDeliveries(ctx, []store.DeliveryInput{
		firingDeliveryFixture("d-pending", "fp-pending", "group:pending", now),
		firingDeliveryFixture("d-expired", "fp-expired", "group:expired", now),
	}); err != nil {
		t.Fatalf("accept deliveries: %v", err)
	}
	if _, err := st.ClaimAlertDispatches(ctx, "stale-worker", now, time.Minute, 1); err != nil {
		t.Fatalf("claim dispatch to expire: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `UPDATE alert_delivery_dispatches SET lease_expires_at = ? WHERE delivery_id = 'd-expired'`,
		now.Add(-time.Second).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("force-expire dispatch lease: %v", err)
	}

	// One expired claimed Situation input, on an Incident of its own.
	if err := st.InsertIncident(ctx, store.Incident{
		ID: "inc-input-source", GroupKey: "group-input-source",
		FirstAlertAt: now, LastAlertAt: now, ReadyAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("insert input-source incident: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO situation_input_outbox (id, idempotency_key, incident_id, kind, group_key, occurred_at, status)
		VALUES ('input-expired', 'idem-input-expired', 'inc-input-source', 'incident_created', 'group-input-source', ?, 'pending')`,
		now.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert pending situation input: %v", err)
	}
	if _, err := st.ClaimSituationInputs(ctx, "stale-worker", now, time.Minute, 1); err != nil {
		t.Fatalf("claim situation input to expire: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `UPDATE situation_input_outbox SET lease_expires_at = ? WHERE id = 'input-expired'`,
		now.Add(-time.Second).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("force-expire situation input lease: %v", err)
	}

	// One expired Situation claim.
	ts := now.UTC().Format(time.RFC3339Nano)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO situations (
			id, group_key, lifecycle, attention, input_version,
			opened_at, effective_started_at, effective_started_at_basis, first_received_at,
			last_lifecycle_observed_at, next_assessment_at, due_reasons_json, created_at, updated_at
		) VALUES ('sit-expired-claim', 'group-sit-expired-claim', 'active', 'observe', 1, ?, ?, 'receipt_fallback', ?, ?, ?, '[]', ?, ?)`,
		ts, ts, ts, ts, ts, ts, ts); err != nil {
		t.Fatalf("seed situation for expired claim: %v", err)
	}
	if _, err := st.ClaimDueSituations(ctx, "stale-worker", now, time.Minute, 10); err != nil {
		t.Fatalf("claim situation to expire: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `UPDATE situations SET lease_expires_at = ? WHERE id = 'sit-expired-claim'`,
		now.Add(-time.Second).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("force-expire situation claim: %v", err)
	}

	// One Incident per operational status, plus one settled resolved
	// Incident — none owned by a Situation.
	for _, status := range []string{"collecting", "ready", "processing", "analyzed", "failed", "resolved"} {
		insertRawIncidentForReconstruction(t, st, "inc-"+status, "group-"+status, status, now)
	}

	notifier := &callCounter{}
	cor := correlator.New(correlator.Config{WindowSeconds: 60}, st, notifier, nil)
	cor.SetResolutionNotifier(notifier)
	dispatch := correlator.NewDispatchWorker(st, cor, correlator.WorkerConfig{Owner: "recon:dispatch"}, nil)
	inputs := situation.NewInputWorker(st, situation.WorkerConfig{Owner: "recon:input"}, nil)

	return st, dispatch, inputs, notifier
}

// reconstructionFixtureWithNotifiableDeliveries builds a second,
// independent file-backed Store whose queued durable deliveries are chosen
// specifically to reach the two Correlator code paths Task 8's review found
// synchronously reachable from Reconstructor.Run's dispatch.Drain ->
// Correlator.ApplyDelivery: (a) a resolved delivery for a group whose
// existing "ready" Incident has exactly one still-firing member — applying
// it resolves that member and flips the Incident fully to "resolved",
// which calls the Correlator's ResolutionNotifier if one is wired (mirrors
// internal/correlator's
// TestApplyDelivery_ResolvedDeliveryResolvesIncidentAndNotifies); and (b) a
// firing delivery for a group whose existing "analyzed" (judged) Incident
// has one member, queued with a brand-new fingerprint — applying it
// collapses into a new recurrence Occurrence, which calls the Correlator's
// OccurrenceNotifier if one is wired (mirrors
// TestApplyDelivery_RecurrenceCollapseAttachesOccurrenceAndNotifies). It
// returns the Correlator itself, unlike reconstructionFixture, so a test can
// control exactly when — relative to calling Reconstructor.Run — those two
// notifiers get wired.
func reconstructionFixtureWithNotifiableDeliveries(t *testing.T) (*store.Store, *correlator.Correlator, *correlator.DispatchWorker, *situation.InputWorker, *callCounter) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "reconstruction-notify.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	// (a) resolved delivery settling an existing "ready" Incident's only member.
	resolveMember := store.Alert{
		ID: "alert-resolve-member", Fingerprint: "fp-resolve-member", Status: "firing",
		Labels:      map[string]string{"alertname": "test", "fp": "fp-resolve-member"},
		Annotations: map[string]string{"summary": "test alert"},
		StartsAt:    now.Add(-time.Hour), ReceivedAt: now.Add(-time.Hour),
	}
	seedJudgedIncidentForReconstruction(t, st, "inc-resolve-target", "group:resolve-target", "ready", now.Add(-time.Hour), now.Add(-time.Hour), resolveMember)
	if _, err := st.AcceptDeliveries(ctx, []store.DeliveryInput{
		deliveryFixtureForReconstruction("d-resolve", "fp-resolve-member", "group:resolve-target", "resolved", now),
	}); err != nil {
		t.Fatalf("accept resolved delivery: %v", err)
	}

	// (b) firing delivery, new fingerprint, collapsing into a recurrence
	// occurrence against an existing "analyzed" Incident.
	occMember := store.Alert{
		ID: "alert-occ-member", Fingerprint: "fp-occ-member", Status: "firing",
		Labels:      map[string]string{"alertname": "test", "fp": "fp-occ-member"},
		Annotations: map[string]string{"summary": "test alert"},
		StartsAt:    now.Add(-5 * time.Minute), ReceivedAt: now.Add(-5 * time.Minute),
	}
	seedJudgedIncidentForReconstruction(t, st, "inc-occ-target", "group:occ-target", "analyzed", now.Add(-5*time.Minute), now.Add(-10*time.Minute), occMember)
	if _, err := st.AcceptDeliveries(ctx, []store.DeliveryInput{
		deliveryFixtureForReconstruction("d-occ", "fp-occ-new", "group:occ-target", "firing", now),
	}); err != nil {
		t.Fatalf("accept recurrence-collapsing delivery: %v", err)
	}

	notifier := &callCounter{}
	cor := correlator.New(correlator.Config{WindowSeconds: 60}, st, notifier, nil)
	dispatch := correlator.NewDispatchWorker(st, cor, correlator.WorkerConfig{Owner: "recon-notify:dispatch"}, nil)
	inputs := situation.NewInputWorker(st, situation.WorkerConfig{Owner: "recon-notify:input"}, nil)

	return st, cor, dispatch, inputs, notifier
}

// assertOperationalIncidentsRepresented asserts that every operational
// Incident (collecting/ready/processing/analyzed/failed) reconstructionFixture
// seeded now belongs to a Situation, and that the settled resolved Incident
// (no firing member) still does not.
func assertOperationalIncidentsRepresented(t *testing.T, st *store.Store) {
	t.Helper()
	ctx := context.Background()
	for _, status := range []string{"collecting", "ready", "processing", "analyzed", "failed"} {
		id := "inc-" + status
		var count int
		if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_incidents WHERE incident_id = ?`, id).Scan(&count); err != nil {
			t.Fatalf("count membership for %s: %v", id, err)
		}
		if count != 1 {
			t.Errorf("incident %s (status=%s) situation membership count = %d, want 1", id, status, count)
		}
	}
	var settledCount int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_incidents WHERE incident_id = 'inc-resolved'`).Scan(&settledCount); err != nil {
		t.Fatalf("count membership for settled resolved incident: %v", err)
	}
	if settledCount != 0 {
		t.Errorf("settled resolved incident got represented (count=%d), want 0 (excluded)", settledCount)
	}
}

// ----------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------

func TestReconstructorRepresentsEveryOperationalIncidentWithoutPublishing(t *testing.T) {
	st, dispatch, inputs, notifier := reconstructionFixture(t)
	r := situation.NewReconstructor(st, fixedClock).WithReplay(dispatch, inputs)
	report, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if notifier.Calls != 0 {
		t.Fatalf("startup published %d outward effects", notifier.Calls)
	}
	if report.ReplayedDeliveries == 0 || report.ReplayedInputs == 0 {
		t.Fatalf("report = %+v", report)
	}
	assertOperationalIncidentsRepresented(t, st)
}

// TestReconstructorReportsDeadLetteredWork proves a permanently failed
// (status='failed', MaxAttempts exhausted) row in each fenced outbox table
// surfaces on the report Run returns — the startup-visible tripwire
// docs/concepts/architecture.md's "nothing is ever silently dropped"
// promise depends on (see store.CountDeadLetteredFoundationWork).
func TestReconstructorReportsDeadLetteredWork(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "dead-letter.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	if _, err := st.AcceptDeliveries(ctx, []store.DeliveryInput{
		firingDeliveryFixture("d-dead", "fp-dead", "group:dead", now),
	}); err != nil {
		t.Fatalf("accept delivery: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `UPDATE alert_delivery_dispatches SET status = 'failed' WHERE delivery_id = 'd-dead'`); err != nil {
		t.Fatalf("dead-letter dispatch: %v", err)
	}

	r := situation.NewReconstructor(st, fixedClock)
	report, err := r.Run(ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.DeadLettered.AlertDispatches != 1 {
		t.Fatalf("DeadLettered.AlertDispatches = %d, want 1", report.DeadLettered.AlertDispatches)
	}
	if report.DeadLettered.SituationInputs != 0 {
		t.Fatalf("DeadLettered.SituationInputs = %d, want 0", report.DeadLettered.SituationInputs)
	}
}

func TestReconstructorSecondRunCreatesOrAttachesNothingNew(t *testing.T) {
	st, dispatch, inputs, notifier := reconstructionFixture(t)
	r := situation.NewReconstructor(st, fixedClock).WithReplay(dispatch, inputs)
	ctx := context.Background()

	if _, err := r.Run(ctx); err != nil {
		t.Fatalf("first run: %v", err)
	}
	assertOperationalIncidentsRepresented(t, st)

	var situationsBefore, membershipsBefore int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM situations`).Scan(&situationsBefore); err != nil {
		t.Fatal(err)
	}
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_incidents`).Scan(&membershipsBefore); err != nil {
		t.Fatal(err)
	}

	report, err := r.Run(ctx)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if notifier.Calls != 0 {
		t.Fatalf("second run published %d outward effects", notifier.Calls)
	}
	if report.ReplayedDeliveries != 0 || report.ReplayedInputs != 0 || report.RepresentedGroups != 0 || report.RepresentedIncidents != 0 {
		t.Fatalf("second run report = %+v, want an all-zero no-op", report)
	}

	var situationsAfter, membershipsAfter int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM situations`).Scan(&situationsAfter); err != nil {
		t.Fatal(err)
	}
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_incidents`).Scan(&membershipsAfter); err != nil {
		t.Fatal(err)
	}
	if situationsAfter != situationsBefore || membershipsAfter != membershipsBefore {
		t.Fatalf("second run changed durable state: situations %d->%d, memberships %d->%d",
			situationsBefore, situationsAfter, membershipsBefore, membershipsAfter)
	}
}

// TestReconstructorNeverCallsNotifiersWiredAfterReconstruction proves the
// discipline cmd/alertint's startCorrelator now follows (wire
// SetResolutionNotifier/SetOccurrenceNotifier strictly between reconstruct
// and Correlator.Start, never before) is what actually keeps reconstruction
// silent: it runs Reconstructor.Run against a fixture whose queued
// deliveries genuinely reach both the resolution-notifier and the
// occurrence-notifier branches (see
// reconstructionFixtureWithNotifiableDeliveries), then wires both notifiers
// only afterward, and asserts zero calls happened. Its sibling test below
// proves this isn't vacuous — the same fixture, with the notifiers wired
// before Run instead, does leak.
func TestReconstructorNeverCallsNotifiersWiredAfterReconstruction(t *testing.T) {
	st, cor, dispatch, inputs, notifier := reconstructionFixtureWithNotifiableDeliveries(t)
	r := situation.NewReconstructor(st, fixedClock).WithReplay(dispatch, inputs)

	if _, err := r.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if notifier.Calls != 0 {
		t.Fatalf("reconstruction produced %d outward notifier call(s) with no notifier wired yet — impossible unless Correlator.ApplyDelivery changed", notifier.Calls)
	}

	// Wire the notifiers exactly where cmd/alertint's startCorrelator does:
	// strictly between reconstruction and Correlator.Start, never before.
	cor.SetResolutionNotifier(notifier)
	cor.SetOccurrenceNotifier(notifier)
}

// TestNotifiersWiredBeforeReconstructionWouldLeakOutward intentionally
// reproduces the exact ordering bug Task 8's review caught in
// cmd/alertint/main.go — wiring the Correlator's notifiers before
// reconstruction runs — against the same fixture the sibling test above
// uses. It exists so a future change that wires notifiers earlier (in
// cmd/alertint, or in a fixture like this one) fails loudly here instead of
// silently regressing the fix, and so the sibling test's zero-calls
// assertion is proven non-vacuous: this fixture's resolved/
// recurrence-collapsing deliveries really do reach the notifier branches
// when given the chance.
func TestNotifiersWiredBeforeReconstructionWouldLeakOutward(t *testing.T) {
	st, cor, dispatch, inputs, notifier := reconstructionFixtureWithNotifiableDeliveries(t)
	cor.SetResolutionNotifier(notifier)
	cor.SetOccurrenceNotifier(notifier)
	r := situation.NewReconstructor(st, fixedClock).WithReplay(dispatch, inputs)

	if _, err := r.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if notifier.Calls == 0 {
		t.Fatal("expected wiring notifiers before reconstruction to leak at least one outward call; if this reads 0, the fixture's deliveries no longer reach the vulnerable code paths and this regression guard has gone silent")
	}
}

// ----------------------------------------------------------------------
// Orchestration-layer unit tests against fakes
// ----------------------------------------------------------------------

// fakeReconstructStore is a scriptable ReconstructStore for testing
// Reconstructor.Run's own ordering and error-handling logic in isolation
// from any real database.
type fakeReconstructStore struct {
	recoverErr error
	recovered  situation.LeaseRecovery

	deadLettered    situation.DeadLetterCounts
	deadLetteredErr error

	incidents    []situation.UpgradeIncident
	incidentsErr error

	reconstructErr map[string]error // group key -> error, if any
	reconstructed  []string         // group keys actually reconstructed, in call order
}

func (f *fakeReconstructStore) RecoverExpiredFoundationLeases(context.Context, time.Time) (situation.LeaseRecovery, error) {
	return f.recovered, f.recoverErr
}

func (f *fakeReconstructStore) CountDeadLetteredFoundationWork(context.Context) (situation.DeadLetterCounts, error) {
	return f.deadLettered, f.deadLetteredErr
}

func (f *fakeReconstructStore) UnrepresentedOperationalIncidents(context.Context) ([]situation.UpgradeIncident, error) {
	return f.incidents, f.incidentsErr
}

func (f *fakeReconstructStore) ReconstructSituation(_ context.Context, groupKey string, _ []situation.UpgradeIncident, _ time.Time) (string, error) {
	f.reconstructed = append(f.reconstructed, groupKey)
	if err, ok := f.reconstructErr[groupKey]; ok {
		return "", err
	}
	return "sit-" + groupKey, nil
}

type fakeReplayer struct {
	drained int
	err     error
	calls   int
}

func (f *fakeReplayer) Drain(context.Context) (int, error) {
	f.calls++
	return f.drained, f.err
}

func TestReconstructorRunShortCircuitsOnLeaseRecoveryFailure(t *testing.T) {
	fs := &fakeReconstructStore{recoverErr: errors.New("boom")}
	dispatch := &fakeReplayer{}
	inputs := &fakeReplayer{}
	r := situation.NewReconstructor(fs, fixedClock).WithReplay(dispatch, inputs)

	if _, err := r.Run(context.Background()); err == nil {
		t.Fatal("expected an error when lease recovery fails")
	}
	if dispatch.calls != 0 || inputs.calls != 0 {
		t.Fatalf("dispatch/input drains ran despite a lease-recovery failure: %d/%d calls", dispatch.calls, inputs.calls)
	}
}

func TestReconstructorRunShortCircuitsOnDrainFailure(t *testing.T) {
	fs := &fakeReconstructStore{}
	dispatch := &fakeReplayer{err: errors.New("dispatch drain failed")}
	inputs := &fakeReplayer{}
	r := situation.NewReconstructor(fs, fixedClock).WithReplay(dispatch, inputs)

	if _, err := r.Run(context.Background()); err == nil {
		t.Fatal("expected an error when the delivery drain fails")
	}
	if inputs.calls != 0 {
		t.Fatalf("input drain ran despite a delivery-drain failure: %d calls", inputs.calls)
	}
}

func TestReconstructorRunOneBadGroupDoesNotBlockTheRest(t *testing.T) {
	fs := &fakeReconstructStore{
		incidents: []situation.UpgradeIncident{
			{IncidentID: "inc-1", GroupKey: "group-a"},
			{IncidentID: "inc-2", GroupKey: "group-b"},
			{IncidentID: "inc-3", GroupKey: "group-c"},
		},
		reconstructErr: map[string]error{"group-b": errors.New("malformed group")},
	}
	r := situation.NewReconstructor(fs, fixedClock)

	report, err := r.Run(context.Background())
	if err == nil {
		t.Fatal("expected a joined error surfacing the one malformed group")
	}
	if report.RepresentedGroups != 2 || report.RepresentedIncidents != 2 {
		t.Fatalf("report = %+v, want the two good groups represented despite the bad one", report)
	}
	want := []string{"group-a", "group-b", "group-c"}
	if len(fs.reconstructed) != len(want) {
		t.Fatalf("reconstructed groups = %v, want all three attempted", fs.reconstructed)
	}
	for i, g := range want {
		if fs.reconstructed[i] != g {
			t.Fatalf("reconstructed groups = %v, want deterministic order %v", fs.reconstructed, want)
		}
	}
}

func TestReconstructorRunOrdersRecoverDrainDrainRepresent(t *testing.T) {
	var trace []string
	fs := &traceReconstructStore{trace: &trace}
	dispatch := &traceReplayer{trace: &trace, label: "drain_deliveries"}
	inputs := &traceReplayer{trace: &trace, label: "drain_inputs"}
	r := situation.NewReconstructor(fs, fixedClock).WithReplay(dispatch, inputs)

	if _, err := r.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	want := []string{"recover_leases", "drain_deliveries", "drain_inputs", "reconstruct_incidents"}
	if len(trace) != len(want) {
		t.Fatalf("trace = %v, want %v", trace, want)
	}
	for i := range want {
		if trace[i] != want[i] {
			t.Fatalf("trace = %v, want %v", trace, want)
		}
	}
}

// traceReconstructStore appends to a shared trace at recover-leases time
// and at the one represent-phase call (a single group, so
// "reconstruct_incidents" appears exactly once) — enough to prove
// Reconstructor.Run's phase order without needing a real database.
type traceReconstructStore struct {
	trace *[]string
}

func (f *traceReconstructStore) RecoverExpiredFoundationLeases(context.Context, time.Time) (situation.LeaseRecovery, error) {
	*f.trace = append(*f.trace, "recover_leases")
	return situation.LeaseRecovery{}, nil
}

func (f *traceReconstructStore) CountDeadLetteredFoundationWork(context.Context) (situation.DeadLetterCounts, error) {
	return situation.DeadLetterCounts{}, nil
}

func (f *traceReconstructStore) UnrepresentedOperationalIncidents(context.Context) ([]situation.UpgradeIncident, error) {
	return []situation.UpgradeIncident{{IncidentID: "inc-1", GroupKey: "group-a"}}, nil
}

func (f *traceReconstructStore) ReconstructSituation(context.Context, string, []situation.UpgradeIncident, time.Time) (string, error) {
	*f.trace = append(*f.trace, "reconstruct_incidents")
	return "sit-a", nil
}

type traceReplayer struct {
	trace *[]string
	label string
}

func (f *traceReplayer) Drain(context.Context) (int, error) {
	*f.trace = append(*f.trace, f.label)
	return 0, nil
}
