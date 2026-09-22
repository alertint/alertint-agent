// SPDX-License-Identifier: FSL-1.1-ALv2

package correlator_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/correlator"
	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

// ----------------------------------------------------------------------
// Task 9, Step 4: end-to-end durability scenarios 3, 4, and 7 — the crash
// boundaries this package's own DispatchWorker and the sibling
// situation.InputWorker/Reconstructor own. Every fixture here drives the
// real durable pipeline (AcceptDeliveries / ClaimAlertDispatches /
// Correlator.ApplyDelivery / ClaimSituationInputs / ApplySituationInput);
// none of them ever INSERTs a row into the situations table by hand.
// ----------------------------------------------------------------------

// newFoundationFileStore opens a fresh file-backed Store in a per-test temp
// directory and returns it plus its file path, so a test can close it and
// reopen the SAME file to simulate a restart. Unlike newTestStore
// (correlator_test.go, :memory:), this is real, durable, on-disk state —
// exactly what Step 4's crash-boundary scenarios require.
func newFoundationFileStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "foundation.db")
	st, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("open file store: %v", err)
	}
	return st, path
}

// foundationDeliveryFixture builds one firing DeliveryInput ready for
// AcceptDeliveries — the minimum viable immutable delivery this task's
// scenarios correlate through the real pipeline, never a hand-inserted
// Situation or Incident row.
func foundationDeliveryFixture(id, fingerprint, groupIdentity string, at time.Time) store.DeliveryInput {
	return store.DeliveryInput{
		ID: id,
		Alert: store.Alert{
			ID:          "alert-" + fingerprint,
			Fingerprint: fingerprint,
			Status:      "firing",
			Labels:      map[string]string{"alertname": "test", "fp": fingerprint},
			Annotations: map[string]string{},
			StartsAt:    at,
			ReceivedAt:  at,
		},
		Source:                   "alertmanager",
		SourceEpisodeKey:         "alertmanager:" + fingerprint + ":" + at.UTC().Format(time.RFC3339Nano),
		StartedAtBasis:           situationmodel.SourceTimeBasisReceiptFallback,
		ResolvedAtBasis:          situationmodel.SourceTimeBasisMissing,
		ReceiverGroupingIdentity: groupIdentity,
		PayloadDigest:            "sha256:" + id,
		SourceProvenance:         store.SourceProvenance{AcquisitionMode: store.SourceAcquisitionWebhook},
	}
}

// countRows runs a literal (never concatenated) COUNT query and returns the
// scalar result.
func countRows(t *testing.T, st *store.Store, query string) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRowContext(context.Background(), query).Scan(&n); err != nil {
		t.Fatalf("count query %q: %v", query, err)
	}
	return n
}

func incidentStatus(t *testing.T, st *store.Store, incidentID string) string {
	t.Helper()
	var status string
	if err := st.DB().QueryRowContext(context.Background(), `SELECT status FROM incidents WHERE id = ?`, incidentID).Scan(&status); err != nil {
		t.Fatalf("read incident %s status: %v", incidentID, err)
	}
	return status
}

func situationLifecycleForGroup(t *testing.T, st *store.Store, groupKey string) string {
	t.Helper()
	var lifecycle string
	if err := st.DB().QueryRowContext(context.Background(), `SELECT lifecycle FROM situations WHERE group_key = ?`, groupKey).Scan(&lifecycle); err != nil {
		t.Fatalf("read situation lifecycle for group %s: %v", groupKey, err)
	}
	return lifecycle
}

// ----------------------------------------------------------------------
// Scenario 3: stop after correlation commit and before input application,
// reopen, reconstruct, and observe the same one Incident/Situation.
// ----------------------------------------------------------------------

func TestFoundationCrashAfterCorrelationCommitBeforeInputApplication(t *testing.T) {
	ctx := context.Background()
	st, path := newFoundationFileStore(t)

	now := time.Date(2026, 9, 1, 4, 0, 0, 0, time.UTC)
	delivery := foundationDeliveryFixture("d-crash-input", "fp-crash-input", "group:crash-input", now)
	if _, err := st.AcceptDeliveries(ctx, []store.DeliveryInput{delivery}); err != nil {
		t.Fatalf("accept delivery: %v", err)
	}

	cor := correlator.New(correlator.Config{WindowSeconds: 60}, st, nil, nil)
	dispatch := correlator.NewDispatchWorker(st, cor, correlator.WorkerConfig{Owner: "precrash:dispatch"}, nil)
	n, err := dispatch.Drain(ctx)
	if err != nil {
		t.Fatalf("drain dispatch: %v", err)
	}
	if n != 1 {
		t.Fatalf("dispatch drained %d, want 1", n)
	}

	// Correlation committed: exactly one Incident and one pending Situation
	// input, but the input worker has never run — zero Situations yet.
	if got := countRows(t, st, `SELECT COUNT(*) FROM incidents`); got != 1 {
		t.Fatalf("incidents = %d, want 1", got)
	}
	if got := countRows(t, st, `SELECT COUNT(*) FROM situations`); got != 0 {
		t.Fatalf("situations = %d, want 0 (input worker has not run yet)", got)
	}
	if got := countRows(t, st, `SELECT COUNT(*) FROM situation_input_outbox WHERE status = 'pending'`); got != 1 {
		t.Fatalf("pending situation inputs = %d, want 1", got)
	}

	// Crash: close before the input worker ever claims that pending input.
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	// Restart against the same file.
	st2, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { _ = st2.Close() })

	cor2 := correlator.New(correlator.Config{WindowSeconds: 60}, st2, nil, nil)
	dispatch2 := correlator.NewDispatchWorker(st2, cor2, correlator.WorkerConfig{Owner: "restart:dispatch"}, nil)
	inputs2 := situation.NewInputWorker(st2, situation.WorkerConfig{Owner: "restart:input"}, nil)
	r := situation.NewReconstructor(st2, func() time.Time { return now.Add(time.Minute) }).WithReplay(dispatch2, inputs2)

	report, err := r.Run(ctx)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if report.ReplayedInputs != 1 {
		t.Fatalf("replayed inputs = %d, want 1", report.ReplayedInputs)
	}
	if report.RepresentedGroups != 0 || report.RepresentedIncidents != 0 {
		t.Fatalf("report = %+v, want the fallback represent phase to find nothing — the input-drain path already owns this Incident", report)
	}

	if got := countRows(t, st2, `SELECT COUNT(*) FROM incidents`); got != 1 {
		t.Fatalf("incidents after restart = %d, want 1 (no duplicate)", got)
	}
	if got := countRows(t, st2, `SELECT COUNT(*) FROM situations`); got != 1 {
		t.Fatalf("situations after restart = %d, want exactly 1", got)
	}
	if got := countRows(t, st2, `SELECT COUNT(*) FROM situation_incidents`); got != 1 {
		t.Fatalf("situation_incidents after restart = %d, want exactly 1", got)
	}
}

// ----------------------------------------------------------------------
// Scenario 4: expire both claim types and prove replacement workers
// complete them while stale workers are fenced.
// ----------------------------------------------------------------------

func TestFoundationExpiredClaimsCompleteByReplacementFencingStaleWorkers(t *testing.T) {
	ctx := context.Background()
	st, _ := newFoundationFileStore(t)
	now := time.Date(2026, 9, 1, 5, 0, 0, 0, time.UTC)

	// --- alert_delivery_dispatches: expire, replacement completes, stale is fenced ---
	delivery := foundationDeliveryFixture("d-fence", "fp-fence", "group:fence-dispatch", now)
	if _, err := st.AcceptDeliveries(ctx, []store.DeliveryInput{delivery}); err != nil {
		t.Fatalf("accept delivery: %v", err)
	}
	staleDispatchClaims, err := st.ClaimAlertDispatches(ctx, "stale-worker", now, time.Minute, 1)
	if err != nil || len(staleDispatchClaims) != 1 {
		t.Fatalf("stale dispatch claim: %v (%d claims)", err, len(staleDispatchClaims))
	}
	staleDispatchClaim := staleDispatchClaims[0]
	if _, err := st.DB().ExecContext(ctx, `UPDATE alert_delivery_dispatches SET lease_expires_at = ? WHERE delivery_id = ?`,
		now.Add(-time.Second).UTC().Format(time.RFC3339Nano), delivery.ID); err != nil {
		t.Fatalf("force-expire dispatch lease: %v", err)
	}

	cor := correlator.New(correlator.Config{WindowSeconds: 60}, st, nil, nil)
	replacementDispatch := correlator.NewDispatchWorker(st, cor, correlator.WorkerConfig{Owner: "replacement-worker"}, nil)
	n, err := replacementDispatch.Drain(ctx)
	if err != nil {
		t.Fatalf("replacement dispatch drain: %v", err)
	}
	if n != 1 {
		t.Fatalf("replacement dispatch drained %d, want 1", n)
	}
	if got := countRows(t, st, `SELECT COUNT(*) FROM incidents WHERE group_key = 'group:fence-dispatch'`); got != 1 {
		t.Fatalf("incidents for fenced group = %d, want exactly 1 (no double-apply)", got)
	}

	// The stale worker's own (pre-expiry) claim can no longer commit: the
	// row's claim_token already moved on to the replacement's claim.
	if err := cor.ApplyDelivery(ctx, staleDispatchClaim); !errors.Is(err, store.ErrAlertDispatchLeaseLost) {
		t.Fatalf("stale dispatch apply = %v, want ErrAlertDispatchLeaseLost", err)
	}

	// Draining the dispatch above queued its own situation_input_outbox row
	// (every correlated delivery produces one — ApplyCorrelatedDelivery).
	// Drain it now so it cannot compete with "input-fence" below for the
	// next ClaimSituationInputs call's LIMIT-1 slot.
	if _, err := situation.NewInputWorker(st, situation.WorkerConfig{Owner: "drain-before-input-fencing"}, nil).Drain(ctx); err != nil {
		t.Fatalf("drain situation inputs queued by the dispatch fencing above: %v", err)
	}

	// --- situation_input_outbox: expire, replacement claims, stale is
	// fenced WHILE the replacement still holds the claim (the only window
	// where fencing is observable — ApplySituationInput treats an already-
	// "applied" row as an idempotent no-op, not a lease error, so this must
	// be proven before the replacement's own apply commits).
	if err := st.InsertIncident(ctx, store.Incident{
		ID: "inc-fence-input", GroupKey: "group:fence-input",
		FirstAlertAt: now, LastAlertAt: now, ReadyAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO situation_input_outbox (id, idempotency_key, incident_id, kind, group_key, occurred_at, status)
		VALUES ('input-fence', 'idem-input-fence', 'inc-fence-input', 'incident_created', 'group:fence-input', ?, 'pending')`,
		now.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert situation input: %v", err)
	}
	staleInputClaims, err := st.ClaimSituationInputs(ctx, "stale-worker", now, time.Minute, 1)
	if err != nil || len(staleInputClaims) != 1 {
		t.Fatalf("stale input claim: %v (%d claims)", err, len(staleInputClaims))
	}
	if _, err := st.DB().ExecContext(ctx, `UPDATE situation_input_outbox SET lease_expires_at = ? WHERE id = 'input-fence'`,
		now.Add(-time.Second).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("force-expire situation input lease: %v", err)
	}
	replacementInputClaims, err := st.ClaimSituationInputs(ctx, "replacement-worker", now, time.Minute, 1)
	if err != nil || len(replacementInputClaims) != 1 {
		t.Fatalf("replacement input claim: %v (%d claims)", err, len(replacementInputClaims))
	}

	if err := st.ApplySituationInput(ctx, staleInputClaims[0]); !errors.Is(err, store.ErrSituationLeaseLost) {
		t.Fatalf("stale input apply while replacement holds the claim = %v, want ErrSituationLeaseLost", err)
	}
	if err := st.ApplySituationInput(ctx, replacementInputClaims[0]); err != nil {
		t.Fatalf("replacement input apply: %v", err)
	}
	if got := countRows(t, st, `SELECT COUNT(*) FROM situations WHERE group_key = 'group:fence-input'`); got != 1 {
		t.Fatalf("situations for fenced input group = %d, want exactly 1", got)
	}
}

// ----------------------------------------------------------------------
// Scenario 7: a `failed` active Incident predating Situation attachment —
// the same operational shape Task 2's migration-12 upgrade fixture proves
// at the store layer (internal/store/situation_upgrade_test.go) — must
// reconstruct through this task's runtime Reconstructor. This uses only
// the exported Store surface (InsertIncident/MarkIncidentReady/
// MarkIncidentFailed); store's own unexported partial-migration fixture
// builder lives in a different package this test cannot import.
// ----------------------------------------------------------------------

func TestFoundationReconstructionExposesFailedOperationalIncident(t *testing.T) {
	ctx := context.Background()
	st, _ := newFoundationFileStore(t)
	now := time.Date(2026, 9, 1, 6, 0, 0, 0, time.UTC)

	if err := st.InsertIncident(ctx, store.Incident{
		ID: "inc-failed-upgrade", GroupKey: "group:failed-upgrade",
		FirstAlertAt: now, LastAlertAt: now, ReadyAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	if err := st.MarkIncidentReady(ctx, "inc-failed-upgrade"); err != nil {
		t.Fatalf("mark ready: %v", err)
	}
	if err := st.MarkIncidentFailed(ctx, "inc-failed-upgrade"); err != nil {
		t.Fatalf("mark failed: %v", err)
	}
	if got := incidentStatus(t, st, "inc-failed-upgrade"); got != "failed" {
		t.Fatalf("incident status = %s, want failed", got)
	}
	if got := countRows(t, st, `SELECT COUNT(*) FROM situation_incidents WHERE incident_id = 'inc-failed-upgrade'`); got != 0 {
		t.Fatalf("situation membership before reconstruction = %d, want 0", got)
	}

	cor := correlator.New(correlator.Config{WindowSeconds: 60}, st, nil, nil)
	dispatch := correlator.NewDispatchWorker(st, cor, correlator.WorkerConfig{Owner: "recon:dispatch"}, nil)
	inputs := situation.NewInputWorker(st, situation.WorkerConfig{Owner: "recon:input"}, nil)
	r := situation.NewReconstructor(st, func() time.Time { return now.Add(time.Hour) }).WithReplay(dispatch, inputs)

	report, err := r.Run(ctx)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if report.RepresentedIncidents != 1 || report.RepresentedGroups != 1 {
		t.Fatalf("report = %+v, want exactly the one failed incident represented via the fallback represent phase", report)
	}

	if got := countRows(t, st, `SELECT COUNT(*) FROM situation_incidents WHERE incident_id = 'inc-failed-upgrade'`); got != 1 {
		t.Fatalf("situation membership after reconstruction = %d, want 1", got)
	}
	if got := situationLifecycleForGroup(t, st, "group:failed-upgrade"); got != "active" {
		t.Fatalf("represented situation lifecycle = %s, want active", got)
	}
	// incident status itself is untouched by representation — reconstruction
	// only attaches Situation membership, it never mutates Incident state.
	if got := incidentStatus(t, st, "inc-failed-upgrade"); got != "failed" {
		t.Fatalf("incident status after reconstruction = %s, want still failed", got)
	}
}
