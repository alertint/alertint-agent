// SPDX-License-Identifier: FSL-1.1-ALv2

// Package situation_test exercises the crash-boundary guarantee across the
// full production stack (internal/ingress, internal/correlator,
// internal/store, and internal/situation) against a real file-backed SQLite
// database — never an in-package double. It lives as an external test
// package specifically so it can import internal/store and
// internal/correlator (which internal/situation itself cannot, since
// internal/store already imports internal/situation) while still reaching
// the crash-injection seam through the exported *ForTest setters
// internal/situation/replay.go declares for exactly this purpose.
package situation_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/correlator"
	"github.com/alertint/alertint-agent/internal/ingress"
	"github.com/alertint/alertint-agent/internal/llm"
	notifyslack "github.com/alertint/alertint-agent/internal/notify/slack"
	"github.com/alertint/alertint-agent/internal/observation"
	"github.com/alertint/alertint-agent/internal/observation/connectors"
	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

// errInjectedCrash marks the point a subtest asked the crash seam to
// simulate a process death. It is never itself asserted on — only that
// nothing durable was lost, duplicated, or reopened once the process comes
// back up against the same SQLite file.
var errInjectedCrash = errors.New("crash test: injected boundary failure")

func crashAt(target string) func(name string) error {
	return func(name string) error {
		if name == target {
			return errInjectedCrash
		}
		return nil
	}
}

// TestRestartAfterEveryBoundary drives one realistic scenario per named I/O
// boundary — receiver commit, correlation commit, Situation-input apply,
// observation execution, L1 completion, L2 completion, the authoritative
// transition commit, and every outward Slack effect — injects a crash
// exactly there via the boundaryHook seam, closes the SQLite file, reopens
// it (a real process restart would do no less and no more), resumes
// ordinary operation to quiescence, and asserts the exactly-once durability
// invariants: no lost accepted delivery, no duplicate ownership, no
// duplicate input version, no duplicate root, no reopened terminal
// Situation, and no missing durable intent.
//
// observation_commit has no real production commit to interrupt today:
// internal/situation's Controller never invokes the observation.Runner
// during Reconcile (a parked plan gap noted in this task's brief), so
// nothing about a bounded observation run is durable to begin with. This
// subtest instead exercises the one production path that DOES exist —
// observation.Runner.Execute against the real store_read reducer — and
// proves it is safely re-runnable, which is the honest substitute for a
// persistence boundary that is not yet wired.
func TestRestartAfterEveryBoundary(t *testing.T) {
	boundaries := []string{
		"receiver_commit", "correlation_commit", "situation_input_commit", "observation_commit",
		"l1_complete", "l2_complete", "transition_commit",
		"slack_post_timeout", "slack_coordinate_commit", "root_edit", "thread_reply",
	}
	for _, boundary := range boundaries {
		t.Run(boundary, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "alertint.db")
			runUntilInjectedCrash(t, dbPath, boundary)
			runToQuiescence(t, dbPath)
			assertExactlyOnceInvariants(t, dbPath, boundary)
		})
	}
}

// --------------------------------------------------------------------------
// Scenario doubles
// --------------------------------------------------------------------------

// completingInvestigator is a real, immediately-completing AcuteInvestigator.
type completingInvestigator struct{}

func (completingInvestigator) Investigate(_ context.Context, incidentID string) (situation.AcuteResult, error) {
	return situation.AcuteResult{IncidentID: incidentID, RootCause: "resolved", Confidence: 0.9, CompletedAt: time.Now().UTC()}, nil
}

// observeAssessor scripts one valid, unpublished L2 response (Attention
// observe, no sufficient reason) — used only for the l2_complete/
// transition_commit boundaries against a non-critical delivery that never
// crosses the deterministic floor, so L2 genuinely runs instead of being
// short-circuited by it.
type observeAssessor struct{}

func (observeAssessor) Complete(_ context.Context, _ string, _ llm.Prompt, _ []string) (llm.Completion, error) {
	nextUpdate := time.Now().UTC().Add(5 * time.Minute)
	a := model.Assessment{
		SchemaVersion: situation.AssessmentSchemaVersion, Persistence: model.PersistenceUnknown, Impact: model.ImpactUnknown,
		Novelty: model.NoveltyInsufficientHistory, Causality: model.CausalityUnknown, Attention: model.AttentionObserve,
		Lifecycle: model.LifecycleActive, EvidenceQuality: model.EvidenceQualityDegraded,
		ActionContract:  model.ActionContract{NextActor: model.NextActorNone, ActionStatus: model.ActionStatusWaiting, NextUpdateAt: &nextUpdate},
		Limitations:     []model.Limitation{},
		ProposedCadence: model.CadenceNormal,
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return llm.Completion{}, err
	}
	return llm.Completion{Raw: raw, Model: "stub-observe"}, nil
}

// recordingDeliverer is a real situation.NotificationDeliverer double: it
// always succeeds, deterministically deriving coordinates from the intent's
// own client_msg_id — the same idempotent identity Slack delivery replays
// against in production.
type recordingDeliverer struct{}

func (recordingDeliverer) Deliver(_ context.Context, intent model.NotificationIntent) (situation.NotificationDelivery, error) {
	sum := sha256.Sum256([]byte(intent.ClientMessageID))
	return situation.NotificationDelivery{Channel: "#alerts", MessageTS: hex.EncodeToString(sum[:8])}, nil
}

// --------------------------------------------------------------------------
// Wiring
// --------------------------------------------------------------------------

// crashRig is the minimal production topology one crash-boundary subtest
// needs, rebuilt fresh against the same SQLite file every time the test
// simulates a restart.
type crashRig struct {
	st         *store.Store
	runtime    *store.SituationRuntime
	receiver   ingress.Receiver
	dispatch   *correlator.DispatchWorker
	inputs     *situation.InputWorker
	controller *situation.Controller
	notify     *situation.NotificationWorker
	clock      func() time.Time
}

func buildCrashRig(t *testing.T, dbPath string, assessor situation.AssessmentClient) *crashRig {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	clock := func() time.Time { return time.Now().UTC() }
	logger := slog.New(slog.DiscardHandler)
	cor := correlator.New(correlator.Config{GroupLabels: []string{"service"}}, st, correlator.NopIncidentSink{}, logger)
	receiver := ingress.NewAlertReceiver(st, "test-token", nil, logger)
	dispatch := correlator.NewDispatchWorker(st, cor, correlator.DispatchWorkerConfig{Owner: "crash-dispatch", Lease: time.Minute}, logger)

	runtime := store.NewSituationRuntime(st, notifyslack.ClientMessageID, nil, clock, store.SituationRuntimePolicy{
		MinSeverity: model.PriorityLow, RecurrenceMode: "", HorizonTier: situation.HorizonUnknown,
	})
	inputs := situation.NewInputWorker(runtime, situation.WorkerConfig{Owner: "crash-inputs", Batch: 16}, clock, logger)
	controller := situation.NewController(runtime, nil, nil, completingInvestigator{}, assessor, clock, situation.Config{})
	notify := situation.NewNotificationWorker(runtime, recordingDeliverer{}, situation.WorkerConfig{Owner: "crash-notify", Batch: 16}, clock, logger)

	return &crashRig{st: st, runtime: runtime, receiver: receiver, dispatch: dispatch, inputs: inputs, controller: controller, notify: notify, clock: clock}
}

// ingestOne posts one Alertmanager delivery for the fixed test group.
func ingestOne(t *testing.T, receiver ingress.Receiver, severity string, at time.Time) {
	t.Helper()
	payload := ingress.AlertmanagerPayload{
		Version: "4", Status: "firing", GroupLabels: map[string]string{"service": "crash-svc"},
		Alerts: []ingress.AlertmanagerAlert{{
			Status: "firing", Fingerprint: "fp-crash-boundary",
			Labels:      map[string]string{"alertname": "CrashBoundaryProbe", "service": "crash-svc", "severity": severity},
			Annotations: map[string]string{}, StartsAt: at,
		}},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if _, err := receiver.Ingest(context.Background(), raw); err != nil {
		t.Fatalf("ingest: %v", err)
	}
}

// --------------------------------------------------------------------------
// Crash driver
// --------------------------------------------------------------------------

// runUntilInjectedCrash drives the scenario up to and through the named
// boundary and stops — the store stays open on return, standing in for a
// process that just crashed rather than shutting down cleanly; the caller
// reopens it via runToQuiescence.
func runUntilInjectedCrash(t *testing.T, dbPath string, boundary string) {
	t.Helper()
	ctx := context.Background()
	nonCritical := boundary == "l2_complete"

	var assessor situation.AssessmentClient
	if nonCritical {
		assessor = observeAssessor{}
	}
	rig := buildCrashRig(t, dbPath, assessor)
	now := rig.clock()

	severity := "critical"
	if nonCritical {
		severity = "high"
	}
	ingestOne(t, rig.receiver, severity, now)
	if boundary == "receiver_commit" {
		return
	}

	if err := rig.dispatch.RunOnce(ctx); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if boundary == "correlation_commit" {
		return
	}

	if _, err := rig.inputs.RunOnce(ctx); err != nil {
		t.Fatalf("apply situation input: %v", err)
	}
	if boundary == "situation_input_commit" {
		return
	}

	if boundary == "observation_commit" {
		runObservationOnce(t, rig.st)
		return
	}

	// From here every boundary needs the Situation claimed and reconciled at
	// least once — the B+ gate's async L1 dispatch and (for the non-critical
	// scenario) the synchronous L2 call both live inside Reconcile.
	situationID := claimOneDueSituation(t, rig.runtime, "crash-controller")

	if boundary == "l1_complete" || boundary == "l2_complete" || boundary == "transition_commit" {
		// Reconcile dispatches L1 at most once per call, so this fires at
		// most once — a single-buffered channel needs no drain guard.
		l1Done := make(chan struct{}, 1)
		rig.controller.SetBoundaryHookForTest(func(name string) error {
			if name == "l1_complete" {
				l1Done <- struct{}{}
			}
			return crashAt(boundary)(name)
		})
		err := rig.controller.Reconcile(ctx, situationID)
		if boundary == "l1_complete" {
			// l1_complete fires asynchronously; Reconcile itself returns
			// synchronously via the deterministic floor commit (which does
			// not wait on L1), so the harness must wait for the async
			// completion signal before treating the crash as having landed.
			if err != nil {
				t.Fatalf("reconcile: %v", err)
			}
			select {
			case <-l1Done:
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for l1_complete to fire")
			}
		} else if !errors.Is(err, errInjectedCrash) {
			t.Fatalf("reconcile err = %v, want the injected crash", err)
		}
		return
	}

	// slack_post_timeout, slack_coordinate_commit, root_edit, and
	// thread_reply all need at least one already-durable, already-delivered
	// root: round one runs clean (no hook), then the notification worker
	// delivers it for real.
	if err := rig.controller.Reconcile(ctx, situationID); err != nil {
		t.Fatalf("round 1 reconcile: %v", err)
	}
	if _, err := rig.notify.RunOnce(ctx); err != nil {
		t.Fatalf("round 1 notify: %v", err)
	}

	// slack_post_timeout and slack_coordinate_commit only need a second
	// pending intent to crash on; root_edit and (once a recurrence rung is
	// seeded) thread_reply need that second intent to be specifically a
	// root edit / thread reply, which the same second reconciliation round
	// against unchanged critical evidence already produces (a floor-driven
	// Situation's Assessment is always degraded, so it is never
	// "trustworthy" and a later pass against the same facts re-commits).
	if boundary == "thread_reply" {
		seedRecurrenceOccurrence(t, rig.st, situationID)
	}
	if err := advanceOneRound(ctx, rig); err != nil {
		t.Fatalf("round 2 reconcile: %v", err)
	}
	rig.notify.SetBoundaryHookForTest(crashAt(boundary))
	if _, err := rig.notify.RunOnce(ctx); err != nil && !errors.Is(err, errInjectedCrash) {
		t.Fatalf("round 2 notify: %v", err)
	}
}

// advanceOneRound re-claims and reconciles the same Situation a second time.
// A floor-driven Situation is never "trustworthy" (its Assessment's
// EvidenceQuality is always degraded), so a second reconciliation pass
// against unchanged critical evidence re-commits — producing a root_edit
// (and, once a recurrence rung is seeded, a thread_reply) against the
// already-published root, exactly like a real operator watching the same
// Situation update twice.
func advanceOneRound(ctx context.Context, rig *crashRig) error {
	// The first round's deterministic floor commit schedules its own next
	// checkpoint one FastCadence (60s) out, so a second round genuinely due
	// for reconciliation needs a claim instant past that — exactly what a
	// real second delivery's fresh due-reason union, or simply the wall
	// clock catching up, would also produce.
	future := time.Now().UTC().Add(2 * time.Minute)
	situationID := claimOneDueSituationCtx(ctx, rig.runtime, "crash-controller-2", future)
	if situationID == "" {
		return errors.New("no due situation to reconcile a second round against")
	}
	return rig.controller.Reconcile(ctx, situationID)
}

func claimOneDueSituation(t *testing.T, runtime *store.SituationRuntime, owner string) string {
	t.Helper()
	id := claimOneDueSituationCtx(context.Background(), runtime, owner, time.Now().UTC())
	if id == "" {
		t.Fatal("no due situation to claim")
	}
	return id
}

func claimOneDueSituationCtx(ctx context.Context, runtime *store.SituationRuntime, owner string, now time.Time) string {
	claims, err := runtime.ClaimDueSituations(ctx, owner, now, time.Minute, 1)
	if err != nil || len(claims) != 1 {
		return ""
	}
	return claims[0].SituationID
}

// runObservationOnce exercises the one production observation path that
// exists today — Runner.Execute against the real store_read reducer — as
// the honest substitute for the currently-unwired observation-persistence
// boundary (see the TestRestartAfterEveryBoundary doc comment).
func runObservationOnce(t *testing.T, st *store.Store) {
	t.Helper()
	sits, err := st.ListSituations(context.Background(), 1)
	if err != nil || len(sits) != 1 {
		t.Fatalf("list situations: %v (n=%d)", err, len(sits))
	}
	situationID := sits[0].ID
	catalog := observation.DefaultCatalog(connectors.Sources{Situations: st}.Adapters())
	runner := observation.NewRunner(catalog, 4, 2)
	now := time.Now().UTC()
	plan := observationmodel.Plan{
		Capability: observationmodel.CapabilityStoreRead, Scope: map[string]string{"situation_id": situationID},
		Parameters: json.RawMessage(`{"resource":"situation"}`), Start: now.Add(-time.Hour), End: now, Limit: 10,
		Why: "crash-boundary probe",
	}
	allowed := observation.Scope{"situation_id": {situationID}}
	if _, _, err := runner.Execute(context.Background(), []observationmodel.Plan{plan}, allowed); err != nil {
		t.Fatalf("execute observation plan: %v", err)
	}
}

// seedRecurrenceOccurrence seeds one recurrence-collapse occurrence row with
// a severity rung trigger directly against the real schema — the same
// production table the correlator's own occurrence-attach path writes, here
// seeded directly so the test does not need five real repeat deliveries to
// reach a real thread-reply-eligible recurrence context. Mirrors the direct
// seeding pattern internal/correlator's own crash_recovery_test.go already
// uses for prior-state setup.
func seedRecurrenceOccurrence(t *testing.T, st *store.Store, situationID string) {
	t.Helper()
	ctx := context.Background()
	var incidentID string
	if err := st.DB().QueryRowContext(ctx, `SELECT incident_id FROM situation_incidents WHERE situation_id = ? LIMIT 1`, situationID).Scan(&incidentID); err != nil {
		t.Fatalf("read situation incident: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO incident_occurrences (incident_id, occurred_at, last_seen, fingerprints_json, payload_json, trigger_kind)
		VALUES (?, ?, ?, '[]', '{}', 'severity')`, incidentID, now, now); err != nil {
		t.Fatalf("seed recurrence occurrence: %v", err)
	}
}

// --------------------------------------------------------------------------
// Recovery + invariants
// --------------------------------------------------------------------------

// runToQuiescence reopens the SQLite file (a real process restart does no
// less and no more) and drains every durable queue through the ordinary
// production workers until none of them find further work — the recovery
// half of every crash-boundary subtest.
func runToQuiescence(t *testing.T, dbPath string) {
	t.Helper()
	rig := buildCrashRig(t, dbPath, observeAssessor{})
	ctx := context.Background()

	// Step 1 of the spec's startup reconstruction order: recover every
	// abandoned lease a real crash left claimed. A synthetic future instant
	// stands in for the wall clock catching up to the lease deadline — a
	// real restart may happen seconds or hours later, but it never needs to
	// wait out the lease itself.
	future := time.Now().UTC().Add(10 * time.Minute)
	if _, err := rig.runtime.RecoverExpiredLeases(ctx, future); err != nil {
		t.Fatalf("recover expired leases: %v", err)
	}

	for round := 0; round < 8; round++ {
		progressed := false
		if err := rig.dispatch.RunOnce(ctx); err != nil {
			t.Fatalf("recovery dispatch: %v", err)
		}
		if applied, err := rig.inputs.RunOnce(ctx); err != nil {
			t.Fatalf("recovery inputs: %v", err)
		} else if applied > 0 {
			progressed = true
		}
		for {
			// Real current time here, deliberately not `future`: once a
			// round's reconciliation commits, it schedules its own next
			// checkpoint ~60s out (FastCadence), and claiming against
			// `future` would see it as perpetually due and loop forever.
			situationID := claimOneDueSituationCtx(ctx, rig.runtime, fmt.Sprintf("crash-recovery-%d", round), time.Now().UTC())
			if situationID == "" {
				break
			}
			progressed = true
			if err := rig.controller.Reconcile(ctx, situationID); err != nil {
				t.Fatalf("recovery reconcile: %v", err)
			}
		}
		if delivered, err := rig.notify.RunOnce(ctx); err != nil {
			t.Fatalf("recovery notify: %v", err)
		} else if delivered > 0 {
			progressed = true
		}
		if !progressed {
			return
		}
	}
	t.Fatal("recovery did not reach quiescence within the round budget")
}

// assertExactlyOnceInvariants asserts the durability guarantees the whole
// crash-boundary suite exists to lock: no lost accepted delivery, no
// duplicate ownership, no duplicate input version, no duplicate root, no
// reopened terminal Situation, and no missing durable intent.
func assertExactlyOnceInvariants(t *testing.T, dbPath, boundary string) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("reopen store for assertions: %v", err)
	}
	defer func() { _ = st.Close() }()
	db := st.DB()

	// No lost accepted delivery.
	assertCount(t, db, `SELECT COUNT(*) FROM alert_deliveries`, 1, "accepted deliveries")

	// No duplicate ownership: the one delivery belongs to exactly one Incident.
	assertCount(t, db, `SELECT COUNT(DISTINCT incident_id) FROM incident_alert_deliveries`, 1, "distinct delivery owners")

	// No duplicate input version / no phantom second Situation for the exact
	// group: correlation and reconstruction never produce more than one.
	assertCount(t, db, `SELECT COUNT(*) FROM situations WHERE group_key = 'service=crash-svc'`, 1, "situations for the exact group")

	// No duplicate root: at most one situation_root_create intent ever
	// exists for the Situation, regardless of how many times the process
	// restarted mid-delivery.
	var roots int
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM notification_intents
		WHERE subject_kind = 'situation' AND kind = 'situation_root_create'`).Scan(&roots); err != nil {
		t.Fatalf("count root-create intents: %v", err)
	}
	if boundary == "receiver_commit" || boundary == "correlation_commit" || boundary == "situation_input_commit" || boundary == "observation_commit" {
		// These boundaries crash before any reconciliation ever ran; a
		// critical delivery always earns its root once reconciliation
		// resumes after the restart.
		if roots != 1 {
			t.Fatalf("root-create intents = %d, want exactly 1 once recovery resumed reconciliation", roots)
		}
	} else if roots > 1 {
		t.Fatalf("root-create intents = %d, want at most 1", roots)
	}

	// No reopened terminal Situation and every notification intent lands in
	// a closed, valid status.
	var lifecycle string
	if err := db.QueryRowContext(ctx, `SELECT lifecycle FROM situations WHERE group_key = 'service=crash-svc'`).Scan(&lifecycle); err != nil {
		t.Fatalf("read situation lifecycle: %v", err)
	}
	if lifecycle != string(model.LifecycleActive) {
		t.Fatalf("lifecycle = %q, want active (this suite never drives lifecycle past active)", lifecycle)
	}

	rows, err := db.QueryContext(ctx, `SELECT status FROM notification_intents`)
	if err != nil {
		t.Fatalf("query notification intent statuses: %v", err)
	}
	defer func() { _ = rows.Close() }()
	validStatus := map[string]bool{"pending": true, "delivered": true, "failed": true, "withheld_by_operator_slack_floor": true}
	count := 0
	for rows.Next() {
		var status string
		if err := rows.Scan(&status); err != nil {
			t.Fatalf("scan notification intent status: %v", err)
		}
		if !validStatus[status] {
			t.Fatalf("notification intent carries an invalid status %q", status)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate notification intent statuses: %v", err)
	}
	// No missing durable intent: recovery must have produced at least the
	// one root every critical delivery earns, for every boundary that ever
	// reached reconciliation.
	if boundary != "l2_complete" && count == 0 {
		t.Fatal("no durable notification intent exists after recovery; a promised root was lost")
	}
}

func assertCount(t *testing.T, db *sql.DB, query string, want int, label string) {
	t.Helper()
	var got int
	if err := db.QueryRowContext(context.Background(), query).Scan(&got); err != nil {
		t.Fatalf("count %s: %v", label, err)
	}
	if got != want {
		t.Fatalf("%s = %d, want %d", label, got, want)
	}
}
