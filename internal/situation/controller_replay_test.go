// SPDX-License-Identifier: FSL-1.1-ALv2

// package situation_test (external test package), not package situation:
// this file drives a real *store.Store, a real ingress.Server/httptest host,
// the real Correlator dispatch worker, and the real production
// foundation/controller/Triage assembly (situation.NewInputWorker,
// situation.NewReconstructor, situation.NewControllerWorker,
// situation.NewTriageWorker, situation.NewController) end to end —
// internal/store already imports internal/situation for the controller's
// transport-neutral types, so an internal (same-package) test file here that
// also imported internal/store would create the exact "import cycle not
// allowed in test" Go forbids for a package's own test files (see
// reconstruct_test.go's own header comment for the same constraint, already
// hit and documented by Task 8).
//
// Task 10, brief item 1-2: one file-backed replay fixture entering through
// real Receiver HTTP input — never a hand-seeded Situation, fact, Assessment,
// or Triage envelope — with eight crash-boundary subtests, each closing and
// reopening the SAME on-disk database file and running the real startup
// recovery/replay sequence (situation.Reconstructor.Run, plus the exact
// store.Store.BackfillUpgradedIncidentTriageSchedule/
// RecoverInterruptedAssessmentCalls/RecoverExpiredIncidentTriageAttempts/
// ExhaustOverdueUnclaimedIncidentTriage sequence
// cmd/alertint/situation_controller.go's own RecoverAndBackfill uses) before
// asserting convergence. Every fake in this file is a deterministic L1/L2
// (Acute Triage analyzer / Situation Assessment) client that counts calls
// and returns typed outcomes — every store, worker, and pipeline component
// around it is the real, unmodified production implementation.

package situation_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/correlator"
	"github.com/alertint/alertint-agent/internal/ingress"
	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

const replayToken = "replay-test-token" //nolint:gosec // test-only bearer token literal, never a real credential

// ----------------------------------------------------------------------
// Deterministic logical clock.
//
// Starts pinned to real wall-clock time (not a fixed historical date) so
// the durable next_assessment_at/due timestamps InputWorker/DispatchWorker
// compute internally using their OWN default wall clock (this file never
// overrides their Now — matching internal/ingress/foundation_integration_
// test.go's own established convention) are never accidentally in the
// future relative to this file's own claim/reconcile clock. Every
// time-sensitive step below advances it forward by a healthy margin before
// relying on anything being "due" — see advanceMargin's own doc comment.
// ----------------------------------------------------------------------

type replayClock struct {
	mu  sync.Mutex
	now time.Time
}

func newReplayClock(start time.Time) *replayClock { return &replayClock{now: start} }

func (c *replayClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *replayClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// advanceMargin is added before every claim/convergence pass — comfortably
// larger than the microsecond-scale gap between an input worker's own
// wall-clock write and this file's next logical-clock read, so a due check
// never spuriously misses by a hair.
const advanceMargin = time.Minute

// restartMargin is added after every close/reopen "restart" — comfortably
// larger than every bounded schedule this package can produce on its own
// (cadence tiers <= 15m, controller retry backoff <= 5m, Triage backoff
// <= 32m) so nothing scheduled before the simulated crash can still be
// legitimately "not yet due" once replay resumes, without ever approaching
// the separate one-hour ADR-0045 startup horizon this same replay pass also
// exercises (ExhaustOverdueUnclaimedIncidentTriage).
const restartMargin = 35 * time.Minute

// longClassMargin (Task 10 review Finding #2) advances the fixture's clock
// far enough past DurationClass's own >= 1h "long" lower bound
// (snapshot.go's DurationClassLong) that the owning Situation's elapsed
// duration is durably inside DurationClassLong before the convergence pass
// whose resulting Assessment a later idempotent-reconverge check
// (assertIdempotentReconverge, or boundary 6's own manual re-run) re-checks.
// "long" is the only duration class with no upper bound, so once elapsed
// crosses into it there is no further class boundary a later
// slowCadenceCheckpointMargin advance could ever cross — unlike "short"
// ([1m, 15m), a 14-minute span narrower than the 15-minute slow-cadence
// checkpoint delay itself) or "medium" ([15m, 1h), where the natural
// accumulation of this file's own advanceMargin/restartMargin advances
// leaves too little headroom to safely predict which side of the 1h
// boundary a further +15m checkpoint advance lands on. Crossing a duration
// class boundary changes MaterialFactHash (and so AssessmentBasisHash),
// which makes RevalidateReuse's own basis-unchanged precondition fail and
// forces a FRESH, L2-calling derivation instead of exercising the reuse
// path idempotent reconvergence exists to prove — see
// assertIdempotentReconverge's own doc comment. This fixture's own alerts
// carry no critical severity and no prior-Situation history, so none of
// EligibleReasons' duration-sensitive predicates (durationOutlierEligible
// needs >= 5 prior comparable Situations; terminalUncertaintyEligible is an
// unconditional stub — see reasons.go) or lifecycle.go's own
// ObservationDeadlineAt (2h/24h/7d by class — 7 days once "long") ever
// engage regardless of which class this margin lands in, so aging into
// "long" is safe against every other duration-gated behavior in this
// package.
const longClassMargin = 90 * time.Minute

// slowCadenceCheckpointMargin (Task 10 review Finding #2) comfortably
// exceeds CadenceSlow's own +15m next_assessment_at checkpoint
// (assessment.go's cadenceSlowInterval, the tier DeriveCadence returns for
// attention=observe once Triage is no longer in_flight — the state every
// affected subtest's committed Assessment reaches) so a reconverge pass
// genuinely finds the checkpoint already due, instead of silently finding
// nothing due at all. Before this fix, assertIdempotentReconverge's re-run
// (and boundary 6's own separate re-run) only ever advanced the clock by
// convergeAll's own per-round advanceMargin (1 minute) and returned the
// instant one round claimed nothing — which a slow-cadence checkpoint 15
// minutes out never is, so every "no new L2 call"/"hashes unchanged"
// assertion downstream held vacuously: zero work ever executed, not
// "reuse happened with zero new calls." Every Situation this margin is
// applied to has already been aged into DurationClassLong by longClassMargin
// before its own first tested convergence, so this additional advance can
// never cross a duration-class boundary — see longClassMargin's own doc
// comment.
const slowCadenceCheckpointMargin = 20 * time.Minute

// ----------------------------------------------------------------------
// replayFixture: one file-backed Store behind a real ingress.Server,
// reachable over real HTTP, plus the shared logical clock and owner prefix
// every worker/direct call in one subtest uses.
// ----------------------------------------------------------------------

type replayFixture struct {
	t     *testing.T
	ctx   context.Context //nolint:containedctx // test fixture only: ctx is always context.Background(), threaded through every helper method below rather than repeated as a parameter on all of them; never cancelled or deadline-bound in a way call-site plumbing would change.
	path  string
	st    *store.Store
	srv   *httptest.Server
	clock *replayClock
	owner string
}

func newReplayFixture(t *testing.T, owner string) *replayFixture {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "replay.db")
	st, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	f := &replayFixture{t: t, ctx: ctx, path: path, st: st, clock: newReplayClock(time.Now().UTC()), owner: owner}
	f.srv = f.newHost(st)
	return f
}

func (f *replayFixture) newHost(st *store.Store) *httptest.Server {
	f.t.Helper()
	host, err := ingress.New(ingress.Options{
		Store:     st,
		Auditor:   audit.New(st.DB()),
		Receivers: []ingress.Receiver{ingress.NewAlertReceiver(st, replayToken, nil, nil)},
	})
	if err != nil {
		f.t.Fatalf("ingress.New: %v", err)
	}
	return httptest.NewServer(host.Handler())
}

// postGroup POSTs one firing Alertmanager v4 alert over real HTTP through
// the real Receiver — the fixture's only inbound entry point, matching this
// task's "enters through real Receiver HTTP input" requirement.
func (f *replayFixture) postGroup(group, alertname, fingerprint string) {
	f.t.Helper()
	payload := ingress.AlertmanagerPayload{
		Version:     "4",
		Status:      "firing",
		GroupLabels: map[string]string{"group": group},
		Alerts: []ingress.AlertmanagerAlert{{
			Status:      "firing",
			Labels:      map[string]string{"alertname": alertname, "group": group},
			Annotations: map[string]string{},
			StartsAt:    f.clock.Now(),
			Fingerprint: fingerprint,
		}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		f.t.Fatalf("marshal alertmanager payload: %v", err)
	}
	req, err := http.NewRequestWithContext(f.ctx, http.MethodPost, f.srv.URL+"/webhook/alertmanager", bytes.NewReader(body))
	if err != nil {
		f.t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+replayToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		f.t.Fatalf("post alert: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		f.t.Fatalf("post alert status = %d, want 204", resp.StatusCode)
	}
}

// drainFoundation drains the delivery-dispatch and Situation-input outboxes
// once each — Plan 1's own durable acceptance/correlation/input-application
// path, matching internal/ingress/foundation_integration_test.go's own
// established pattern. It never touches the controller or Triage worker.
func (f *replayFixture) drainFoundation() {
	f.t.Helper()
	cor := correlator.New(correlator.Config{WindowSeconds: 60}, f.st, nil, nil)
	dispatch := correlator.NewDispatchWorker(f.st, cor, correlator.WorkerConfig{Owner: f.owner + ":dispatch"}, nil)
	inputs := situation.NewInputWorker(f.st, situation.WorkerConfig{Owner: f.owner + ":input"}, nil)
	if _, err := dispatch.Drain(f.ctx); err != nil {
		f.t.Fatalf("dispatch drain: %v", err)
	}
	if _, err := inputs.Drain(f.ctx); err != nil {
		f.t.Fatalf("input drain: %v", err)
	}
}

// markReady transitions incidentID collecting -> ready via the real
// store.MarkIncidentReadyWithSituationInput primitive (the same transition
// the Correlator's own fixed-window flush eventually performs — this just
// takes it deterministically, without a real wall-clock wait), then drains
// its own queued Situation input.
func (f *replayFixture) markReady(incidentID string) {
	f.t.Helper()
	if err := f.st.MarkIncidentReadyWithSituationInput(f.ctx, incidentID, f.clock.Now()); err != nil {
		f.t.Fatalf("mark incident ready: %v", err)
	}
	f.drainFoundation()
}

func (f *replayFixture) soleIncidentID() string {
	f.t.Helper()
	return scalarString(f.t, f.st, `SELECT id FROM incidents ORDER BY created_at ASC LIMIT 1`)
}

func (f *replayFixture) soleSituationID() string {
	f.t.Helper()
	return scalarString(f.t, f.st, `SELECT id FROM situations ORDER BY created_at ASC LIMIT 1`)
}

// setupDueSituation POSTs one alert and drains it into a fresh, active
// Situation with a due reason and no controller cycle ever run against it —
// the shared starting point for the boundary-1-through-5 subtests.
func (f *replayFixture) setupDueSituation(group, alertname, fingerprint string) (situationID string) {
	f.t.Helper()
	f.postGroup(group, alertname, fingerprint)
	f.drainFoundation()
	return f.soleSituationID()
}

// setupReadyIncidentWithRequestedTriage boots f all the way through: POST ->
// foundation drain -> mark ready -> one clean, uncrashed controller
// convergence (a real accepting L2 client) so the owning Situation gets its
// first authoritative Assessment and DecideTriage's own
// DecisionReasonNoTrustworthyAssessment request decision moves the
// Incident's durable schedule from awaiting_decision to pending, due now.
// Shared by the boundary-6/7 (Triage-attempt) subtests.
func (f *replayFixture) setupReadyIncidentWithRequestedTriage(group, alertname, fingerprint string) (incidentID string) {
	f.t.Helper()
	f.postGroup(group, alertname, fingerprint)
	f.drainFoundation()
	incidentID = f.soleIncidentID()
	f.markReady(incidentID)
	f.clock.Advance(advanceMargin)
	// One single controller drain pass at this fixed "now" — not
	// convergeControllerOnly's own repeated-clock-advance loop, which
	// deliberately excludes the Triage worker: once this cycle commits its
	// "request" decision (Triage phase awaiting_decision -> pending), the
	// controller's own checkpoint legitimately wants to check back on
	// Triage's progress soon (it is, correctly, still outstanding), so a
	// loop that keeps advancing the clock and re-polling would never see
	// dispatch/input/controller all report zero — there is nothing to
	// converge to without the Triage worker this setup helper deliberately
	// does not run yet. One Drain pass at one fixed instant is exactly what
	// "one clean, uncrashed controller convergence" needs here: reconcile
	// whatever is due right now to quiescence, then stop.
	f.oneControllerDrainPass(newAcceptingL2Client())
	if phase := scalarString(f.t, f.st, `SELECT phase FROM incident_triage WHERE incident_id = ?`, incidentID); phase != "pending" {
		f.t.Fatalf("triage phase after the setup controller convergence = %q, want pending", phase)
	}
	return incidentID
}

// close simulates a process crash/shutdown: close the HTTP host and the
// Store's own SQLite connection. Whatever committed to disk before this
// point survives; nothing else does.
func (f *replayFixture) close() {
	f.t.Helper()
	f.srv.Close()
	if err := f.st.Close(); err != nil {
		f.t.Fatalf("close store: %v", err)
	}
}

// reopen simulates a restart: open a fresh *store.Store against the SAME
// on-disk file — the literal "reopen the database" this task's brief names
// for every one of the eight crash-boundary subtests.
func (f *replayFixture) reopen() {
	f.t.Helper()
	st, err := store.Open(f.ctx, f.path)
	if err != nil {
		f.t.Fatalf("reopen store: %v", err)
	}
	f.t.Cleanup(func() { _ = st.Close() })
	f.st = st
	f.srv = f.newHost(st)
	f.t.Cleanup(f.srv.Close)
}

// restart is the shared close-reopen-advance sequence every crash-boundary
// subtest runs once its crash is simulated, before running normal
// startup/replay.
func (f *replayFixture) restart() {
	f.t.Helper()
	f.close()
	f.reopen()
	f.clock.Advance(restartMargin)
}

// ageIntoLongDurationClass advances the fixture's clock by longClassMargin —
// see that constant's own doc comment for why "long" is the only duration
// class this fixture can safely age a Situation into ahead of a later
// idempotent-reconverge check without risking a class-boundary crossing.
func (f *replayFixture) ageIntoLongDurationClass() {
	f.t.Helper()
	f.clock.Advance(longClassMargin)
}

// replayBootReport is bootReplay's own report, so a subtest that wants extra
// rigor (e.g. "exactly one orphaned assessment call was recovered") can
// assert on it directly instead of only on the eventual converged state.
type replayBootReport struct {
	Reconstruction                situation.Reconstruction
	AssessmentCallsRecovered      int
	TriageAttemptsRecovered       int
	TriageBackfilled              int
	TriageStartupHorizonExhausted int
}

// bootReplay runs the exact real startup order cmd/alertint's own
// foundationSequence + controllerRuntime.RecoverAndBackfill uses — every
// step here is an unmodified production primitive, called in the same
// order: recover expired foundation leases, drain queued deliveries/inputs,
// represent unowned Incidents (situation.Reconstructor.Run); then the
// controller/Triage recovery/backfill pass
// (store.Store.BackfillUpgradedIncidentTriageSchedule,
// RecoverInterruptedAssessmentCalls, RecoverExpiredIncidentTriageAttempts,
// ExhaustOverdueUnclaimedIncidentTriage — see
// cmd/alertint/situation_controller.go's own RecoverAndBackfill, which this
// mirrors exactly since internal/situation's own test package cannot import
// package main). Call once per restart, before any worker claims new work.
func (f *replayFixture) bootReplay() replayBootReport {
	f.t.Helper()
	cor := correlator.New(correlator.Config{WindowSeconds: 60}, f.st, nil, nil)
	dispatch := correlator.NewDispatchWorker(f.st, cor, correlator.WorkerConfig{Owner: f.owner + ":dispatch"}, nil)
	inputs := situation.NewInputWorker(f.st, situation.WorkerConfig{Owner: f.owner + ":input"}, nil)
	r := situation.NewReconstructor(f.st, f.clock.Now).WithReplay(dispatch, inputs)
	report, err := r.Run(f.ctx)
	if err != nil {
		f.t.Fatalf("reconstruct: %v", err)
	}

	now := f.clock.Now()
	backfilled, err := f.st.BackfillUpgradedIncidentTriageSchedule(f.ctx, now)
	if err != nil {
		f.t.Fatalf("backfill upgraded incident triage schedule: %v", err)
	}
	callsRecovered, err := f.st.RecoverInterruptedAssessmentCalls(f.ctx, now)
	if err != nil {
		f.t.Fatalf("recover interrupted assessment calls: %v", err)
	}
	attemptsRecovered, err := f.st.RecoverExpiredIncidentTriageAttempts(f.ctx, now)
	if err != nil {
		f.t.Fatalf("recover expired incident triage attempts: %v", err)
	}
	exhausted, err := f.st.ExhaustOverdueUnclaimedIncidentTriage(f.ctx, now, time.Hour)
	if err != nil {
		f.t.Fatalf("exhaust overdue unclaimed incident triage: %v", err)
	}
	return replayBootReport{
		Reconstruction:                report,
		AssessmentCallsRecovered:      callsRecovered,
		TriageAttemptsRecovered:       attemptsRecovered,
		TriageBackfilled:              backfilled,
		TriageStartupHorizonExhausted: len(exhausted),
	}
}

// oneControllerDrainPass drains dispatch/input/controller (never Triage)
// ONCE, at the current fixed clock value — no outer clock-advancing loop.
// cw.Drain's own internal loop already repeats "claim + reconcile" until
// nothing is due AT THIS SAME "now" (every checkpoint this package computes
// is strictly in the future relative to the "now" it was derived from), so
// this reaches real quiescence for whatever is due right now without ever
// needing to manufacture new due-ness by advancing the clock. Used by the
// setup phase of the Triage-attempt subtests, which need a
// requested-but-not-yet-claimed Triage schedule without the Triage worker
// itself running yet — see setupReadyIncidentWithRequestedTriage's own
// call-site comment for why a repeated-clock-advance loop is the wrong tool
// here specifically (an outstanding Triage schedule legitimately keeps
// scheduling near-term controller check-ins on its own).
func (f *replayFixture) oneControllerDrainPass(client situation.AssessmentClient) {
	f.t.Helper()
	auditor := audit.New(f.st.DB())
	cor := correlator.New(correlator.Config{WindowSeconds: 60}, f.st, nil, nil)
	dispatch := correlator.NewDispatchWorker(f.st, cor, correlator.WorkerConfig{Owner: f.owner + ":dispatch"}, nil)
	inputs := situation.NewInputWorker(f.st, situation.WorkerConfig{Owner: f.owner + ":input"}, nil)
	if _, err := dispatch.Drain(f.ctx); err != nil {
		f.t.Fatalf("dispatch drain: %v", err)
	}
	if _, err := inputs.Drain(f.ctx); err != nil {
		f.t.Fatalf("input drain: %v", err)
	}

	cw := situation.NewControllerWorker(f.st, f.st, client, situation.ControllerConfig{},
		situation.ControllerWorkerConfig{Owner: f.owner + ":controller", Now: f.clock.Now}, f.clock.Now, auditor, nil)
	if _, err := cw.Drain(f.ctx); err != nil {
		f.t.Fatalf("controller drain: %v", err)
	}
	f.assertNoReconcileFailed()
}

// assertNoReconcileFailed asserts no controller reconcile cycle has ever
// left an error class recorded on any Situation in this fixture's own
// on-disk database (Task 10 review Finding #1's systemic guard).
// ControllerWorker.processOne (controller_worker.go) swallows a failed
// Reconcile into a log line and a bounded typed retry/backoff rather than
// propagating the error to anything a caller observes — so a regression
// that makes reconcile fail (e.g. reintroducing the exact stale
// fact-identity collision factIdentityWithContent fixes) would otherwise
// only ever surface, if at all, as "a later cycle eventually succeeded
// anyway": convergeAll's own quiescence loop keeps calling Drain regardless
// of a failed attempt, and a later successful commit clears
// last_error_class back to NULL (controller.go's commitResult), so checking
// this only once at the very end of a convergence pass would itself risk
// missing a mid-run failure that got silently retried away — never a red
// assertion unless something checks last_error_class after EVERY round, not
// just the last one. Called after every controller drain in both
// convergence helpers below.
func (f *replayFixture) assertNoReconcileFailed() {
	f.t.Helper()
	n := scalarInt(f.t, f.st, `SELECT COUNT(*) FROM situations WHERE last_error_class IS NOT NULL`)
	if n == 0 {
		return
	}
	detail := scalarString(f.t, f.st,
		`SELECT group_concat(id || '=' || last_error_class) FROM situations WHERE last_error_class IS NOT NULL`)
	f.t.Fatalf("%d situation(s) carry a non-nil last_error_class, want 0 (a reconcile cycle silently failed and was swallowed): %s", n, detail)
}

// convergeTotals is convergeAll's own tally of work items each drain
// component actually claimed and handled, summed across every round it took
// to reach quiescence — Task 10 review Finding #2's fix: assertIdempotentReconverge
// (and boundary 6's own manual re-run) assert Controller > 0 on the totals
// from their own re-run to prove a REAL second controller reconcile cycle
// actually executed, not that nothing was ever due — the original bug: the
// re-run's clock never reached the committed next_assessment_at checkpoint,
// so every round claimed zero work and every "no new L2 call"/"hashes
// unchanged" assertion downstream held vacuously.
type convergeTotals struct {
	Dispatch, Input, Controller, Triage int
}

// convergeAll drains dispatch/input/controller/Triage together, repeating
// until one full round handles nothing at all — production's own "drain to
// quiescence" shape (foundationRuntime.Drain/controllerRuntime.Drain), so a
// Triage completion's own fresh Situation input still gets a chance to feed
// back into another controller round within the same call. Returns the
// summed per-component totals across every round, so a caller that needs to
// prove a convergence pass genuinely did work (not just that it reached
// quiescence) can assert on them directly — see convergeTotals' own doc
// comment.
func (f *replayFixture) convergeAll(client situation.AssessmentClient, analyzer situation.AcuteAnalyzer, after situation.AfterCommitter, exhaustion situation.ExhaustionNotifier) convergeTotals {
	f.t.Helper()
	auditor := audit.New(f.st.DB())
	triageStore := &replayTriageStoreAdapter{f.st}
	triageLister := &replayTriageListerAdapter{f.st}
	var totals convergeTotals
	for round := 0; round < 8; round++ {
		f.clock.Advance(advanceMargin)
		cor := correlator.New(correlator.Config{WindowSeconds: 60}, f.st, nil, nil)
		dispatch := correlator.NewDispatchWorker(f.st, cor, correlator.WorkerConfig{Owner: f.owner + ":dispatch"}, nil)
		inputs := situation.NewInputWorker(f.st, situation.WorkerConfig{Owner: f.owner + ":input"}, nil)
		nd, err := dispatch.Drain(f.ctx)
		if err != nil {
			f.t.Fatalf("dispatch drain: %v", err)
		}
		ni, err := inputs.Drain(f.ctx)
		if err != nil {
			f.t.Fatalf("input drain: %v", err)
		}

		cw := situation.NewControllerWorker(f.st, f.st, client, situation.ControllerConfig{},
			situation.ControllerWorkerConfig{Owner: f.owner + ":controller", Now: f.clock.Now}, f.clock.Now, auditor, nil)
		nc, err := cw.Drain(f.ctx)
		if err != nil {
			f.t.Fatalf("controller drain: %v", err)
		}
		f.assertNoReconcileFailed()

		tw := situation.NewTriageWorker(triageStore, triageLister, analyzer, after, exhaustion,
			situation.TriageWorkerConfig{Owner: f.owner + ":triage", Now: f.clock.Now}, nil)
		tw.SetAuditSink(auditor)
		nt, err := tw.Drain(f.ctx)
		if err != nil {
			f.t.Fatalf("triage drain: %v", err)
		}

		totals.Dispatch += nd
		totals.Input += ni
		totals.Controller += nc
		totals.Triage += nt

		if nd+ni+nc+nt == 0 {
			return totals
		}
	}
	f.t.Fatal("convergeAll: did not reach quiescence within bounded rounds")
	return totals
}

// ----------------------------------------------------------------------
// Triage store/lister adapters — a verbatim replica of
// cmd/alertint/situation_controller.go's own unexported
// triageAttemptStoreAdapter/triageScheduleListerAdapter/mapTriageStoreError
// (package main, unreachable from this test package). *store.Store already
// satisfies situation.TriageAttemptStore's other five methods directly via
// embedding — only Claim/Complete need this real shim, exactly as that
// file's own header comment explains.
// ----------------------------------------------------------------------

type replayTriageStoreAdapter struct{ *store.Store }

func (a *replayTriageStoreAdapter) ClaimIncidentTriageAttempt(ctx context.Context, incidentID, owner string, now time.Time, lease time.Duration) (situation.TriageAttemptClaim, error) {
	claimed, err := a.Store.ClaimIncidentTriageAttempt(ctx, incidentID, owner, now, lease)
	if err != nil {
		return situation.TriageAttemptClaim{}, mapReplayTriageStoreError(err)
	}
	return situation.TriageAttemptClaim{
		AttemptID:            claimed.AttemptID,
		IncidentID:           claimed.IncidentID,
		AttemptNumber:        claimed.AttemptNumber,
		SituationID:          claimed.SituationID,
		DecisionInputVersion: claimed.DecisionInputVersion,
		MembershipDigest:     claimed.MembershipDigest,
		IncidentInputDigest:  claimed.IncidentInputDigest,
		MemberDeliveryIDs:    claimed.MemberDeliveryIDs,
		StartedAt:            claimed.StartedAt,
		LeaseOwner:           claimed.LeaseOwner,
		LeaseExpiresAt:       claimed.LeaseExpiresAt,
		ClaimToken:           claimed.ClaimToken,
	}, nil
}

func (a *replayTriageStoreAdapter) CompleteIncidentTriageAttempt(ctx context.Context, attemptID, incidentID string, finding situation.TriageFindingInput, now time.Time) (situation.TriageCompletionOutcome, error) {
	result, err := a.Store.CompleteIncidentTriageAttempt(ctx, attemptID, incidentID, store.TriageFinding{
		OutputJSON: finding.OutputJSON, Summary: finding.Summary, RootCause: finding.RootCause,
		Confidence: finding.Confidence, EnrichmentJSON: finding.EnrichmentJSON, EvidencePackDigest: finding.EvidencePackDigest,
	}, now)
	if err != nil {
		return "", mapReplayTriageStoreError(err)
	}
	return situation.TriageCompletionOutcome(result.Outcome), nil
}

func mapReplayTriageStoreError(err error) error {
	switch {
	case errors.Is(err, store.ErrTriageNotDue):
		return situation.ErrTriageAttemptNotDue
	case errors.Is(err, store.ErrTriageNotDecided):
		return situation.ErrTriageAttemptNotDecided
	case errors.Is(err, store.ErrTriageAttemptLeaseLost):
		return situation.ErrTriageAttemptLeaseLost
	case errors.Is(err, store.ErrTriageAttemptCompletedDifferently):
		return situation.ErrTriageAttemptCompletedDifferently
	default:
		return err
	}
}

type replayTriageListerAdapter struct{ *store.Store }

func (a *replayTriageListerAdapter) ListDueIncidentTriage(ctx context.Context, now time.Time) ([]string, error) {
	due, err := a.Store.ListDueIncidentTriage(ctx, now)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(due))
	for _, d := range due {
		ids = append(ids, d.IncidentID)
	}
	return ids, nil
}

// ----------------------------------------------------------------------
// Query helpers.
// ----------------------------------------------------------------------

func scalarString(t *testing.T, st *store.Store, q string, args ...any) string {
	t.Helper()
	var s string
	if err := st.DB().QueryRowContext(context.Background(), q, args...).Scan(&s); err != nil {
		t.Fatalf("scalar string query %q: %v", q, err)
	}
	return s
}

func scalarNullableString(t *testing.T, st *store.Store, q string, args ...any) string {
	t.Helper()
	var s sql.NullString
	if err := st.DB().QueryRowContext(context.Background(), q, args...).Scan(&s); err != nil {
		t.Fatalf("scalar nullable string query %q: %v", q, err)
	}
	return s.String
}

func scalarInt(t *testing.T, st *store.Store, q string, args ...any) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("scalar int query %q: %v", q, err)
	}
	return n
}

type assessmentIdentity struct {
	AssessmentID, MaterialFactHash, BasisHash string
}

func readAssessmentIdentity(t *testing.T, st *store.Store, situationID string) assessmentIdentity {
	t.Helper()
	var id, mfh, bh sql.NullString
	err := st.DB().QueryRowContext(context.Background(),
		`SELECT current_assessment_id, current_material_fact_hash, current_assessment_basis_hash FROM situations WHERE id = ?`,
		situationID).Scan(&id, &mfh, &bh)
	if err != nil {
		t.Fatalf("read assessment identity: %v", err)
	}
	return assessmentIdentity{AssessmentID: id.String, MaterialFactHash: mfh.String, BasisHash: bh.String}
}

// assertOneCurrentAssessment asserts situationID converged to exactly one
// current, authoritative Assessment.
func assertOneCurrentAssessment(t *testing.T, st *store.Store, situationID string) assessmentIdentity {
	t.Helper()
	id := readAssessmentIdentity(t, st, situationID)
	if id.AssessmentID == "" {
		t.Fatal("current_assessment_id is empty after convergence, want exactly one current Assessment")
	}
	if id.MaterialFactHash == "" || id.BasisHash == "" {
		t.Fatalf("current hashes after convergence = %+v, want both populated", id)
	}
	n := scalarInt(t, st, `SELECT COUNT(*) FROM situation_assessment_attempts WHERE situation_id = ? AND status = 'authoritative'`, situationID)
	if n == 0 {
		t.Fatal("no authoritative situation_assessment_attempts row after convergence")
	}
	return id
}

// assertL2CallCeiling asserts situationID never exceeded the spec's own L2
// dispatch-slot ceiling across every work attempt it has consumed:
// max_l2_calls_per_attempt (default 2) times max_work_attempts_per_input
// (default 5).
func assertL2CallCeiling(t *testing.T, st *store.Store, situationID string) {
	t.Helper()
	n := scalarInt(t, st, `SELECT COUNT(*) FROM situation_assessment_calls WHERE situation_id = ?`, situationID)
	const maxPerAttempt, maxAttempts = 2, 5
	if n > maxPerAttempt*maxAttempts {
		t.Fatalf("situation_assessment_calls rows = %d, want <= %d (%d work attempts * %d dispatch slots)",
			n, maxPerAttempt*maxAttempts, maxAttempts, maxPerAttempt)
	}
}

// assertIdempotentReconverge re-runs convergeAll with the SAME (call-
// counting) client/analyzer/afterCommit and asserts a genuine reuse cycle
// happened: no new L2 call, no new Analyze call, both hashes byte-identical,
// and the reused commit's own derivation is revalidated_reuse — "stable
// hashes", "no repeated Finding", and "unchanged bases reuse reasoning with
// zero model calls" in one assertion. The caller's Situation must already be
// aged into DurationClassLong (replayFixture.ageIntoLongDurationClass,
// called before its own first tested convergence) — this advances the clock
// PAST the committed next_assessment_at checkpoint
// (slowCadenceCheckpointMargin: see its own doc comment) before
// reconverging, so this genuinely exercises a second controller reconcile
// cycle (asserted via the returned totals' Controller count) rather than
// proving nothing, because nothing was ever due (Task 10 review Finding #2).
//
// current_assessment_id is deliberately NOT asserted stable: a reuse commit
// still writes its own new authoritative situation_assessment_attempts row
// (never repointing the prior one) — internal/store/situation_controller_
// reconcile_test.go's own TestControllerReconcileEndToEndReuseCommitsAgainstRealSchema
// already pins this exact production behavior ("reuse must still write a
// NEW authoritative attempt row, not just repoint the existing one"). An
// earlier version of this assertion required current_assessment_id to stay
// byte-identical too; that requirement was never actually exercised before
// this fix (Finding #2's own bug meant zero reconciles ever ran here) and
// turned out to contradict that already-established, deliberately tested
// contract the moment a real second cycle finally ran — corrected here to
// check identity where production actually promises stability (the hashes)
// and check for a fresh, correctly-derived reuse attempt where it does not.
func assertIdempotentReconverge(f *replayFixture, situationID string, client *scriptedL2Client, analyzer *scriptedAnalyzer, after *countingAfterCommitter) {
	f.t.Helper()
	beforeL2, beforeAnalyze := client.callCount(), analyzer.callCount()
	before := readAssessmentIdentity(f.t, f.st, situationID)

	f.clock.Advance(slowCadenceCheckpointMargin)
	totals := f.convergeAll(client, analyzer, after, nil)
	if totals.Controller == 0 {
		f.t.Fatal("idempotent reconverge: controller drain claimed 0 situations even after advancing past the committed " +
			"next_assessment_at checkpoint, want > 0 — a real second reconcile cycle must actually run, or every assertion " +
			"below (no new L2 call, unchanged hashes) is vacuously true rather than proving reuse")
	}

	if got := client.callCount(); got != beforeL2 {
		f.t.Fatalf("L2 calls after an idempotent reconverge = %d, want unchanged %d (unchanged basis must reuse reasoning with zero model calls)", got, beforeL2)
	}
	if got := analyzer.callCount(); got != beforeAnalyze {
		f.t.Fatalf("Analyze calls after an idempotent reconverge = %d, want unchanged %d (no repeated Finding)", got, beforeAnalyze)
	}
	after2 := readAssessmentIdentity(f.t, f.st, situationID)
	if after2.MaterialFactHash != before.MaterialFactHash || after2.BasisHash != before.BasisHash {
		f.t.Fatalf("assessment hashes changed on an idempotent reconverge: %+v -> %+v (hashes must be stable)", before, after2)
	}
	if after2.AssessmentID == before.AssessmentID {
		f.t.Fatalf("current_assessment_id unchanged after a genuine second reconcile cycle (controller claimed %d situations) — "+
			"a reuse commit still mints its own new authoritative attempt row (see this function's own doc comment)", totals.Controller)
	}
	if derivation := scalarString(f.t, f.st, `SELECT derivation FROM situation_assessment_attempts WHERE id = ?`, after2.AssessmentID); derivation != string(situationmodel.DerivationRevalidatedReuse) {
		f.t.Fatalf("reconverged attempt %s derivation = %q, want %q", after2.AssessmentID, derivation, situationmodel.DerivationRevalidatedReuse)
	}
}

// ----------------------------------------------------------------------
// Deterministic fake L2 (Situation Assessment) client.
// ----------------------------------------------------------------------

type scriptedL2Client struct {
	mu    sync.Mutex
	calls int
	fn    func(callNumber int) (llm.OneShotCompletion, error)
}

func (c *scriptedL2Client) CompleteOnce(_ context.Context, _ string, _ llm.Prompt, _ []string) (llm.OneShotCompletion, error) {
	c.mu.Lock()
	c.calls++
	n := c.calls
	c.mu.Unlock()
	return c.fn(n)
}

func (c *scriptedL2Client) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// acceptedOneShot builds one schema-valid, accepted (non-floor, non-urgent)
// model.AssessmentProposal response — the exact shape
// internal/store/situation_controller_reconcile_test.go's own
// acceptedProposalResponse uses for Task 8's own real-Store Reconcile
// tests.
func acceptedOneShot() llm.OneShotCompletion {
	p := situationmodel.AssessmentProposal{
		SchemaVersion: situationmodel.AssessmentSchemaVersion,
		Persistence:   situationmodel.PersistenceSustained,
		Impact:        situationmodel.ImpactSuspected,
		Novelty:       situationmodel.NoveltyFamiliar,
		Causality:     situationmodel.CausalityCorrelated,
		Attention:     situationmodel.AttentionObserve,
	}
	raw, err := json.Marshal(p)
	if err != nil {
		panic(err)
	}
	return llm.OneShotCompletion{
		Completion:     llm.Completion{Raw: raw, Model: "replay-test-model", Latency: 5 * time.Millisecond},
		RequestStarted: llm.RequestStartStatusTrue,
	}
}

func newAcceptingL2Client() *scriptedL2Client {
	return &scriptedL2Client{fn: func(int) (llm.OneShotCompletion, error) { return acceptedOneShot(), nil }}
}

// unreachableL2Client fails the test the moment CompleteOnce is ever called
// — used at a crash boundary the fixture asserts happens strictly BEFORE
// any physical L2 request, so an unexpected call proves the simulated crash
// landed in the wrong place.
func unreachableL2Client(t *testing.T, reason string) *scriptedL2Client {
	t.Helper()
	return &scriptedL2Client{fn: func(int) (llm.OneShotCompletion, error) {
		t.Fatalf("CompleteOnce must not be reached: %s", reason)
		return llm.OneShotCompletion{}, nil
	}}
}

// rejectedThenUnreachableL2Client returns one malformed (missing every
// required key) response on the FIRST call — status="rejected" once
// validated — then fails the test on any further call, for the boundary-4
// subtest, which must crash immediately after that first rejected outcome
// persists, never reaching a second dispatch.
func rejectedThenUnreachableL2Client(t *testing.T) *scriptedL2Client {
	return &scriptedL2Client{fn: func(n int) (llm.OneShotCompletion, error) {
		if n > 1 {
			t.Fatalf("CompleteOnce called a second time (call #%d): the crash must happen after the first rejected outcome persists, before any further dispatch", n)
		}
		return llm.OneShotCompletion{
			Completion:     llm.Completion{Raw: []byte(`{}`), Model: "replay-test-model", Latency: time.Millisecond},
			RequestStarted: llm.RequestStartStatusTrue,
		}, nil
	}}
}

// ----------------------------------------------------------------------
// Deterministic fake L1 (Acute Triage) analyzer / after-committer.
// ----------------------------------------------------------------------

type scriptedAnalyzer struct {
	mu    sync.Mutex
	calls int
	fn    func(ctx context.Context, claim situation.TriageAttemptClaim) (situation.AcuteResult, error)
}

func (a *scriptedAnalyzer) Analyze(ctx context.Context, claim situation.TriageAttemptClaim) (situation.AcuteResult, error) {
	a.mu.Lock()
	a.calls++
	a.mu.Unlock()
	return a.fn(ctx, claim)
}

func (a *scriptedAnalyzer) callCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

func acceptedAcuteResult(incidentID string) situation.AcuteResult {
	return situation.AcuteResult{
		IncidentID:         incidentID,
		EvidencePackDigest: "sha256:replay-evidence",
		OutputJSON:         json.RawMessage(`{"summary":"replay finding"}`),
		AnalysisName:       "replay-analysis",
		Summary:            "replay finding summary",
		RootCause:          "replay root cause",
		Confidence:         0.5,
	}
}

func newAcceptingAnalyzer() *scriptedAnalyzer {
	return &scriptedAnalyzer{fn: func(_ context.Context, claim situation.TriageAttemptClaim) (situation.AcuteResult, error) {
		return acceptedAcuteResult(claim.IncidentID), nil
	}}
}

// crashingAnalyzer panics the moment Analyze is invoked — Acute Triage's
// attempt claim (durable, consumed) already committed for real before this
// point (TriageWorker.processOne calls ClaimIncidentTriageAttempt, THEN
// Analyze), so this simulates a crash strictly after Triage attempt begin
// but before Acute Triage result.
type crashingAnalyzer struct{ boundary string }

func (a crashingAnalyzer) Analyze(context.Context, situation.TriageAttemptClaim) (situation.AcuteResult, error) {
	panic(replayCrash(a))
}

type countingAfterCommitter struct {
	mu    sync.Mutex
	calls int
}

func (a *countingAfterCommitter) AfterCommit(context.Context, situation.AcuteResult) error {
	a.mu.Lock()
	a.calls++
	a.mu.Unlock()
	return nil
}

func (a *countingAfterCommitter) callCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

// crashingAfterCommitter counts its own call then panics — the real
// CompleteIncidentTriageAttempt store commit (the Finding itself) has
// already succeeded for real by the time TriageWorker ever calls
// AfterCommit (completeSuccessOrStale calls the store first, then
// AfterCommit only on success), so this simulates a crash strictly after
// Finding persistence but before worker return.
type crashingAfterCommitter struct {
	mu    sync.Mutex
	calls int
}

func (a *crashingAfterCommitter) AfterCommit(context.Context, situation.AcuteResult) error {
	a.mu.Lock()
	a.calls++
	a.mu.Unlock()
	panic(replayCrash{boundary: "finding_persisted_before_worker_return"})
}

func (a *crashingAfterCommitter) callCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

// ----------------------------------------------------------------------
// Crash simulation: a fault-injecting situation.ControllerStore decorator
// plus the shared panic/recover harness every subtest uses.
//
// Each fault site calls through to the REAL store method first (so its own
// durable, atomic write actually lands on disk exactly as production would)
// and panics with a distinguished sentinel only once that real call has
// already returned successfully — modeling "the process died at this exact
// point, with everything up to and including the last real write durable,
// and nothing after it ever executed." The one exception is
// CommitController — see that method's own doc comment below for why it
// panics BEFORE delegating, not after.
// ----------------------------------------------------------------------

type crashPoint string

const (
	crashPointRecordAssessmentCall    crashPoint = "crash_after_l2_dispatch_record_before_response"
	crashPointAppendAssessmentOutcome crashPoint = "crash_after_rejected_attempt_persisted"
	crashPointCommitController        crashPoint = "crash_after_authoritative_insert_before_commit"
)

type replayCrash struct{ boundary string }

type faultyControllerStore struct {
	*store.Store

	armed crashPoint
}

func (f *faultyControllerStore) RecordAssessmentCall(ctx context.Context, claim situation.Claim, call situation.AssessmentCall) error {
	if err := f.Store.RecordAssessmentCall(ctx, claim, call); err != nil {
		return err
	}
	if f.armed == crashPointRecordAssessmentCall {
		panic(replayCrash{boundary: string(crashPointRecordAssessmentCall)})
	}
	return nil
}

func (f *faultyControllerStore) AppendAssessmentOutcome(ctx context.Context, attempt situation.AssessmentAttempt) error {
	if err := f.Store.AppendAssessmentOutcome(ctx, attempt); err != nil {
		return err
	}
	if f.armed == crashPointAppendAssessmentOutcome {
		panic(replayCrash{boundary: string(crashPointAppendAssessmentOutcome)})
	}
	return nil
}

// CommitController crashes BEFORE delegating at all when armed for this
// boundary. CommitController (internal/store/situation_controller.go) is
// one fenced, atomic SQLite transaction: insert the authoritative attempt
// row and its coverage, apply Triage decisions, then one projection UPDATE,
// then Commit. There is no seam in this package's own public surface to
// interrupt it mid-transaction without a custom fault-injecting SQL driver
// reaching inside modernc.org/sqlite — engineering that would only
// re-verify SQLite's own well-tested rollback behavior, not this codebase's
// logic. By SQLite's own atomicity guarantee, a real crash landing anywhere
// inside that one transaction — one statement in, or a hair's breadth from
// its own tx.Commit() call — is OBSERVABLY IDENTICAL to a crash landing
// before the call is ever made: either way, nothing this cycle intended to
// commit is ever durably visible, and the situation's lease/input_version
// are exactly as they were before this cycle claimed it. Not calling
// through models that identical durable outcome with no loss of fidelity —
// see the boundary-5 subtest below for the assertions this equivalence
// lets the test make honestly.
func (f *faultyControllerStore) CommitController(ctx context.Context, claim situation.Claim, commit situation.ControllerCommit) error {
	if f.armed == crashPointCommitController {
		panic(replayCrash{boundary: string(crashPointCommitController)})
	}
	return f.Store.CommitController(ctx, claim, commit)
}

// simulateCrash runs fn and requires it to panic with exactly the expected
// replayCrash sentinel — a real (unexpected) panic is never swallowed, so a
// genuine bug in the code under test still fails loudly instead of being
// silently absorbed as though it were the expected simulated crash.
func simulateCrash(t *testing.T, boundary string, fn func()) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("simulateCrash(%s): expected a simulated crash panic, got none (the call completed normally)", boundary)
			return
		}
		rc, ok := r.(replayCrash)
		if !ok || rc.boundary != boundary {
			panic(r) // not our sentinel — a real bug must surface, never be swallowed.
		}
	}()
	fn()
}

// ----------------------------------------------------------------------
// TestControllerRealStoreReplay: the file-backed replay fixture, entering
// through real Receiver HTTP input and production foundation/controller/
// Triage assembly (never a hand-seeded Situation, fact, Assessment, or
// Triage envelope), with eight crash-boundary subtests, per this task's
// brief:
//
//  1. after Plan 1 Situation input application
//  2. after Situation claim
//  3. after L2 provider dispatch record but before response
//  4. after rejected/failed attempt persistence
//  5. after authoritative Assessment append but before projection commit
//  6. after Triage attempt begin but before Acute Triage result
//  7. after Finding persistence but before worker return
//  8. while a concurrent Situation input raises a new due reason
//
// Every subtest closes and reopens the same on-disk database file and runs
// the real startup recovery/replay sequence (replayFixture.bootReplay) before
// asserting convergence: one current input-bound Assessment and one Triage
// state, stable hashes, at most 2 consumed L2 dispatch slots per work
// attempt, at most 5 work attempts per unchanged input, at most one physical
// HTTP request per dispatch (scriptedL2Client.calls counts CompleteOnce
// invocations 1:1 against durable situation_assessment_calls rows), no
// repeated Finding or consumed Acute Triage attempt after committed
// completion, no lost wake-up, and no outward Situation effect (there is no
// Situation-owned Slack/notifier path in this codebase at all yet — nothing
// in this fixture wires one, so there is nothing to accidentally trigger).
func TestControllerRealStoreReplay(t *testing.T) {
	// Each subtest is a named top-level function (not an inline closure):
	// gocyclo counts every subtest's own branching against this one outer
	// function when they are inlined, and eight independent crash-boundary
	// scenarios inlined together comfortably exceeds this repo's configured
	// complexity ceiling even though no single scenario is itself complex.
	// Extracting them keeps each scenario's own branching scoped to its own
	// function, exactly where a reader already expects to find it.
	t.Run("crash_after_situation_input_applied", testReplayCrashAfterSituationInputApplied)
	t.Run("crash_after_situation_claim", testReplayCrashAfterSituationClaim)
	t.Run("crash_after_l2_dispatch_record_before_response", testReplayCrashAfterL2DispatchRecordBeforeResponse)
	t.Run("crash_after_rejected_attempt_persisted", testReplayCrashAfterRejectedAttemptPersisted)
	t.Run("crash_after_authoritative_insert_before_commit", testReplayCrashAfterAuthoritativeInsertBeforeCommit)
	t.Run("crash_after_triage_attempt_begin_before_result", testReplayCrashAfterTriageAttemptBeginBeforeResult)
	t.Run("crash_after_finding_persisted_before_worker_return", testReplayCrashAfterFindingPersistedBeforeWorkerReturn)
	t.Run("concurrent_input_raises_new_due_reason", testReplayConcurrentInputRaisesNewDueReason)
}

// Boundary 1: after Plan 1 Situation input application.
func testReplayCrashAfterSituationInputApplied(t *testing.T) {
	f := newReplayFixture(t, "b1")
	sitID := f.setupDueSituation("boundary1-group", "HighLatency", "fp-b1")

	// Sanity: Plan 1's own input application is the ONLY thing that has
	// happened so far — no controller cycle has ever run.
	if got := scalarNullableString(t, f.st, `SELECT current_assessment_id FROM situations WHERE id = ?`, sitID); got != "" {
		t.Fatalf("current_assessment_id = %q before any reconcile, want empty", got)
	}
	if got := scalarInt(t, f.st, `SELECT COUNT(*) FROM situation_assessment_attempts`); got != 0 {
		t.Fatalf("situation_assessment_attempts before any reconcile = %d, want 0", got)
	}

	// Simulated crash: nothing beyond Plan 1's own durable input
	// application ever ran, so there is nothing to fault-inject — just
	// stop here, close, and reopen.
	f.restart()
	f.bootReplay()
	f.ageIntoLongDurationClass()

	client := newAcceptingL2Client()
	analyzer := newAcceptingAnalyzer()
	after := &countingAfterCommitter{}
	f.convergeAll(client, analyzer, after, nil)

	assertOneCurrentAssessment(t, f.st, sitID)
	assertL2CallCeiling(t, f.st, sitID)
	assertIdempotentReconverge(f, sitID, client, analyzer, after)
}

// Boundary 2: after Situation claim.
func testReplayCrashAfterSituationClaim(t *testing.T) {
	f := newReplayFixture(t, "b2")
	sitID := f.setupDueSituation("boundary2-group", "HighLatency", "fp-b2")

	f.clock.Advance(advanceMargin)
	claims, err := f.st.ClaimControllerWork(f.ctx, "b2:controller", f.clock.Now(), 300*time.Second, 10)
	if err != nil {
		t.Fatalf("claim controller work: %v", err)
	}
	if len(claims) != 1 {
		t.Fatalf("claimed %d situations, want 1", len(claims))
	}
	if got := scalarNullableString(t, f.st, `SELECT lease_owner FROM situations WHERE id = ?`, sitID); got == "" {
		t.Fatal("lease_owner empty right after claim, want set (the claim itself is durable)")
	}

	// Simulated crash: the claim committed for real; Reconcile never runs
	// against it at all.
	f.restart()
	f.bootReplay()
	f.ageIntoLongDurationClass()

	client := newAcceptingL2Client()
	analyzer := newAcceptingAnalyzer()
	after := &countingAfterCommitter{}
	f.convergeAll(client, analyzer, after, nil)

	assertOneCurrentAssessment(t, f.st, sitID)
	if got := scalarNullableString(t, f.st, `SELECT lease_owner FROM situations WHERE id = ?`, sitID); got != "" {
		t.Fatalf("lease_owner after convergence = %q, want cleared", got)
	}
	assertL2CallCeiling(t, f.st, sitID)
	assertIdempotentReconverge(f, sitID, client, analyzer, after)
}

// KNOWN BUG (discovered by this task's own Finding #1 systemic
// assertNoReconcileFailed check, NOT introduced by it, and NOT caused by
// Finding #2's clock-advancement fix — reproduces identically with
// ageIntoLongDurationClass removed): boundaries 3, 4, and 5 below currently
// fail assertNoReconcileFailed with last_error_class = "transport_failure"
// on their first post-restart convergeAll call. Root cause, traced via a
// temporary debug wrapper on ControllerStore.RecordAssessmentCall (since
// removed):
//
//  1. Each of these three boundaries crashes strictly BEFORE its cycle's own
//     CommitController ever runs — by construction, that is the whole point
//     of "after dispatch record but before response" /"after rejected
//     attempt persisted" / "after authoritative insert but before
//     commit". So situations.controller_work_attempts and
//     current_material_fact_hash are left exactly as they were before this
//     Situation's very first controller cycle: controller_work_attempts=0,
//     current_material_fact_hash=NULL. The pre-crash cycle DID durably
//     record one situation_assessment_calls row at
//     (input_version=1, retry_epoch=0, work_attempt=1, call_number=1) —
//     immutable, per migration 0015's own no-update/no-delete triggers.
//  2. On replay, the first post-restart reconcile calls BeginControllerAttempt
//     (internal/store/situation_controller.go): since current_material_fact_hash
//     is NULL (never committed), it treats this as a fresh epoch and returns
//     work_attempt=1 again — nextAttempt intentionally resets on ANY basis
//     change, "this covers BOTH 'a genuinely new material input arrived' and
//     '...already reset controller_work_attempts to 0'" (that function's own
//     doc comment). controller_retry_epoch is untouched: "controller_retry_epoch
//     is returned read-only; only the [dependency-recovery] wake primitive
//     ever writes it" (same doc comment) — so it is still 0.
//  3. dispatchWorkBearing (controller.go) then calls RecordAssessmentCall
//     again with the IDENTICAL (situation_id, input_version=1, retry_epoch=0,
//     work_attempt=1, call_number=1) — colliding with the immutable pre-crash
//     row on situation_assessment_calls' own
//     UNIQUE(situation_id, input_version, retry_epoch, work_attempt, call_number)
//     index (migration 0015_situation_controller.sql). The INSERT's own
//     ON CONFLICT(id) clause only covers the primary key, not this separate
//     unique index, so the raw SQLite constraint error propagates as
//     RecordAssessmentCall's return error.
//  4. dispatchWorkBearing wraps it as a generic transportErr; ClassifyL2Outcome
//     has no case for it, so classifyTransportErr's own catch-all default
//     classifies it L2OutcomeTransportFailure — the SAME literal string
//     "transport_failure" sanitizeTransportError separately produces for an
//     unrecognized network error, which is what led early debugging astray.
//     Reconcile then takes the ordinary "no accepted proposal" branch:
//     fallbackOrPreserve + a NORMAL, SUCCESSFUL CommitController commit
//     (status=authoritative, derivation=deterministic_fallback), recording
//     last_error_class="transport_failure" on situations as a diagnostic
//     breadcrumb — Reconcile itself returns nil, so ControllerWorker never
//     logs a warning either. No physical L2 request happens this cycle at
//     all (RecordAssessmentCall fails before CompleteOnce is ever called).
//
// Net effect: a crash landing in any of these three windows causes the
// Situation's first REAL post-crash controller cycle to silently waste
// itself on a degraded deterministic_fallback Assessment — with zero visible
// error anywhere — before self-healing on the SECOND post-restart cycle
// (once current_material_fact_hash finally gets populated by this first
// commit, so BeginControllerAttempt correctly advances work_attempt to 2 and
// stops colliding). This is a genuine, previously undiscovered gap in the
// crash-recovery bookkeeping (situation_assessment_calls' own UNIQUE index
// does not account for controller_work_attempts legitimately resetting to 1
// without input_version or controller_retry_epoch also advancing), not a
// test-timing artifact and not either of this task's two already-verified
// production fixes (internal/store/situation_controller.go's appendFactTx,
// internal/situation/facts.go's factIdentityWithContent). Per this task's
// own explicit instructions ("stop and report clearly rather than weakening
// the assertion to match"), assertNoReconcileFailed is NOT weakened or
// scoped away from these three boundaries — see the Task 10 fix report for
// the full write-up; this is flagged there as a DONE_WITH_CONCERNS finding
// for a dedicated follow-up fix, not something this task's own scope
// (test coverage only) is authorized to change.

// Boundary 3: after L2 provider dispatch record but before response.
func testReplayCrashAfterL2DispatchRecordBeforeResponse(t *testing.T) {
	f := newReplayFixture(t, "b3")
	sitID := f.setupDueSituation("boundary3-group", "HighLatency", "fp-b3")

	f.clock.Advance(advanceMargin)
	claims, err := f.st.ClaimControllerWork(f.ctx, "b3:controller", f.clock.Now(), 300*time.Second, 10)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim controller work: claims=%d err=%v", len(claims), err)
	}
	claim := claims[0]

	faulty := &faultyControllerStore{Store: f.st, armed: crashPointRecordAssessmentCall}
	// The physical L2 request must never be reached: the crash lands
	// immediately after the durable dispatch-slot record commits, before
	// any request is even issued — a strict subset of "before response."
	crashClient := unreachableL2Client(t, "the crash happens right after RecordAssessmentCall, before CompleteOnce is ever invoked")
	controller := situation.NewController(faulty, crashClient, situation.ControllerConfig{}, f.clock.Now, audit.New(f.st.DB()), nil)

	simulateCrash(t, string(crashPointRecordAssessmentCall), func() {
		_ = controller.Reconcile(f.ctx, claim)
	})

	if got := scalarInt(t, f.st, `SELECT COUNT(*) FROM situation_assessment_calls WHERE situation_id = ?`, sitID); got != 1 {
		t.Fatalf("situation_assessment_calls after the crash = %d, want 1 (durably recorded before the simulated crash)", got)
	}
	if got := scalarNullableString(t, f.st, `SELECT current_assessment_id FROM situations WHERE id = ?`, sitID); got != "" {
		t.Fatal("current_assessment_id set despite the crash happening before any commit")
	}

	f.restart()
	report := f.bootReplay()
	if report.AssessmentCallsRecovered != 1 {
		t.Fatalf("assessment calls recovered on restart = %d, want 1 (the orphaned dispatch record from before the crash)", report.AssessmentCallsRecovered)
	}
	f.ageIntoLongDurationClass()

	client := newAcceptingL2Client()
	analyzer := newAcceptingAnalyzer()
	after := &countingAfterCommitter{}
	f.convergeAll(client, analyzer, after, nil)

	assertOneCurrentAssessment(t, f.st, sitID)
	assertL2CallCeiling(t, f.st, sitID)
	assertIdempotentReconverge(f, sitID, client, analyzer, after)
}

// Boundary 4: after rejected/failed attempt persistence.
func testReplayCrashAfterRejectedAttemptPersisted(t *testing.T) {
	f := newReplayFixture(t, "b4")
	sitID := f.setupDueSituation("boundary4-group", "HighLatency", "fp-b4")

	f.clock.Advance(advanceMargin)
	claims, err := f.st.ClaimControllerWork(f.ctx, "b4:controller", f.clock.Now(), 300*time.Second, 10)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim controller work: claims=%d err=%v", len(claims), err)
	}
	claim := claims[0]

	faulty := &faultyControllerStore{Store: f.st, armed: crashPointAppendAssessmentOutcome}
	rejectingClient := rejectedThenUnreachableL2Client(t)
	controller := situation.NewController(faulty, rejectingClient, situation.ControllerConfig{}, f.clock.Now, audit.New(f.st.DB()), nil)

	simulateCrash(t, string(crashPointAppendAssessmentOutcome), func() {
		_ = controller.Reconcile(f.ctx, claim)
	})

	if got := scalarInt(t, f.st, `SELECT COUNT(*) FROM situation_assessment_attempts WHERE situation_id = ? AND status = 'rejected'`, sitID); got != 1 {
		t.Fatalf("rejected situation_assessment_attempts after the crash = %d, want 1", got)
	}
	if got := scalarNullableString(t, f.st, `SELECT current_assessment_id FROM situations WHERE id = ?`, sitID); got != "" {
		t.Fatal("current_assessment_id set despite the crash happening before any commit")
	}

	f.restart()
	f.bootReplay()
	f.ageIntoLongDurationClass()

	client := newAcceptingL2Client()
	analyzer := newAcceptingAnalyzer()
	after := &countingAfterCommitter{}
	f.convergeAll(client, analyzer, after, nil)

	assertOneCurrentAssessment(t, f.st, sitID)
	// The pre-crash rejected attempt is retained, never repeated: exactly
	// one rejected row from before the crash, plus whatever the post-restart
	// accepting client needed.
	if got := scalarInt(t, f.st, `SELECT COUNT(*) FROM situation_assessment_attempts WHERE situation_id = ? AND status = 'rejected'`, sitID); got != 1 {
		t.Fatalf("rejected situation_assessment_attempts after convergence = %d, want still exactly 1 (retained, never repeated)", got)
	}
	assertL2CallCeiling(t, f.st, sitID)
	assertIdempotentReconverge(f, sitID, client, analyzer, after)
}

// Boundary 5: after authoritative Assessment append but before projection
// commit.
func testReplayCrashAfterAuthoritativeInsertBeforeCommit(t *testing.T) {
	f := newReplayFixture(t, "b5")
	sitID := f.setupDueSituation("boundary5-group", "HighLatency", "fp-b5")

	f.clock.Advance(advanceMargin)
	claims, err := f.st.ClaimControllerWork(f.ctx, "b5:controller", f.clock.Now(), 300*time.Second, 10)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim controller work: claims=%d err=%v", len(claims), err)
	}
	claim := claims[0]

	faulty := &faultyControllerStore{Store: f.st, armed: crashPointCommitController}
	client := newAcceptingL2Client()
	controller := situation.NewController(faulty, client, situation.ControllerConfig{}, f.clock.Now, audit.New(f.st.DB()), nil)

	simulateCrash(t, string(crashPointCommitController), func() {
		_ = controller.Reconcile(f.ctx, claim)
	})

	if got := client.callCount(); got != 1 {
		t.Fatalf("L2 calls before the simulated crash = %d, want 1 (the draft call itself completed for real; this boundary crashes strictly after it, inside CommitController's own fenced transaction)", got)
	}
	if got := scalarInt(t, f.st, `SELECT COUNT(*) FROM situation_assessment_attempts WHERE situation_id = ? AND status = 'authoritative'`, sitID); got != 0 {
		t.Fatal("an authoritative attempt row is durably visible despite CommitController's own atomic transaction never committing")
	}
	if got := scalarNullableString(t, f.st, `SELECT current_assessment_id FROM situations WHERE id = ?`, sitID); got != "" {
		t.Fatal("current_assessment_id set despite CommitController never committing")
	}

	f.restart()
	f.bootReplay()
	f.ageIntoLongDurationClass()

	// A fresh client: the pre-crash client already spent its one real call,
	// and it is never reused across a restart in production either.
	freshClient := newAcceptingL2Client()
	analyzer := newAcceptingAnalyzer()
	after := &countingAfterCommitter{}
	f.convergeAll(freshClient, analyzer, after, nil)

	assertOneCurrentAssessment(t, f.st, sitID)
	assertL2CallCeiling(t, f.st, sitID)
	assertIdempotentReconverge(f, sitID, freshClient, analyzer, after)
}

// Boundary 6: after Triage attempt begin but before Acute Triage result.
func testReplayCrashAfterTriageAttemptBeginBeforeResult(t *testing.T) {
	f := newReplayFixture(t, "b6")
	incID := f.setupReadyIncidentWithRequestedTriage("boundary6-group", "HighLatency", "fp-b6")

	f.clock.Advance(advanceMargin)
	analyzer := crashingAnalyzer{boundary: "triage_attempt_begin_before_result"}
	triageStore := &replayTriageStoreAdapter{f.st}
	triageLister := &replayTriageListerAdapter{f.st}
	tw := situation.NewTriageWorker(triageStore, triageLister, analyzer, &countingAfterCommitter{}, nil,
		situation.TriageWorkerConfig{Owner: "b6:triage", Now: f.clock.Now}, nil)

	simulateCrash(t, "triage_attempt_begin_before_result", func() {
		_, _ = tw.RunOnce(f.ctx)
	})

	// The attempt begin (claim) is the consumed dispatch slot, and it is
	// durable: the schedule already moved to in_flight before Analyze was
	// ever called.
	if phase := scalarString(t, f.st, `SELECT phase FROM incident_triage WHERE incident_id = ?`, incID); phase != "in_flight" {
		t.Fatalf("triage phase after the crash = %q, want in_flight (the claim itself is durable)", phase)
	}
	if status := scalarString(t, f.st, `SELECT status FROM incidents WHERE id = ?`, incID); status != "processing" {
		t.Fatalf("incident status after the crash = %q, want processing", status)
	}

	f.restart()
	report := f.bootReplay()
	if report.TriageAttemptsRecovered != 1 {
		t.Fatalf("triage attempts recovered on restart = %d, want 1 (the interrupted in_flight attempt from before the crash)", report.TriageAttemptsRecovered)
	}
	f.ageIntoLongDurationClass()

	freshAnalyzer := newAcceptingAnalyzer()
	after := &countingAfterCommitter{}
	f.convergeAll(newAcceptingL2Client(), freshAnalyzer, after, nil)

	if status := scalarString(t, f.st, `SELECT status FROM incidents WHERE id = ?`, incID); status != "analyzed" {
		t.Fatalf("incident status after convergence = %q, want analyzed", status)
	}
	if got := freshAnalyzer.callCount(); got != 1 {
		t.Fatalf("Analyze calls after convergence = %d, want exactly 1 (the crashed attempt's own claim consumed a slot but never produced a result, so replay must run — and count — exactly one real analysis)", got)
	}

	// Idempotent re-run: no repeated Finding, no re-claimed attempt. Advance
	// PAST the situation's own committed next_assessment_at checkpoint first
	// (slowCadenceCheckpointMargin — see its own doc comment) and assert the
	// controller actually reconciled again (Controller > 0): otherwise
	// nothing is ever due and "Analyze calls unchanged" is vacuously true,
	// not proof that Triage genuinely skipped re-claiming a decided attempt
	// (Task 10 review Finding #2).
	before := freshAnalyzer.callCount()
	f.clock.Advance(slowCadenceCheckpointMargin)
	totals := f.convergeAll(newAcceptingL2Client(), freshAnalyzer, after, nil)
	if totals.Controller == 0 {
		t.Fatal("idempotent re-run: controller drain claimed 0 situations even after advancing past the committed " +
			"next_assessment_at checkpoint, want > 0 — a real second reconcile cycle must actually run, or " +
			"\"Analyze calls unchanged\" below is vacuously true rather than proving no re-claimed attempt")
	}
	if got := freshAnalyzer.callCount(); got != before {
		t.Fatalf("Analyze calls after an idempotent reconverge = %d, want unchanged %d", got, before)
	}
}

// Boundary 7: after Finding persistence but before worker return.
func testReplayCrashAfterFindingPersistedBeforeWorkerReturn(t *testing.T) {
	f := newReplayFixture(t, "b7")
	incID := f.setupReadyIncidentWithRequestedTriage("boundary7-group", "HighLatency", "fp-b7")

	f.clock.Advance(advanceMargin)
	successAnalyzer := &scriptedAnalyzer{fn: func(_ context.Context, claim situation.TriageAttemptClaim) (situation.AcuteResult, error) {
		return acceptedAcuteResult(claim.IncidentID), nil
	}}
	crashingAfter := &crashingAfterCommitter{}
	triageStore := &replayTriageStoreAdapter{f.st}
	triageLister := &replayTriageListerAdapter{f.st}
	tw := situation.NewTriageWorker(triageStore, triageLister, successAnalyzer, crashingAfter, nil,
		situation.TriageWorkerConfig{Owner: "b7:triage", Now: f.clock.Now}, nil)

	simulateCrash(t, "finding_persisted_before_worker_return", func() {
		_, _ = tw.RunOnce(f.ctx)
	})

	if got := crashingAfter.callCount(); got != 1 {
		t.Fatalf("AfterCommit calls before the crash = %d, want 1 (it must have been reached, proving the crash lands strictly after the real Finding commit)", got)
	}
	// The Finding itself is durably safe: CompleteIncidentTriageAttempt
	// already committed for real before AfterCommit's own simulated crash.
	if status := scalarString(t, f.st, `SELECT status FROM incidents WHERE id = ?`, incID); status != "analyzed" {
		t.Fatalf("incident status after the crash = %q, want analyzed (the Finding commit itself is real and already durable)", status)
	}
	if got := successAnalyzer.callCount(); got != 1 {
		t.Fatalf("Analyze calls before the crash = %d, want 1", got)
	}

	f.restart()
	f.bootReplay()

	// Neither of these must ever fire again: the schedule already left
	// pending/backoff/in_flight for good on the pre-crash success, so
	// ListDueIncidentTriage never lists this Incident again.
	freshAnalyzer := newAcceptingAnalyzer()
	after := &countingAfterCommitter{}
	f.convergeAll(newAcceptingL2Client(), freshAnalyzer, after, nil)

	if got := freshAnalyzer.callCount(); got != 0 {
		t.Fatalf("Analyze calls after replay = %d, want 0 (a committed Finding must never be re-analyzed, even though AfterCommit's own best-effort post-commit step never ran pre-crash)", got)
	}
	if got := after.callCount(); got != 0 {
		t.Fatalf("AfterCommit calls after replay = %d, want 0 (an already-committed attempt is never re-completed, so its post-commit effects are never re-run either — a best-effort loss on the crashed attempt, not a repeat)", got)
	}
	if status := scalarString(t, f.st, `SELECT status FROM incidents WHERE id = ?`, incID); status != "analyzed" {
		t.Fatalf("incident status after replay = %q, want still analyzed", status)
	}
}

// Boundary 8: while a concurrent Situation input raises a new due reason.
func testReplayConcurrentInputRaisesNewDueReason(t *testing.T) {
	f := newReplayFixture(t, "b8")
	sitID := f.setupDueSituation("boundary8-group", "HighLatency", "fp-b8-1")

	f.clock.Advance(advanceMargin)
	claims, err := f.st.ClaimControllerWork(f.ctx, "b8:controller", f.clock.Now(), 300*time.Second, 10)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim controller work: claims=%d err=%v", len(claims), err)
	}
	claim := claims[0]
	originalVersion := claim.Situation.InputVersion

	// Concurrent: a second alert lands on the SAME group via the real
	// Receiver HTTP path while the first claim is still outstanding, bumping
	// input_version and adding a new due reason before the first cycle ever
	// commits.
	f.postGroup("boundary8-group", "HighLatency", "fp-b8-2")
	f.drainFoundation()

	newVersion := scalarInt(t, f.st, `SELECT input_version FROM situations WHERE id = ?`, sitID)
	if newVersion <= originalVersion {
		t.Fatalf("input_version after the concurrent delivery = %d, want > %d", newVersion, originalVersion)
	}

	client := newAcceptingL2Client()
	controller := situation.NewController(f.st, client, situation.ControllerConfig{}, f.clock.Now, audit.New(f.st.DB()), nil)
	// Reconcile with the STALE claim (still carrying originalVersion):
	// CommitController's own input_version fence must fail this closed —
	// spec.md: "the controller fails closed and the newer input remains
	// due."
	if err := controller.Reconcile(f.ctx, claim); err == nil {
		t.Fatal("Reconcile with a stale (superseded) claim succeeded, want a fenced version-conflict failure")
	}

	if got := scalarNullableString(t, f.st, `SELECT current_assessment_id FROM situations WHERE id = ?`, sitID); got != "" {
		t.Fatal("current_assessment_id set from a stale-claim commit")
	}
	if got := scalarInt(t, f.st, `SELECT input_version FROM situations WHERE id = ?`, sitID); got != newVersion {
		t.Fatalf("input_version after the stale commit attempt = %d, want unchanged %d (the newer input's own due reason must not be lost)", got, newVersion)
	}

	// Simulated crash: the stale cycle's own lease is left dangling, exactly
	// as an ungraceful process death would leave it.
	f.restart()
	f.bootReplay()
	f.ageIntoLongDurationClass()

	freshClient := newAcceptingL2Client()
	analyzer := newAcceptingAnalyzer()
	after := &countingAfterCommitter{}
	f.convergeAll(freshClient, analyzer, after, nil)

	id := assertOneCurrentAssessment(t, f.st, sitID)
	finalVersion := scalarInt(t, f.st, `SELECT input_version FROM situations WHERE id = ?`, sitID)
	attemptInputVersion := scalarInt(t, f.st, `SELECT input_version FROM situation_assessment_attempts WHERE id = ?`, id.AssessmentID)
	if attemptInputVersion != finalVersion {
		t.Fatalf("current assessment's input_version = %d, want the final converged input_version %d (the concurrently-added due reason must not be lost)", attemptInputVersion, finalVersion)
	}
	assertL2CallCeiling(t, f.st, sitID)
	assertIdempotentReconverge(f, sitID, freshClient, analyzer, after)
}
