// SPDX-License-Identifier: FSL-1.1-ALv2

package situation_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// --------------------------------------------------------------------------
// Fakes. Controller's dependencies are narrow, situation-native interfaces
// (ControllerStore/AssessmentClient/AuditSink — no internal/store import),
// so these fakes need no real database at all — mirrors triage_worker_test.go's
// own fakeStore pattern.
// --------------------------------------------------------------------------

type fakeControllerStore struct {
	mu sync.Mutex

	loadInput situation.SnapshotInput
	loadErr   error

	factsAppended []model.Fact

	beginRetryEpoch, beginWorkAttempt int
	beginErr                          error
	beginCalls                        int

	recordCalls []situation.AssessmentCall
	recordErr   error

	outcomeCalls []situation.AssessmentAttempt

	lastTrustworthy *situation.AuthoritativeAssessment

	commits   []situation.ControllerCommit
	commitErr error
	commitFn  func(situation.ControllerCommit) error

	order []string

	// ControllerWorkStore surface — see controller_worker_test.go.
	claimFn      func(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]situation.Claim, error)
	extendCalls  []situation.Claim
	extendErr    error
	releaseCalls []releaseControllerWorkCall
	releaseErr   error
}

// releaseControllerWorkCall records one ReleaseControllerWork invocation —
// the claim it released plus the backoff (Finding I2) it was asked to write,
// if any.
type releaseControllerWorkCall struct {
	Claim      situation.Claim
	RetryAt    *time.Time
	ErrorClass *string
}

func (f *fakeControllerStore) LoadReconciliationInput(ctx context.Context, claim situation.Claim, now time.Time) (situation.SnapshotInput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.order = append(f.order, "load")
	in := f.loadInput
	in.Now = now
	return in, f.loadErr
}

func (f *fakeControllerStore) AppendSituationFacts(ctx context.Context, claim situation.Claim, facts []model.Fact) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.factsAppended = append(f.factsAppended, facts...)
	f.order = append(f.order, "append_facts")
	return nil
}

func (f *fakeControllerStore) BeginControllerAttempt(ctx context.Context, claim situation.Claim, materialFactHash string, now time.Time) (int, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.beginCalls++
	f.order = append(f.order, "begin_attempt")
	return f.beginRetryEpoch, f.beginWorkAttempt, f.beginErr
}

func (f *fakeControllerStore) RecordAssessmentCall(ctx context.Context, claim situation.Claim, call situation.AssessmentCall) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recordCalls = append(f.recordCalls, call)
	f.order = append(f.order, "record_call")
	return f.recordErr
}

func (f *fakeControllerStore) AppendAssessmentOutcome(ctx context.Context, attempt situation.AssessmentAttempt) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.outcomeCalls = append(f.outcomeCalls, attempt)
	f.order = append(f.order, "append_outcome")
	return nil
}

func (f *fakeControllerStore) LastTrustworthyAssessment(ctx context.Context, claim situation.Claim) (*situation.AuthoritativeAssessment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastTrustworthy, nil
}

func (f *fakeControllerStore) CommitController(ctx context.Context, claim situation.Claim, commit situation.ControllerCommit) error {
	if err := ctx.Err(); err != nil {
		// A real *sql.Tx-backed CommitController fails closed the instant
		// its context is canceled or expired (BeginTx/ExecContext/Commit
		// all respect ctx) — mirrored here so a heartbeat-driven lease-loss
		// cancellation propagates exactly as it would against a real store.
		return err
	}
	f.mu.Lock()
	f.commits = append(f.commits, commit)
	f.order = append(f.order, "commit")
	fn := f.commitFn
	f.mu.Unlock()
	// commitFn (a test hook, e.g. simulating slow I/O for heartbeat tests)
	// runs OUTSIDE the lock: a real store never holds an in-process mutex
	// across a database round trip, and holding one here would starve
	// concurrent calls this same fake serves (ExtendControllerLease, in
	// particular) for the hook's own duration, corrupting exactly the
	// heartbeat-cadence tests this fake exists to support.
	if fn != nil {
		return fn(commit)
	}
	return f.commitErr
}

func (f *fakeControllerStore) ClaimControllerWork(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]situation.Claim, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.claimFn != nil {
		return f.claimFn(ctx, owner, now, lease, limit)
	}
	return nil, nil
}

func (f *fakeControllerStore) ExtendControllerLease(ctx context.Context, claim situation.Claim, now time.Time, lease time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.extendCalls = append(f.extendCalls, claim)
	return f.extendErr
}

func (f *fakeControllerStore) ReleaseControllerWork(ctx context.Context, claim situation.Claim, now time.Time, retryAt *time.Time, errorClass *string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releaseCalls = append(f.releaseCalls, releaseControllerWorkCall{Claim: claim, RetryAt: retryAt, ErrorClass: errorClass})
	return f.releaseErr
}

func (f *fakeControllerStore) snapshotExtendCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.extendCalls)
}

func (f *fakeControllerStore) snapshotReleaseCalls() []releaseControllerWorkCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]releaseControllerWorkCall(nil), f.releaseCalls...)
}

func (f *fakeControllerStore) snapshotCommits() []situation.ControllerCommit {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]situation.ControllerCommit(nil), f.commits...)
}

// fakeAssessmentClient scripts one llm.OneShotCompletion/error pair per
// CompleteOnce call, consumed in order.
type fakeAssessmentClient struct {
	mu        sync.Mutex
	responses []func() (llm.OneShotCompletion, error)
	calls     int
	onCall    func()

	// ctxFn, when set, takes priority over responses/onCall entirely — for
	// tests that need the REAL ctx CompleteOnce was called with (e.g.
	// blocking until it is canceled by a lease-loss abandon).
	ctxFn func(ctx context.Context) (llm.OneShotCompletion, error)
}

func (f *fakeAssessmentClient) CompleteOnce(ctx context.Context, systemPrompt string, prompt llm.Prompt, requiredKeys []string) (llm.OneShotCompletion, error) {
	f.mu.Lock()
	idx := f.calls
	f.calls++
	fn := f.ctxFn
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx)
	}
	if f.onCall != nil {
		f.onCall()
	}
	if idx >= len(f.responses) {
		return llm.OneShotCompletion{}, errors.New("fakeAssessmentClient: no more scripted responses")
	}
	return f.responses[idx]()
}

func acceptedProposalJSON(t *testing.T) json.RawMessage {
	t.Helper()
	p := model.AssessmentProposal{
		SchemaVersion: model.AssessmentSchemaVersion,
		Persistence:   model.PersistenceSustained,
		Impact:        model.ImpactSuspected,
		Novelty:       model.NoveltyFamiliar,
		Causality:     model.CausalityCorrelated,
		Attention:     model.AttentionObserve,
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal accepted proposal: %v", err)
	}
	return b
}

func acceptedResponse(t *testing.T) func() (llm.OneShotCompletion, error) {
	t.Helper()
	raw := acceptedProposalJSON(t)
	return func() (llm.OneShotCompletion, error) {
		return llm.OneShotCompletion{
			Completion:     llm.Completion{Raw: raw, Model: "test-model"},
			RequestStarted: llm.RequestStartStatusTrue,
		}, nil
	}
}

func malformedResponse() func() (llm.OneShotCompletion, error) {
	return func() (llm.OneShotCompletion, error) {
		return llm.OneShotCompletion{
			Completion:     llm.Completion{Raw: json.RawMessage(`{not valid json`), Model: "test-model"},
			RequestStarted: llm.RequestStartStatusTrue,
		}, nil
	}
}

func policyRejectedResponse(t *testing.T) func() (llm.OneShotCompletion, error) {
	t.Helper()
	// urgent attention with no deterministic floor active: deterministically
	// policy-rejected by validateProposalContent (urgent_without_floor).
	p := model.AssessmentProposal{
		SchemaVersion: model.AssessmentSchemaVersion,
		Persistence:   model.PersistenceSustained,
		Impact:        model.ImpactSuspected,
		Novelty:       model.NoveltyFamiliar,
		Causality:     model.CausalityCorrelated,
		Attention:     model.AttentionUrgent,
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal policy-rejected proposal: %v", err)
	}
	return func() (llm.OneShotCompletion, error) {
		return llm.OneShotCompletion{
			Completion:     llm.Completion{Raw: raw, Model: "test-model"},
			RequestStarted: llm.RequestStartStatusTrue,
		}, nil
	}
}

// --------------------------------------------------------------------------
// Fixtures.
// --------------------------------------------------------------------------

var ctBaseTime = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

func ctBaseSituation() model.Situation {
	return model.Situation{
		ID:                      "situation-1",
		GroupKey:                "group-1",
		Lifecycle:               model.LifecycleActive,
		Attention:               model.AttentionObserve,
		InputVersion:            3,
		EffectiveStartedAt:      ctBaseTime,
		EffectiveStartedAtBasis: model.SourceTimeBasisSourcePayload,
		FirstReceivedAt:         ctBaseTime,
		LastLifecycleObservedAt: ctBaseTime,
		NextAssessmentAt:        ctBaseTime.Add(-time.Minute),
		DueReasons:              []model.DueReason{model.DueMembershipChanged},
	}
}

func ctBaseClaim() situation.Claim {
	return situation.Claim{Situation: ctBaseSituation(), ClaimOwner: "owner-1", ClaimToken: 7}
}

func ctDelivery(id, incidentID string, firing bool, severity string) situation.Delivery {
	status := model.DeliveryStatusFiring
	if !firing {
		status = model.DeliveryStatusResolved
	}
	return situation.Delivery{
		ID: id, IncidentID: incidentID, AlertID: id, Status: status,
		PayloadDigest: "digest-" + id, ReceivedAt: ctBaseTime, Severity: severity,
	}
}

func ctIncident(id string) situation.IncidentState {
	return situation.IncidentState{
		ID: id, GroupKey: "group-1", Status: "ready",
		FirstAlertAt: ctBaseTime, LastAlertAt: ctBaseTime, ReadyAt: ctBaseTime, AlertCount: 1,
	}
}

func ctBaseSnapshotInput() situation.SnapshotInput {
	return situation.SnapshotInput{
		Situation:  ctBaseSituation(),
		Deliveries: []situation.Delivery{ctDelivery("delivery-1", "incident-1", true, "warning")},
		Incidents:  []situation.IncidentState{ctIncident("incident-1")},
	}
}

func ctController(t *testing.T, store situation.ControllerStore, client situation.AssessmentClient) *situation.Controller {
	t.Helper()
	clock := func() time.Time { return ctBaseTime.Add(10 * time.Minute) }
	return situation.NewController(store, client, situation.ControllerConfig{}, clock, nil, nil)
}

// --------------------------------------------------------------------------
// Tests.
// --------------------------------------------------------------------------

func TestControllerReconcileUnchangedTrustworthyBasisReusesWithZeroL2Calls(t *testing.T) {
	in := ctBaseSnapshotInput()
	// Match the clock ctController's Controller will actually use when it
	// calls LoadReconciliationInput/BuildSnapshot, so the basis hash this
	// fixture seeds the prior Assessment with is the SAME hash the live
	// Reconcile cycle computes (duration class depends on elapsed time,
	// which depends on Now).
	in.Now = ctBaseTime.Add(10 * time.Minute)
	snap := situation.BuildSnapshot(in)

	prior := &situation.AuthoritativeAssessment{
		ID: "assessment-prior", SituationID: "situation-1",
		AssessmentBasisHash: snap.AssessmentBasisHash, MaterialFactHash: snap.MaterialFactHash,
		InputVersion: 2, Derivation: model.DerivationModelValidated,
		Assessment: model.Assessment{
			SchemaVersion: model.AssessmentSchemaVersion, Persistence: model.PersistenceSustained,
			Impact: model.ImpactSuspected, Novelty: model.NoveltyFamiliar, Causality: model.CausalityCorrelated,
			Attention: model.AttentionObserve, Lifecycle: model.LifecycleActive,
			EvidenceQuality: model.EvidenceQualityComplete, Cadence: model.CadenceSlow,
			ActionContract: model.ActionContract{
				NextActor: model.NextActorNone,
				// Stale on purpose: reuse must accept a prior whose own
				// next_update_at promise has already elapsed by the time a
				// LATER reconciliation revisits it (ValidateShape skips the
				// freshness-vs-now check for exactly this reason).
				NextUpdateAt: &ctBaseTime,
			},
		},
	}
	in.CurrentAssessment = prior

	store := &fakeControllerStore{loadInput: in}
	client := &fakeAssessmentClient{}
	c := ctController(t, store, client)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if client.calls != 0 {
		t.Fatalf("CompleteOnce calls = %d, want 0 (reuse must spend zero L2 dispatch slots)", client.calls)
	}
	if len(store.recordCalls) != 0 {
		t.Fatalf("RecordAssessmentCall calls = %d, want 0", len(store.recordCalls))
	}
	if len(store.commits) != 1 {
		t.Fatalf("commits = %d, want 1", len(store.commits))
	}
	commit := store.commits[0]
	if commit.Attempt.Derivation != model.DerivationRevalidatedReuse {
		t.Fatalf("derivation = %q, want %q", commit.Attempt.Derivation, model.DerivationRevalidatedReuse)
	}
	if commit.Attempt.ID == "" {
		t.Fatal("reuse must still write a new authoritative attempt row")
	}
	// Finding C1: a reuse commit must carry a schema-valid work_attempt (1,
	// the documented nominal value for a non-work-bearing commit) — 0 fails
	// migration 0015's CHECK (work_attempt BETWEEN 1 AND 5) against a real
	// store; see TestCommitControllerRejectsWorkAttemptZeroCheckConstraint and
	// the real-SQLite end-to-end reuse test in internal/store.
	if commit.Attempt.WorkAttempt != 1 {
		t.Fatalf("reuse commit work_attempt = %d, want 1 (migration 0015 requires >= 1; 0 violates the CHECK)", commit.Attempt.WorkAttempt)
	}
}

// TestControllerReconcileDeterministicFloorDispatchesL2AndForcesUrgentOnAccept
// proves Finding I3's ruling: a deterministic urgent floor (critical severity)
// no longer short-circuits Reconcile before ever consulting L2 — the first
// cycle for a floor Situation with no prior trustworthy Assessment still
// dispatches exactly like any other Situation. When L2 succeeds, the floor's
// only effect is forcing Attention to urgent (Task 5's own validateProposalContent
// adjustment mechanism, unconditionally applied here, not a Reconcile-level
// special case) regardless of what the model itself proposed.
func TestControllerReconcileDeterministicFloorDispatchesL2AndForcesUrgentOnAccept(t *testing.T) {
	in := ctBaseSnapshotInput()
	in.Deliveries = []situation.Delivery{ctDelivery("delivery-1", "incident-1", true, "critical")}

	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1, beginRetryEpoch: 0}
	// acceptedResponse proposes AttentionObserve — the floor must still force
	// it up to urgent via the adjustment mechanism, not a Reconcile short-circuit.
	client := &fakeAssessmentClient{responses: []func() (llm.OneShotCompletion, error){acceptedResponse(t)}}
	c := ctController(t, store, client)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if client.calls != 1 {
		t.Fatalf("CompleteOnce calls = %d, want exactly 1 (a deterministic floor no longer skips L2 dispatch on the first cycle)", client.calls)
	}
	if len(store.commits) != 1 {
		t.Fatalf("commits = %d, want 1", len(store.commits))
	}
	commit := store.commits[0]
	if commit.Attempt.Derivation != model.DerivationModelValidated {
		t.Fatalf("derivation = %q, want %q (a first cycle with a floor still consults L2)", commit.Attempt.Derivation, model.DerivationModelValidated)
	}
	if commit.Attention != model.AttentionUrgent {
		t.Fatalf("attention = %q, want urgent (the floor forces Attention up regardless of the model's own proposal)", commit.Attention)
	}
}

// TestControllerReconcileDeterministicFloorFallsBackUrgentWhenL2Fails proves
// the other half of Finding I3's ruling: when L2 genuinely fails on a floor
// Situation's first cycle (no trustworthy prior Assessment exists), Reconcile
// falls back to DeterministicFallback — which independently applies the same
// floor check — so Attention is STILL immediately urgent from the very first
// cycle regardless of L2 outcome, and a bounded retry is scheduled (not a
// permanent stuck state) so the Situation gets a real L2 dispatch again on a
// later cycle.
func TestControllerReconcileDeterministicFloorFallsBackUrgentWhenL2Fails(t *testing.T) {
	in := ctBaseSnapshotInput()
	in.Deliveries = []situation.Delivery{ctDelivery("delivery-1", "incident-1", true, "critical")}

	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1, beginRetryEpoch: 0}
	client := &fakeAssessmentClient{} // no scripted responses: CompleteOnce fails.
	c := ctController(t, store, client)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if client.calls != 1 {
		t.Fatalf("CompleteOnce calls = %d, want exactly 1 (L2 must still be attempted before falling back)", client.calls)
	}
	if len(store.commits) != 1 {
		t.Fatalf("commits = %d, want 1", len(store.commits))
	}
	commit := store.commits[0]
	if commit.Attempt.Derivation != model.DerivationDeterministicFallback {
		t.Fatalf("derivation = %q, want %q", commit.Attempt.Derivation, model.DerivationDeterministicFallback)
	}
	if commit.Attention != model.AttentionUrgent {
		t.Fatalf("attention = %q, want urgent (the deterministic floor still applies to the fallback Assessment) even though L2 failed", commit.Attention)
	}
	if commit.RetryAt == nil {
		t.Fatal("expected a bounded retry to be scheduled, not a permanent stuck state on conservative-default semantic fields")
	}
}

// TestControllerReconcileFloorNewlyEligiblePreservedAssessmentForcesUrgentWhenL2Fails
// proves the regression round 1's I3 fix introduced: fallbackOrPreserve's
// PRESERVE branch (a trustworthy prior Assessment exists, this cycle ends
// without an accepted L2 result) must still route the preserved proposal
// through the SAME floor check every other path already gets
// (validateProposalContent's Attention-raising adjustment), not commit the
// stale pre-floor Attention untouched. Sequence: a warning-severity
// Situation already carries a trustworthy model_validated Assessment with
// Attention=observe (no floor eligible yet); a critical firing delivery then
// joins, making critical_anchor newly eligible and changing both
// MaterialFactHash and AssessmentBasisHash (RevalidateReuse correctly
// refuses reuse: "assessment_basis_changed"); L2 is down this cycle
// (transport failure), so Reconcile falls back to preserving the prior's
// semantic content — which must NOT mean preserving its now-stale observe
// Attention once the floor is active.
func TestControllerReconcileFloorNewlyEligiblePreservedAssessmentForcesUrgentWhenL2Fails(t *testing.T) {
	priorIn := ctBaseSnapshotInput()
	priorIn.Now = ctBaseTime.Add(10 * time.Minute)
	priorSnap := situation.BuildSnapshot(priorIn)
	if hasFloorCandidate(priorSnap.EligibleReasons) {
		t.Fatal("fixture invariant: no deterministic floor should be eligible yet in the prior snapshot")
	}

	prior := &situation.AuthoritativeAssessment{
		ID: "assessment-prior-observe", SituationID: "situation-1",
		AssessmentBasisHash: priorSnap.AssessmentBasisHash, MaterialFactHash: priorSnap.MaterialFactHash,
		InputVersion: 2, Derivation: model.DerivationModelValidated,
		Assessment: model.Assessment{
			SchemaVersion: model.AssessmentSchemaVersion, Persistence: model.PersistenceSustained,
			Impact: model.ImpactSuspected, Novelty: model.NoveltyFamiliar, Causality: model.CausalityCorrelated,
			Attention: model.AttentionObserve, Lifecycle: model.LifecycleActive,
			EvidenceQuality: model.EvidenceQualityComplete, Cadence: model.CadenceSlow,
			ActionContract: model.ActionContract{NextActor: model.NextActorNone, NextUpdateAt: &ctBaseTime},
		},
	}

	// This cycle: a critical firing delivery joins the same Incident —
	// critical_anchor becomes newly eligible, changing the basis.
	in := ctBaseSnapshotInput()
	in.Deliveries = append(in.Deliveries, ctDelivery("delivery-2", "incident-1", true, "critical"))
	in.CurrentAssessment = prior

	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1, beginRetryEpoch: 0}
	client := &fakeAssessmentClient{} // no scripted responses: CompleteOnce fails (transport failure).
	c := ctController(t, store, client)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if client.calls != 1 {
		t.Fatalf("CompleteOnce calls = %d, want exactly 1 (L2 must still be attempted before falling back to preserve)", client.calls)
	}
	if len(store.commits) != 1 {
		t.Fatalf("commits = %d, want 1", len(store.commits))
	}
	commit := store.commits[0]
	if commit.Attempt.ID != "" {
		t.Fatalf("expected the PRESERVE branch (no new authoritative attempt row), got Attempt.ID=%q derivation=%q", commit.Attempt.ID, commit.Attempt.Derivation)
	}
	if commit.Attention != model.AttentionUrgent {
		t.Fatalf("Attention = %q, want urgent: a deterministic floor became eligible this cycle and must not be silently dropped by preserving the stale pre-floor Assessment", commit.Attention)
	}
	if commit.Assessment.Attention != model.AttentionUrgent {
		t.Fatalf("committed Assessment.Attention = %q, want urgent", commit.Assessment.Attention)
	}
	if commit.RetryAt == nil {
		t.Fatal("expected a bounded retry to be scheduled after the transport failure, not a permanent stuck state")
	}
}

// TestControllerReconcileFloorNoLongerEligibleDoesNotPreserveStaleUrgent proves
// the symmetric half of the same fix: "never lower... but also never
// invent." A prior trustworthy Assessment carries Attention=urgent grounded
// in critical_anchor; this cycle the critical delivery is no longer part of
// the Situation's input (the floor is no longer eligible) and L2 fails. The
// preserved proposal's SufficientReason no longer matches any current
// eligible candidate, so validateProposalContent must not accept it
// unchanged — Reconcile must fall through to DeterministicFallback (which
// independently proves no floor is active) rather than committing a stale
// urgent Attention with a reason that no longer grounds it.
func TestControllerReconcileFloorNoLongerEligibleDoesNotPreserveStaleUrgent(t *testing.T) {
	priorIn := ctBaseSnapshotInput()
	priorIn.Deliveries = append(priorIn.Deliveries, ctDelivery("delivery-2", "incident-1", true, "critical"))
	priorIn.Now = ctBaseTime.Add(10 * time.Minute)
	priorSnap := situation.BuildSnapshot(priorIn)
	floorCandidate, ok := findFloorCandidateForTest(priorSnap.EligibleReasons)
	if !ok {
		t.Fatal("fixture invariant: critical_anchor must be eligible in the prior snapshot")
	}

	prior := &situation.AuthoritativeAssessment{
		ID: "assessment-prior-urgent", SituationID: "situation-1",
		AssessmentBasisHash: priorSnap.AssessmentBasisHash, MaterialFactHash: priorSnap.MaterialFactHash,
		InputVersion: 2, Derivation: model.DerivationModelValidated,
		Assessment: model.Assessment{
			SchemaVersion: model.AssessmentSchemaVersion, Persistence: model.PersistenceSustained,
			Impact: model.ImpactSuspected, Novelty: model.NoveltyFamiliar, Causality: model.CausalityCorrelated,
			Attention: model.AttentionUrgent,
			SufficientReason: &model.SufficientReason{
				Code: floorCandidate.Code, CandidateID: floorCandidate.ID, Summary: floorCandidate.Summary,
				EvidenceRefs: append([]string(nil), floorCandidate.EvidenceRefs...),
			},
			Lifecycle:       model.LifecycleActive,
			EvidenceQuality: model.EvidenceQualityComplete, Cadence: model.CadenceSlow,
			ActionContract: model.ActionContract{NextActor: model.NextActorNone, NextUpdateAt: &ctBaseTime},
		},
	}

	// This cycle: back to the base warning-only delivery — the critical
	// delivery is gone, so critical_anchor is no longer eligible.
	in := ctBaseSnapshotInput()
	in.CurrentAssessment = prior

	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1, beginRetryEpoch: 0}
	client := &fakeAssessmentClient{} // no scripted responses: CompleteOnce fails (transport failure).
	c := ctController(t, store, client)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(store.commits) != 1 {
		t.Fatalf("commits = %d, want 1", len(store.commits))
	}
	commit := store.commits[0]
	if commit.Attention == model.AttentionUrgent {
		t.Fatalf("Attention = urgent, want non-urgent: the floor grounding the prior's urgent Attention is no longer eligible, so it must not be preserved unchanged")
	}
	if commit.Attempt.ID == "" || commit.Attempt.Derivation != model.DerivationDeterministicFallback {
		t.Fatalf("expected a fresh DeterministicFallback commit (Attempt.ID=%q Derivation=%q), not a preserved-but-ungrounded proposal", commit.Attempt.ID, commit.Attempt.Derivation)
	}
}

func hasFloorCandidate(candidates []model.ReasonCandidate) bool {
	_, ok := findFloorCandidateForTest(candidates)
	return ok
}

func findFloorCandidateForTest(candidates []model.ReasonCandidate) (model.ReasonCandidate, bool) {
	for _, c := range candidates {
		if c.DeterministicFloor {
			return c, true
		}
	}
	return model.ReasonCandidate{}, false
}

func TestControllerReconcileWorkBearingRecordsDispatchBeforeIOAndAcceptsOnce(t *testing.T) {
	in := ctBaseSnapshotInput()
	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1, beginRetryEpoch: 0}
	client := &fakeAssessmentClient{responses: []func() (llm.OneShotCompletion, error){acceptedResponse(t)}}
	client.onCall = func() {
		store.mu.Lock()
		defer store.mu.Unlock()
		store.order = append(store.order, "complete_once")
	}
	c := ctController(t, store, client)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if client.calls != 1 {
		t.Fatalf("CompleteOnce calls = %d, want exactly 1", client.calls)
	}
	if len(store.recordCalls) != 1 {
		t.Fatalf("RecordAssessmentCall calls = %d, want 1", len(store.recordCalls))
	}
	if store.beginCalls != 1 {
		t.Fatalf("BeginControllerAttempt calls = %d, want 1", store.beginCalls)
	}

	// Dispatch must be durably recorded BEFORE the physical I/O.
	recordIdx, completeIdx := -1, -1
	for i, ev := range store.order {
		switch ev {
		case "record_call":
			if recordIdx == -1 {
				recordIdx = i
			}
		case "complete_once":
			if completeIdx == -1 {
				completeIdx = i
			}
		}
	}
	if recordIdx == -1 || completeIdx == -1 || recordIdx >= completeIdx {
		t.Fatalf("dispatch order = %v; RecordAssessmentCall must precede CompleteOnce", store.order)
	}

	if len(store.commits) != 1 {
		t.Fatalf("commits = %d, want 1", len(store.commits))
	}
	commit := store.commits[0]
	if commit.Attempt.Derivation != model.DerivationModelValidated {
		t.Fatalf("derivation = %q, want %q", commit.Attempt.Derivation, model.DerivationModelValidated)
	}
	if commit.Attempt.CallID == nil || *commit.Attempt.CallID != store.recordCalls[0].ID {
		t.Fatalf("authoritative attempt call_id = %v, want linked to the dispatched call %s", commit.Attempt.CallID, store.recordCalls[0].ID)
	}
}

func TestControllerReconcileMalformedCall1PermitsCall2(t *testing.T) {
	in := ctBaseSnapshotInput()
	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1, beginRetryEpoch: 0}
	client := &fakeAssessmentClient{responses: []func() (llm.OneShotCompletion, error){
		malformedResponse(), acceptedResponse(t),
	}}
	c := ctController(t, store, client)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if client.calls != 2 {
		t.Fatalf("CompleteOnce calls = %d, want exactly 2 (one correction permitted)", client.calls)
	}
	if len(store.recordCalls) != 2 {
		t.Fatalf("RecordAssessmentCall calls = %d, want 2", len(store.recordCalls))
	}
	if store.recordCalls[0].CallNumber != 1 || store.recordCalls[1].CallNumber != 2 {
		t.Fatalf("call numbers = %d,%d, want 1,2", store.recordCalls[0].CallNumber, store.recordCalls[1].CallNumber)
	}
	if len(store.outcomeCalls) != 1 {
		t.Fatalf("AppendAssessmentOutcome calls = %d, want 1 (the malformed call 1)", len(store.outcomeCalls))
	}
	if store.outcomeCalls[0].Status != "rejected" {
		t.Fatalf("outcome status = %q, want rejected", store.outcomeCalls[0].Status)
	}
	if len(store.commits) != 1 || store.commits[0].Attempt.Derivation != model.DerivationModelValidated {
		t.Fatalf("expected a final model_validated commit after the correction succeeded")
	}
}

func TestControllerReconcileMalformedBothCallsSchedulesTypedRetry(t *testing.T) {
	in := ctBaseSnapshotInput()
	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1, beginRetryEpoch: 0}
	client := &fakeAssessmentClient{responses: []func() (llm.OneShotCompletion, error){
		malformedResponse(), malformedResponse(),
	}}
	c := ctController(t, store, client)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if client.calls != 2 {
		t.Fatalf("CompleteOnce calls = %d, want exactly 2", client.calls)
	}
	if len(store.outcomeCalls) != 2 {
		t.Fatalf("AppendAssessmentOutcome calls = %d, want 2", len(store.outcomeCalls))
	}
	if len(store.commits) != 1 {
		t.Fatalf("commits = %d, want 1", len(store.commits))
	}
	commit := store.commits[0]
	if commit.RetryAt == nil {
		t.Fatal("expected a scheduled typed retry (RetryAt) after two malformed calls with attempt budget remaining")
	}
	if commit.Parked.Touch && commit.Parked.Reason != "" {
		t.Fatalf("must not park before the attempt budget (5) is exhausted, got parked reason %q", commit.Parked.Reason)
	}
}

func TestControllerReconcilePolicyRejectionParksWithoutRetry(t *testing.T) {
	in := ctBaseSnapshotInput()
	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1, beginRetryEpoch: 0}
	client := &fakeAssessmentClient{responses: []func() (llm.OneShotCompletion, error){policyRejectedResponse(t)}}
	c := ctController(t, store, client)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if client.calls != 1 {
		t.Fatalf("CompleteOnce calls = %d, want exactly 1 (policy rejection permits no immediate correction)", client.calls)
	}
	if len(store.commits) != 1 {
		t.Fatalf("commits = %d, want 1", len(store.commits))
	}
	commit := store.commits[0]
	if commit.RetryAt != nil {
		t.Fatalf("RetryAt = %v, want nil (policy rejection never retries automatically)", commit.RetryAt)
	}
	if !commit.Parked.Touch || commit.Parked.Reason != situation.ParkedReasonPolicyRejected {
		t.Fatalf("Parked = %+v, want Touch=true Reason=%q", commit.Parked, situation.ParkedReasonPolicyRejected)
	}
}

// TestControllerReconcilePolicyParkSuppressesDispatchUntilBasisChanges proves
// Finding I1: a policy/capability park is actually ENFORCED across cycles, not
// merely recorded. The single-cycle test above only proves this cycle's own
// RetryAt is nil — it says nothing about permanence. This test runs THREE
// cycles: cycle 1 parks on a policy rejection; cycle 2 (the store now
// reflecting the park CommitController would have persisted, same basis) must
// NOT dispatch another L2 call or even call BeginControllerAttempt; cycle 3
// (a changed basis — the stale park still recorded against the OLD hash,
// exactly as a real store would leave it since nothing clears it just because
// the input changed) must dispatch again, proving the park lifts naturally
// rather than staying parked forever.
func TestControllerReconcilePolicyParkSuppressesDispatchUntilBasisChanges(t *testing.T) {
	in1 := ctBaseSnapshotInput()
	in1.Now = ctBaseTime.Add(10 * time.Minute)
	snap1 := situation.BuildSnapshot(in1)

	store := &fakeControllerStore{loadInput: in1, beginWorkAttempt: 1, beginRetryEpoch: 0}
	client := &fakeAssessmentClient{responses: []func() (llm.OneShotCompletion, error){policyRejectedResponse(t)}}
	c := ctController(t, store, client)

	// Cycle 1: policy rejection parks.
	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("cycle 1 Reconcile: %v", err)
	}
	if client.calls != 1 {
		t.Fatalf("cycle 1 CompleteOnce calls = %d, want 1", client.calls)
	}
	if len(store.commits) != 1 {
		t.Fatalf("cycle 1 commits = %d, want 1", len(store.commits))
	}
	commit1 := store.commits[0]
	if !commit1.Parked.Touch || commit1.Parked.Reason != situation.ParkedReasonPolicyRejected {
		t.Fatalf("cycle 1 Parked = %+v, want Touch=true Reason=%q", commit1.Parked, situation.ParkedReasonPolicyRejected)
	}

	// Cycle 2: SAME basis, store now reflects the park a real CommitController
	// commit would have persisted (parked reason + the material fact hash it
	// was parked against, both taken from cycle 1's own commit) — must NOT
	// dispatch another L2 call, and must not even call BeginControllerAttempt.
	store.loadInput.ControllerParked = situation.ControllerParkedState{
		Reason: commit1.Parked.Reason, MaterialFactHash: snap1.MaterialFactHash,
	}
	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("cycle 2 Reconcile: %v", err)
	}
	if client.calls != 1 {
		t.Fatalf("cycle 2 CompleteOnce calls = %d, want still 1 (park must suppress dispatch on the unchanged basis)", client.calls)
	}
	if store.beginCalls != 1 {
		t.Fatalf("cycle 2 BeginControllerAttempt calls = %d, want still 1 (park must skip BeginControllerAttempt entirely, not just skip dispatch after it)", store.beginCalls)
	}
	if len(store.commits) != 2 {
		t.Fatalf("cycle 2 commits = %d, want 2", len(store.commits))
	}
	if store.commits[1].Parked.Touch {
		t.Fatalf("cycle 2 must not re-touch parked state, got %+v", store.commits[1].Parked)
	}

	// Cycle 3: CHANGED basis (a second Incident joins the Situation) — the
	// stale park (still recorded against the OLD hash) must be treated as
	// lifted, and work-bearing dispatch must proceed again.
	in3 := ctBaseSnapshotInput()
	in3.Now = ctBaseTime.Add(10 * time.Minute)
	in3.Incidents = append(in3.Incidents, ctIncident("incident-2"))
	in3.Deliveries = append(in3.Deliveries, ctDelivery("delivery-2", "incident-2", true, "warning"))
	snap3 := situation.BuildSnapshot(in3)
	if snap3.MaterialFactHash == snap1.MaterialFactHash {
		t.Fatal("fixture invariant: cycle 3's own input change must actually change MaterialFactHash, or this test proves nothing")
	}
	store.loadInput = in3
	store.loadInput.ControllerParked = situation.ControllerParkedState{
		Reason: commit1.Parked.Reason, MaterialFactHash: snap1.MaterialFactHash, // stale: still names the OLD hash.
	}
	client.responses = append(client.responses, acceptedResponse(t))

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("cycle 3 Reconcile: %v", err)
	}
	if client.calls != 2 {
		t.Fatalf("cycle 3 CompleteOnce calls = %d, want 2 (a changed basis must lift the stale park and dispatch again)", client.calls)
	}
	if len(store.commits) != 3 {
		t.Fatalf("cycle 3 commits = %d, want 3", len(store.commits))
	}
	if store.commits[2].Parked.Touch && store.commits[2].Parked.Reason != "" {
		t.Fatalf("cycle 3's successful accepted dispatch must clear the park, got %+v", store.commits[2].Parked)
	}
}

func TestControllerReconcileValidContradictedStandsAfterOneCall(t *testing.T) {
	in := ctBaseSnapshotInput()
	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1, beginRetryEpoch: 0}
	contradicted := model.AssessmentProposal{
		SchemaVersion: model.AssessmentSchemaVersion, Persistence: model.PersistenceTransient,
		Impact: model.ImpactNoneObserved, Novelty: model.NoveltyFamiliar, Causality: model.CausalityContradicted,
		Attention: model.AttentionObserve,
	}
	raw, err := json.Marshal(contradicted)
	if err != nil {
		t.Fatalf("marshal contradicted proposal: %v", err)
	}
	client := &fakeAssessmentClient{responses: []func() (llm.OneShotCompletion, error){
		func() (llm.OneShotCompletion, error) {
			return llm.OneShotCompletion{Completion: llm.Completion{Raw: raw}, RequestStarted: llm.RequestStartStatusTrue}, nil
		},
	}}
	c := ctController(t, store, client)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if client.calls != 1 {
		t.Fatalf("CompleteOnce calls = %d, want exactly 1", client.calls)
	}
	if len(store.commits) != 1 || store.commits[0].Attempt.Derivation != model.DerivationModelValidated {
		t.Fatal("a valid contradicted proposal must stand as authoritative after one call")
	}
}

func TestControllerReconcileFiveWorkAttemptsExhaustedParksWithoutDispatch(t *testing.T) {
	in := ctBaseSnapshotInput()
	store := &fakeControllerStore{loadInput: in, beginErr: situation.ErrControllerAttemptsExhausted}
	client := &fakeAssessmentClient{}
	c := ctController(t, store, client)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if client.calls != 0 {
		t.Fatalf("CompleteOnce calls = %d, want 0 (never dispatch call 11)", client.calls)
	}
	if len(store.recordCalls) != 0 {
		t.Fatalf("RecordAssessmentCall calls = %d, want 0", len(store.recordCalls))
	}
	if len(store.commits) != 1 {
		t.Fatalf("commits = %d, want 1", len(store.commits))
	}
	commit := store.commits[0]
	if commit.Lifecycle == model.LifecycleClosedUnknown {
		t.Fatal("exhausted L2 work must never close the Situation")
	}
	if commit.Parked.Touch {
		t.Fatalf("an already-parked steady-state cycle must not re-touch parked state, got %+v", commit.Parked)
	}
}

func TestControllerReconcileStaleCommitReturnsErrorWithoutPanicking(t *testing.T) {
	in := ctBaseSnapshotInput()
	sentinel := errors.New("stale claim")
	store := &fakeControllerStore{loadInput: in, commitErr: sentinel}
	client := &fakeAssessmentClient{}
	c := ctController(t, store, client)

	err := c.Reconcile(context.Background(), ctBaseClaim())
	if !errors.Is(err, sentinel) {
		t.Fatalf("Reconcile err = %v, want to wrap %v", err, sentinel)
	}
}

func TestControllerReconcileFallbackCannotSatisfySemanticReuse(t *testing.T) {
	in := ctBaseSnapshotInput()
	in.Now = ctBaseTime.Add(10 * time.Minute)
	snap := situation.BuildSnapshot(in)

	prior := &situation.AuthoritativeAssessment{
		ID: "assessment-fallback", SituationID: "situation-1",
		AssessmentBasisHash: snap.AssessmentBasisHash, MaterialFactHash: snap.MaterialFactHash,
		InputVersion: 2, Derivation: model.DerivationDeterministicFallback,
		Assessment: model.Assessment{
			SchemaVersion: model.AssessmentSchemaVersion, Persistence: model.PersistenceUnknown,
			Impact: model.ImpactNoneObserved, Novelty: model.NoveltyInsufficientHistory, Causality: model.CausalityUnknown,
			Attention: model.AttentionObserve, Lifecycle: model.LifecycleActive,
			EvidenceQuality: model.EvidenceQualityInsufficient, Cadence: model.CadenceSlow,
			Limitations:    []model.Limitation{{Code: "semantic_assessment_unavailable", Detail: "L2 failed"}},
			ActionContract: model.ActionContract{NextActor: model.NextActorNone, NextUpdateAt: &ctBaseTime},
		},
	}
	in.CurrentAssessment = prior

	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1, beginRetryEpoch: 0}
	client := &fakeAssessmentClient{responses: []func() (llm.OneShotCompletion, error){acceptedResponse(t)}}
	c := ctController(t, store, client)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	// A retry-pending fallback can never satisfy semantic reuse: this cycle
	// must still consult L2, not silently reuse the fallback's own
	// conservative content.
	if client.calls != 1 {
		t.Fatalf("CompleteOnce calls = %d, want exactly 1 (a fallback prior must never short-circuit into reuse)", client.calls)
	}
	if len(store.commits) != 1 || store.commits[0].Attempt.Derivation != model.DerivationModelValidated {
		t.Fatal("expected this cycle's fresh L2 result to become authoritative, not a reuse of the fallback")
	}
}

func TestControllerReconcileTransportFailureSchedulesTypedRetryAndFallsBackWhenNoTrustworthyPrior(t *testing.T) {
	in := ctBaseSnapshotInput()
	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1, beginRetryEpoch: 0}
	client := &fakeAssessmentClient{responses: []func() (llm.OneShotCompletion, error){
		func() (llm.OneShotCompletion, error) {
			// A raw, ambiguous transport failure (the CompleteOnce contract's
			// own "unknown" case — see llm.ClassifyRequestStart) — never a
			// RetryableError, which always means a real HTTP response with a
			// retryable status was received (RequestStarted=true).
			return llm.OneShotCompletion{RequestStarted: llm.RequestStartStatusUnknown}, errors.New("dial tcp: connection refused")
		},
	}}
	c := ctController(t, store, client)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	// Transport failure never gets an immediate correction call.
	if client.calls != 1 {
		t.Fatalf("CompleteOnce calls = %d, want exactly 1", client.calls)
	}
	if len(store.outcomeCalls) != 1 || store.outcomeCalls[0].Status != "failed" {
		t.Fatalf("expected exactly one failed outcome row, got %+v", store.outcomeCalls)
	}
	if store.outcomeCalls[0].ProviderRequestStarted == nil || *store.outcomeCalls[0].ProviderRequestStarted != model.ProviderRequestStartedUnknown {
		t.Fatalf("provider_request_started = %v, want unknown", store.outcomeCalls[0].ProviderRequestStarted)
	}
	if len(store.commits) != 1 {
		t.Fatalf("commits = %d, want 1", len(store.commits))
	}
	commit := store.commits[0]
	if commit.RetryAt == nil {
		t.Fatal("expected a scheduled typed retry after a transport failure with attempt budget remaining")
	}
	// No trustworthy prior exists: the deterministic fallback becomes the
	// new authoritative row (limitation-tagged, not silently dropped).
	if commit.Attempt.ID == "" || commit.Attempt.Derivation != model.DerivationDeterministicFallback {
		t.Fatalf("expected a deterministic_fallback authoritative attempt, got %+v", commit.Attempt)
	}
}

func TestControllerReconcileStaleCommitAfterAcceptedCallRetainsSanitizedStaleOutcome(t *testing.T) {
	in := ctBaseSnapshotInput()
	sentinel := errors.New("stale claim")
	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1, beginRetryEpoch: 0, commitErr: sentinel}
	client := &fakeAssessmentClient{responses: []func() (llm.OneShotCompletion, error){acceptedResponse(t)}}
	c := ctController(t, store, client)

	err := c.Reconcile(context.Background(), ctBaseClaim())
	if !errors.Is(err, sentinel) {
		t.Fatalf("Reconcile err = %v, want to wrap %v", err, sentinel)
	}
	if len(store.commits) != 1 {
		t.Fatalf("commits = %d, want 1 (the fenced attempt, even though it failed)", len(store.commits))
	}
	// The failed commit must never have projected anything current — the
	// fake store doesn't project state itself, but this proves Reconcile
	// never tried a second commit or otherwise worked around the failure.
	if len(store.outcomeCalls) != 1 {
		t.Fatalf("AppendAssessmentOutcome calls = %d, want exactly 1 (the sanitized stale retention)", len(store.outcomeCalls))
	}
	stale := store.outcomeCalls[0]
	if stale.Status != "stale" {
		t.Fatalf("status = %q, want stale", stale.Status)
	}
	if stale.Derivation != "" {
		t.Fatalf("derivation = %q, want empty (authoritative-only field must be cleared)", stale.Derivation)
	}
	if stale.CallID == nil || *stale.CallID != store.recordCalls[0].ID {
		t.Fatalf("stale outcome call_id = %v, want linked to the dispatched call %s", stale.CallID, store.recordCalls[0].ID)
	}
	if stale.Sequence < 1 {
		t.Fatalf("sequence = %d, want >= 1", stale.Sequence)
	}
}

func TestControllerReconcileTriageRequestAndAssessmentShareOneCommit(t *testing.T) {
	in := ctBaseSnapshotInput()
	in.Incidents[0].Triage.Phase = "awaiting_decision"

	store := &fakeControllerStore{loadInput: in}
	client := &fakeAssessmentClient{}
	c := ctController(t, store, client)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(store.commits) != 1 {
		t.Fatalf("commits = %d, want exactly 1 (Triage decisions and the Assessment share one commit)", len(store.commits))
	}
	commit := store.commits[0]
	if len(commit.TriageDecisions) != 1 {
		t.Fatalf("TriageDecisions = %d, want 1", len(commit.TriageDecisions))
	}
	if commit.TriageDecisions[0].Decision != situation.TriageDecisionRequest {
		t.Fatalf("decision = %q, want request (no trustworthy Assessment exists yet)", commit.TriageDecisions[0].Decision)
	}
}

// --------------------------------------------------------------------------
// Lifecycle transition tests (Finding C2 + the brief's originally-requested
// coverage). resolveLifecycle is unexported, so these drive it through
// Reconcile — lifecycle_test.go (package situation) only covers the pure
// timing HELPERS (RecoveryGraceDuration, ObservationDeadlineAt,
// ClosedUnknownReason, AnyFiring, AdvanceLifecycle) in isolation, never
// resolveLifecycle/Reconcile actually driving a Situation through these
// transitions end to end — exactly the gap that let Finding C2 through.
// --------------------------------------------------------------------------

// ctLifecycleController builds a Controller with a fixed clock returning now
// — unlike ctController's hardcoded ctBaseTime+10m offset, these tests need
// precise, test-specific control over elapsed time (DurationClass,
// ObservationDeadlineAt) and grace timing.
func ctLifecycleController(store situation.ControllerStore, client situation.AssessmentClient, now time.Time) *situation.Controller {
	clock := func() time.Time { return now }
	return situation.NewController(store, client, situation.ControllerConfig{}, clock, nil, nil)
}

func TestControllerReconcileLifecycleActiveStaysActiveWhileFiring(t *testing.T) {
	now := ctBaseTime.Add(5 * time.Minute)
	in := ctBaseSnapshotInput() // one firing delivery, active lifecycle.
	in.Now = now

	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1}
	c := ctLifecycleController(store, &fakeAssessmentClient{}, now)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(store.commits) != 1 {
		t.Fatalf("commits = %d, want 1", len(store.commits))
	}
	commit := store.commits[0]
	if commit.Lifecycle != model.LifecycleActive {
		t.Fatalf("lifecycle = %q, want active", commit.Lifecycle)
	}
	if commit.RecoveryObservedAt != nil || commit.GraceUntil != nil || commit.TerminalAt != nil || commit.TerminalReason != nil {
		t.Fatalf("active must carry all four recovery/terminal fields nil (migration 0014's per-lifecycle CHECK), got %+v", commit)
	}
}

func TestControllerReconcileLifecycleActiveTransitionsToRecoveryPendingOnResolution(t *testing.T) {
	now := ctBaseTime.Add(5 * time.Minute)
	in := ctBaseSnapshotInput()
	in.Now = now
	in.Deliveries = []situation.Delivery{ctDelivery("delivery-1", "incident-1", false, "warning")} // resolved, not firing.

	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1}
	c := ctLifecycleController(store, &fakeAssessmentClient{}, now)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	commit := store.commits[0]
	if commit.Lifecycle != model.LifecycleRecoveryPending {
		t.Fatalf("lifecycle = %q, want recovery_pending", commit.Lifecycle)
	}
	if commit.RecoveryObservedAt == nil || !commit.RecoveryObservedAt.Equal(now) {
		t.Fatalf("recovery_observed_at = %v, want %v", commit.RecoveryObservedAt, now)
	}
	if commit.GraceUntil == nil {
		t.Fatal("grace_until must be set on a fresh recovery_pending transition")
	}
	if commit.TerminalAt != nil || commit.TerminalReason != nil {
		t.Fatalf("recovery_pending must carry both terminal fields nil, got %+v", commit)
	}
}

func TestControllerReconcileLifecycleRefireDuringGraceReturnsToActive(t *testing.T) {
	effectiveStartedAt := ctBaseTime
	recoveryObservedAt := ctBaseTime.Add(5 * time.Minute)
	graceUntil := recoveryObservedAt.Add(2 * time.Minute)
	now := recoveryObservedAt.Add(time.Minute) // still within grace.

	in := ctBaseSnapshotInput()
	in.Now = now
	in.Situation.EffectiveStartedAt = effectiveStartedAt
	in.Situation.Lifecycle = model.LifecycleRecoveryPending
	in.Situation.RecoveryObservedAt = &recoveryObservedAt
	in.Situation.GraceUntil = &graceUntil
	in.Deliveries = []situation.Delivery{ctDelivery("delivery-1", "incident-1", true, "warning")} // firing again.

	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1}
	c := ctLifecycleController(store, &fakeAssessmentClient{}, now)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	commit := store.commits[0]
	if commit.Lifecycle != model.LifecycleActive {
		t.Fatalf("lifecycle = %q, want active", commit.Lifecycle)
	}
	if commit.RecoveryObservedAt != nil || commit.GraceUntil != nil || commit.TerminalAt != nil || commit.TerminalReason != nil {
		t.Fatalf("a refire returning to active must carry all four recovery/terminal fields nil, got %+v", commit)
	}
}

func TestControllerReconcileLifecycleGraceExpiryReachesRecovered(t *testing.T) {
	effectiveStartedAt := ctBaseTime
	recoveryObservedAt := ctBaseTime.Add(5 * time.Minute)
	graceUntil := recoveryObservedAt.Add(2 * time.Minute)
	now := graceUntil.Add(time.Minute) // grace already expired.

	in := ctBaseSnapshotInput()
	in.Now = now
	in.Situation.EffectiveStartedAt = effectiveStartedAt
	in.Situation.Lifecycle = model.LifecycleRecoveryPending
	in.Situation.RecoveryObservedAt = &recoveryObservedAt
	in.Situation.GraceUntil = &graceUntil
	in.Deliveries = []situation.Delivery{ctDelivery("delivery-1", "incident-1", false, "warning")} // still not firing.

	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1}
	c := ctLifecycleController(store, &fakeAssessmentClient{}, now)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	commit := store.commits[0]
	if commit.Lifecycle != model.LifecycleRecovered {
		t.Fatalf("lifecycle = %q, want recovered", commit.Lifecycle)
	}
	if commit.RecoveryObservedAt == nil || !commit.RecoveryObservedAt.Equal(recoveryObservedAt) {
		t.Fatalf("recovery_observed_at = %v, want %v", commit.RecoveryObservedAt, recoveryObservedAt)
	}
	if commit.GraceUntil == nil || !commit.GraceUntil.Equal(graceUntil) {
		t.Fatalf("grace_until = %v, want %v", commit.GraceUntil, graceUntil)
	}
	if commit.TerminalAt == nil || !commit.TerminalAt.Equal(now) {
		t.Fatalf("terminal_at = %v, want %v", commit.TerminalAt, now)
	}
	if commit.TerminalReason != nil {
		t.Fatalf("recovered must carry terminal_reason nil (migration 0014's per-lifecycle CHECK), got %v", commit.TerminalReason)
	}
}

// TestControllerReconcileLifecycleDeadlineDuringRecoveryReachesClosedUnknownWithGraceCarried
// is Finding C2's core regression test: recovery_pending -> closed_unknown
// via the observation deadline being crossed WHILE still within the grace
// window (deadline < grace_until) — the exact reachable window the reviewer
// identified. Before the fix, this branch left GraceUntil nil while
// RecoveryObservedAt stayed non-nil, violating migration 0014's unconditional
// recovery-field pairing CHECK ((recovery_observed_at IS NULL) =
// (grace_until IS NULL)).
func TestControllerReconcileLifecycleDeadlineDuringRecoveryReachesClosedUnknownWithGraceCarried(t *testing.T) {
	effectiveStartedAt := ctBaseTime
	// "long" duration class (elapsed >= 1h) has no upper bound, so its own
	// 7-day deadline can be crossed while still self-consistently "long" —
	// see ObservationDeadlineDuration's own doc comment. This is the only
	// class where pastDeadline is naturally reachable at all (short/medium's
	// own deadlines — 2h/24h — always exceed their own class's elapsed
	// range).
	deadline := effectiveStartedAt.Add(7 * 24 * time.Hour)
	recoveryObservedAt := deadline.Add(-time.Minute)      // observed shortly before the deadline.
	graceUntil := recoveryObservedAt.Add(2 * time.Minute) // = deadline + 1 minute: expires AFTER the deadline.
	now := deadline.Add(30 * time.Second)                 // past the deadline, still (barely) within grace.

	if !now.Before(graceUntil) {
		t.Fatalf("fixture invariant: now (%v) must be before graceUntil (%v) — this test exercises the deadline-crossed-while-still-in-grace window", now, graceUntil)
	}

	in := ctBaseSnapshotInput()
	in.Now = now
	in.Situation.EffectiveStartedAt = effectiveStartedAt
	in.Situation.EffectiveStartedAtBasis = model.SourceTimeBasisSourcePayload
	in.Situation.Lifecycle = model.LifecycleRecoveryPending
	in.Situation.RecoveryObservedAt = &recoveryObservedAt
	in.Situation.GraceUntil = &graceUntil
	in.Deliveries = []situation.Delivery{ctDelivery("delivery-1", "incident-1", false, "warning")} // resolved, not firing.

	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1}
	c := ctLifecycleController(store, &fakeAssessmentClient{}, now)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(store.commits) != 1 {
		t.Fatalf("commits = %d, want 1", len(store.commits))
	}
	commit := store.commits[0]
	if commit.Lifecycle != model.LifecycleClosedUnknown {
		t.Fatalf("lifecycle = %q, want closed_unknown", commit.Lifecycle)
	}
	if commit.RecoveryObservedAt == nil || !commit.RecoveryObservedAt.Equal(recoveryObservedAt) {
		t.Fatalf("recovery_observed_at = %v, want %v", commit.RecoveryObservedAt, recoveryObservedAt)
	}
	if commit.GraceUntil == nil || !commit.GraceUntil.Equal(graceUntil) {
		t.Fatalf("grace_until = %v, want %v carried forward (Finding C2) — nil violates migration 0014's recovery-field pairing CHECK", commit.GraceUntil, graceUntil)
	}
	if commit.TerminalAt == nil || !commit.TerminalAt.Equal(now) {
		t.Fatalf("terminal_at = %v, want %v", commit.TerminalAt, now)
	}
	if commit.TerminalReason == nil {
		t.Fatal("terminal_reason must be set for closed_unknown")
	}
}

// TestControllerReconcileLifecycleActiveReachesClosedUnknownWithoutRecoveryFields
// covers the OTHER reachable closed_unknown path — straight from active, no
// recovery ever observed — proving RecoveryObservedAt/GraceUntil correctly
// stay nil (never fabricated) when the Situation never entered recovery at
// all, alongside the C2 test above's carried-forward-non-nil case.
func TestControllerReconcileLifecycleActiveReachesClosedUnknownWithoutRecoveryFields(t *testing.T) {
	effectiveStartedAt := ctBaseTime
	now := effectiveStartedAt.Add(7*24*time.Hour + time.Minute) // just past the "long" class's 7-day deadline.

	in := ctBaseSnapshotInput()
	in.Now = now
	in.Situation.EffectiveStartedAt = effectiveStartedAt
	in.Situation.EffectiveStartedAtBasis = model.SourceTimeBasisSourcePayload
	in.Situation.Lifecycle = model.LifecycleActive
	in.Deliveries = []situation.Delivery{ctDelivery("delivery-1", "incident-1", false, "warning")} // resolved, not firing, never recovered through the controller.

	store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1}
	c := ctLifecycleController(store, &fakeAssessmentClient{}, now)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	commit := store.commits[0]
	if commit.Lifecycle != model.LifecycleClosedUnknown {
		t.Fatalf("lifecycle = %q, want closed_unknown", commit.Lifecycle)
	}
	if commit.RecoveryObservedAt != nil || commit.GraceUntil != nil {
		t.Fatalf("closed_unknown reached directly from active (recovery never observed) must carry both recovery fields nil, got RecoveryObservedAt=%v GraceUntil=%v", commit.RecoveryObservedAt, commit.GraceUntil)
	}
	if commit.TerminalAt == nil || commit.TerminalReason == nil {
		t.Fatalf("closed_unknown must carry both terminal fields set, got TerminalAt=%v TerminalReason=%v", commit.TerminalAt, commit.TerminalReason)
	}
}

// ----------------------------------------------------------------------
// AssessmentHealthObserver: installation LLM health sees the FINAL typed
// outcome, keyed by Situation.
// ----------------------------------------------------------------------

type healthObservation struct {
	situationID  string
	outcome      situation.L2Outcome
	transportErr error
}

type fakeHealthObserver struct {
	mu       sync.Mutex
	begun    int
	finished []healthObservation
}

type fakeHealthObservation struct {
	f           *fakeHealthObserver
	situationID string
}

func (f *fakeHealthObserver) BeginAssessmentCall(situationID string) situation.AssessmentCallObservation {
	f.mu.Lock()
	f.begun++
	f.mu.Unlock()
	return fakeHealthObservation{f: f, situationID: situationID}
}

func (o fakeHealthObservation) Finish(outcome situation.L2Outcome, transportErr error) {
	o.f.mu.Lock()
	o.f.finished = append(o.f.finished, healthObservation{o.situationID, outcome, transportErr})
	o.f.mu.Unlock()
}

// TestControllerReportsFinalTypedOutcomeToHealthObserverPerSituation proves
// the controller observes LLM health AFTER validation/classification — a
// malformed proposal is reported as malformed even though the transport
// returned it successfully — exactly once per dispatch, with the Situation
// ID as the subject, and that a genuine transport failure carries its
// error through.
func TestControllerReportsFinalTypedOutcomeToHealthObserverPerSituation(t *testing.T) {
	t.Run("malformed then accepted", func(t *testing.T) {
		in := ctBaseSnapshotInput()
		store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1, beginRetryEpoch: 0}
		client := &fakeAssessmentClient{responses: []func() (llm.OneShotCompletion, error){
			malformedResponse(), acceptedResponse(t),
		}}
		c := ctController(t, store, client)
		obs := &fakeHealthObserver{}
		c.SetAssessmentHealthObserver(obs)

		claim := ctBaseClaim()
		if err := c.Reconcile(context.Background(), claim); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if obs.begun != 2 || len(obs.finished) != 2 {
			t.Fatalf("observations begun/finished = %d/%d, want 2/2 (one per dispatched call)", obs.begun, len(obs.finished))
		}
		want := []healthObservation{
			{claim.Situation.ID, situation.L2OutcomeMalformed, nil},
			{claim.Situation.ID, situation.L2OutcomeAccepted, nil},
		}
		for i, w := range want {
			got := obs.finished[i]
			if got.situationID != w.situationID || got.outcome != w.outcome || got.transportErr != nil {
				t.Fatalf("observation %d = %+v, want %+v", i, got, w)
			}
		}
	})

	t.Run("transport failure carries the error", func(t *testing.T) {
		in := ctBaseSnapshotInput()
		store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1, beginRetryEpoch: 0}
		transportErr := errors.New("dial tcp: connection refused")
		client := &fakeAssessmentClient{responses: []func() (llm.OneShotCompletion, error){
			func() (llm.OneShotCompletion, error) {
				return llm.OneShotCompletion{RequestStarted: llm.RequestStartStatusUnknown}, transportErr
			},
		}}
		c := ctController(t, store, client)
		obs := &fakeHealthObserver{}
		c.SetAssessmentHealthObserver(obs)

		if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if len(obs.finished) != 1 {
			t.Fatalf("observations = %d, want 1", len(obs.finished))
		}
		got := obs.finished[0]
		if got.outcome != situation.L2OutcomeTransportFailure || !errors.Is(got.transportErr, transportErr) {
			t.Fatalf("observation = %+v, want transport_failure carrying the CompleteOnce error", got)
		}
	})

	t.Run("policy rejection is reported as policy_rejected", func(t *testing.T) {
		in := ctBaseSnapshotInput()
		store := &fakeControllerStore{loadInput: in, beginWorkAttempt: 1, beginRetryEpoch: 0}
		client := &fakeAssessmentClient{responses: []func() (llm.OneShotCompletion, error){policyRejectedResponse(t)}}
		c := ctController(t, store, client)
		obs := &fakeHealthObserver{}
		c.SetAssessmentHealthObserver(obs)

		if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if len(obs.finished) != 1 || obs.finished[0].outcome != situation.L2OutcomePolicyRejected {
			t.Fatalf("observations = %+v, want exactly one policy_rejected", obs.finished)
		}
	})
}
