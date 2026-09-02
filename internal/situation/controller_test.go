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
	releaseCalls []situation.Claim
	releaseErr   error
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

func (f *fakeControllerStore) ReleaseControllerWork(ctx context.Context, claim situation.Claim, now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releaseCalls = append(f.releaseCalls, claim)
	return f.releaseErr
}

func (f *fakeControllerStore) snapshotExtendCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.extendCalls)
}

func (f *fakeControllerStore) snapshotReleaseCalls() []situation.Claim {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]situation.Claim(nil), f.releaseCalls...)
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
}

func TestControllerReconcileDeterministicUrgentFloorCommitsWithoutL2(t *testing.T) {
	in := ctBaseSnapshotInput()
	in.Deliveries = []situation.Delivery{ctDelivery("delivery-1", "incident-1", true, "critical")}

	store := &fakeControllerStore{loadInput: in}
	client := &fakeAssessmentClient{}
	c := ctController(t, store, client)

	if err := c.Reconcile(context.Background(), ctBaseClaim()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if client.calls != 0 {
		t.Fatalf("CompleteOnce calls = %d, want 0 (deterministic floor must not wait for L2)", client.calls)
	}
	if len(store.commits) != 1 {
		t.Fatalf("commits = %d, want 1", len(store.commits))
	}
	commit := store.commits[0]
	if commit.Attempt.Derivation != model.DerivationDeterministic {
		t.Fatalf("derivation = %q, want %q", commit.Attempt.Derivation, model.DerivationDeterministic)
	}
	if commit.Attention != model.AttentionUrgent {
		t.Fatalf("attention = %q, want urgent", commit.Attention)
	}
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
