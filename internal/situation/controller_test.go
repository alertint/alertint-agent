// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// --------------------------------------------------------------------------
// Fakes
// --------------------------------------------------------------------------

// fakeStore is an in-memory Store used only by this package's own tests. It
// has no persistence semantics beyond what each test scenario needs.
type fakeStore struct {
	mu sync.Mutex

	claims      map[string]Claim
	inputs      map[string]SnapshotInput
	incidentIDs map[string]string
	analysis    map[string]AnalysisState
	trusted     map[string]TrustedAssessment
	prior       map[string]*model.Assessment

	staleNext bool

	attempts    []AssessmentAttempt
	committed   []model.Transition
	rescheduled []time.Time
	parked      []string // decision reasons
	dueMarks    []model.DueReason
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		claims: map[string]Claim{}, inputs: map[string]SnapshotInput{}, incidentIDs: map[string]string{},
		analysis: map[string]AnalysisState{}, trusted: map[string]TrustedAssessment{}, prior: map[string]*model.Assessment{},
	}
}

func (f *fakeStore) ClaimedSituation(_ context.Context, situationID string) (Claim, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	claim, ok := f.claims[situationID]
	if !ok {
		return Claim{}, errors.New("fake store: situation not claimed")
	}
	return claim, nil
}

func (f *fakeStore) LoadReconciliationInput(_ context.Context, claim Claim) (SnapshotInput, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	in, ok := f.inputs[claim.Situation.ID]
	if !ok {
		return SnapshotInput{}, "", errors.New("fake store: no reconciliation input seeded")
	}
	return in, f.incidentIDs[claim.Situation.ID], nil
}

func (f *fakeStore) AnalysisState(_ context.Context, incidentID string) (AnalysisState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.analysis[incidentID], nil
}

func (f *fakeStore) SetAnalysisState(_ context.Context, state AnalysisState) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.analysis[state.IncidentID] = state
	return nil
}

func (f *fakeStore) LastTrustedAssessment(_ context.Context, claim Claim) (TrustedAssessment, *model.Assessment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.trusted[claim.Situation.ID], f.prior[claim.Situation.ID], nil
}

func (f *fakeStore) AppendAssessmentAttempt(_ context.Context, _ Claim, attempt AssessmentAttempt) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts = append(f.attempts, attempt)
	return nil
}

func (f *fakeStore) CommitAuthoritative(_ context.Context, claim Claim, attempt AssessmentAttempt, tr model.Transition) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.staleNext {
		f.staleNext = false
		return ErrStaleInput
	}
	f.attempts = append(f.attempts, attempt)
	f.committed = append(f.committed, tr)
	var validated model.Assessment
	_ = json.Unmarshal(attempt.Validated, &validated)
	f.trusted[claim.Situation.ID] = TrustedAssessment{Sequence: attempt.Sequence, FactHash: attempt.FactHash, Trustworthy: true}
	f.prior[claim.Situation.ID] = &validated
	return nil
}

func (f *fakeStore) Reschedule(_ context.Context, _ Claim, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rescheduled = append(f.rescheduled, at)
	return nil
}

func (f *fakeStore) Park(_ context.Context, _ Claim, _ time.Time, decisionReason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.parked = append(f.parked, decisionReason)
	return nil
}

func (f *fakeStore) MarkDue(_ context.Context, _ string, reason model.DueReason, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dueMarks = append(f.dueMarks, reason)
	return nil
}

func (f *fakeStore) analysisStatus(incidentID string) L1Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.analysis[incidentID].Status
}

func (f *fakeStore) committedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.committed)
}

func (f *fakeStore) lastCommitted() model.Transition {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.committed[len(f.committed)-1]
}

// blockingInvestigator blocks Investigate until the harness unblocks it, so
// a test can assert Reconcile returns without waiting on L1.
type blockingInvestigator struct {
	unblock chan struct{}
	done    chan struct{}
}

func blockingAcuteInvestigator() *blockingInvestigator {
	return &blockingInvestigator{unblock: make(chan struct{}), done: make(chan struct{})}
}

func (b *blockingInvestigator) Investigate(_ context.Context, incidentID string) (AcuteResult, error) {
	defer close(b.done)
	<-b.unblock
	return AcuteResult{IncidentID: incidentID, RootCause: "resolved", Confidence: 0.9, CompletedAt: time.Now().UTC()}, nil
}

// noopInvestigator completes immediately without a durable finding — used
// when a test only cares about the L2/commit path.
type noopInvestigator struct{}

func (noopInvestigator) Investigate(_ context.Context, incidentID string) (AcuteResult, error) {
	return AcuteResult{IncidentID: incidentID, CompletedAt: time.Now().UTC()}, nil
}

// fakeAssessor returns queued completions in order, repeating the last one.
type fakeAssessor struct {
	mu          sync.Mutex
	completions []llm.Completion
	err         error
	calls       int
}

func (f *fakeAssessor) Complete(_ context.Context, _ string, _ llm.Prompt, _ []string) (llm.Completion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return llm.Completion{}, f.err
	}
	idx := f.calls - 1
	if idx >= len(f.completions) {
		idx = len(f.completions) - 1
	}
	return f.completions[idx], nil
}

func (f *fakeAssessor) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// --------------------------------------------------------------------------
// Harness
// --------------------------------------------------------------------------

const harnessSituationID = "s-1" // matches reasons_test.go's sampleSnapshot()/fact() fixtures
const harnessIncidentID = "inc-1"

type controllerHarness struct {
	t          *testing.T
	controller *Controller
	store      *fakeStore
	assessor   *fakeAssessor
	now        time.Time
}

func newControllerHarness(t *testing.T, acute AcuteInvestigator) *controllerHarness {
	return newControllerHarnessWithAssessor(t, acute, nil)
}

func newControllerHarnessWithAssessor(t *testing.T, acute AcuteInvestigator, assessor *fakeAssessor) *controllerHarness {
	t.Helper()
	st := newFakeStore()
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	var client AssessmentClient
	if assessor != nil {
		client = assessor
	}
	ctrl := NewController(st, nil, nil, acute, client, func() time.Time { return now }, Config{})
	return &controllerHarness{t: t, controller: ctrl, store: st, assessor: assessor, now: now}
}

// seedSituation seeds a claimed active Situation whose deterministic
// evidence matches the named reason-catalog code (reasons_test.go's
// snapshotForReasonEvidence), with the given prior attempt count.
func (h *controllerHarness) seedSituation(code string, attemptCount int) model.Situation {
	h.t.Helper()
	// -20 minutes matches snapshotWithCompletedDurations' baked-in
	// current_duration fact (elapsed_seconds=1200) used by the
	// duration_outlier fixture — BuildSnapshot always derives ElapsedSeconds
	// from EffectiveStartedAt/Now itself, so the Situation's own timing must
	// agree with the fixture's fact value or the candidate's evidence match
	// fails.
	situation := model.Situation{
		ID: harnessSituationID, GroupKey: "group-1", Lifecycle: model.LifecycleActive, Attention: model.AttentionObserve,
		InputVersion: 3, EffectiveStartedAt: h.now.Add(-20 * time.Minute), EffectiveStartedAtBasis: model.SourceTimeBasisSourcePayload,
		FirstReceivedAt: h.now.Add(-20 * time.Minute), LastLifecycleObservedAt: h.now.Add(-time.Minute),
		NextAssessmentAt: h.now, DueReasons: []model.DueReason{model.DueIncidentCreated}, AttemptCount: attemptCount,
		CreatedAt: h.now.Add(-20 * time.Minute), UpdatedAt: h.now,
	}
	claim := Claim{Situation: situation, ClaimOwner: "worker-1", ClaimToken: 1}
	h.store.claims[harnessSituationID] = claim
	h.store.inputs[harnessSituationID] = snapshotInputFor(code, situation, h.now)
	h.store.incidentIDs[harnessSituationID] = harnessIncidentID
	return situation
}

func (h *controllerHarness) seedCriticalInput() {
	h.seedSituation("critical_anchor", 0)
}

func (h *controllerHarness) reconcile() error {
	h.t.Helper()
	return h.controller.Reconcile(context.Background(), harnessSituationID)
}

func (h *controllerHarness) assertRootIntentPersisted() {
	h.t.Helper()
	if h.store.committedCount() != 1 {
		h.t.Fatalf("committed transitions = %d, want 1", h.store.committedCount())
	}
	tr := h.store.lastCommitted()
	if tr.Attention != model.AttentionUrgent {
		h.t.Fatalf("committed attention = %s, want urgent", tr.Attention)
	}
}

func (h *controllerHarness) assertL1State(status L1Status) {
	h.t.Helper()
	if got := h.store.analysisStatus(harnessIncidentID); got != status {
		h.t.Fatalf("l1 state = %s, want %s", got, status)
	}
}

// snapshotInputFor copies the type-compatible material fields
// snapshotForReasonEvidence produced into a SnapshotInput BuildSnapshot can
// reduce, paired with a real Situation. Envelope/Judgments/L1 are left zero
// — none of the codes this package's tests use need them.
func snapshotInputFor(code string, situation model.Situation, now time.Time) SnapshotInput {
	src, _ := snapshotForReasonEvidence(code)
	return SnapshotInput{
		Situation: situation, Now: now,
		Symptoms: src.Symptoms, Facts: src.Facts, Impact: src.Impact, BlastRadius: src.BlastRadius,
		UrgentPolicies: src.UrgentPolicies, SemanticChoice: src.SemanticChoice, TerminalUncertainty: src.TerminalUncertainty,
		ConnectorStates: src.ConnectorStates, Limitations: src.Limitations, CompletedEpisodes: src.CompletedEpisodes,
		CurrentDurationEvidenceRefs: src.CurrentDurationEvidenceRefs, DurationClass: src.DurationClass,
		RecurrenceClass: src.RecurrenceClass, CrossedMilestones: src.CrossedMilestones,
	}
}

func validAssessmentCompletion(t *testing.T) llm.Completion {
	t.Helper()
	raw, err := json.Marshal(validInvestigateProposal(t))
	if err != nil {
		t.Fatalf("marshal valid proposal: %v", err)
	}
	return llm.Completion{Raw: raw, Model: "fake-model"}
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

// TestCriticalPublishesBeforeL1Finishes verifies a deterministic urgent
// floor commits its root Assessment without waiting on L1: Reconcile
// returns even though the acute investigator never completes, and the B+
// gate state is durably "planned" (dispatched, not blocking).
func TestCriticalPublishesBeforeL1Finishes(t *testing.T) {
	blocking := blockingAcuteInvestigator()
	t.Cleanup(func() { close(blocking.unblock); <-blocking.done })
	h := newControllerHarness(t, blocking)
	h.seedCriticalInput()
	if err := h.reconcile(); err != nil {
		t.Fatal(err)
	}
	h.assertRootIntentPersisted()
	h.assertL1State(L1StatusPlanned)
}

// TestReconcileCommitsValidL2Proposal is the green-path control: a fresh
// Situation with no deterministic floor and a genuinely eligible non-floor
// reason gets a validated L2 Assessment committed from the assessor's first
// response.
func TestReconcileCommitsValidL2Proposal(t *testing.T) {
	assessor := &fakeAssessor{completions: []llm.Completion{validAssessmentCompletion(t)}}
	h := newControllerHarnessWithAssessor(t, noopInvestigator{}, assessor)
	h.seedSituation("duration_outlier", 0)

	if err := h.reconcile(); err != nil {
		t.Fatal(err)
	}
	if h.store.committedCount() != 1 {
		t.Fatalf("committed transitions = %d, want 1", h.store.committedCount())
	}
	if got := h.store.lastCommitted().Attention; got != model.AttentionInvestigate {
		t.Fatalf("committed attention = %s, want investigate", got)
	}
	if assessor.callCount() != 1 {
		t.Fatalf("assessor calls = %d, want 1", assessor.callCount())
	}
}

// TestReconcileWastedL1RunDoesNotTriggerL2 verifies that once a trustworthy
// Assessment already covers the exact current material hash — including the
// case where that hash already reflects a completed L1 finding whose
// classified conclusion did not change ("wasted" run) — Reconcile makes no
// L2 call and commits nothing further.
func TestReconcileWastedL1RunDoesNotTriggerL2(t *testing.T) {
	assessor := &fakeAssessor{completions: []llm.Completion{validAssessmentCompletion(t)}}
	h := newControllerHarnessWithAssessor(t, noopInvestigator{}, assessor)
	situation := h.seedSituation("duration_outlier", 0)

	in := h.store.inputs[harnessSituationID]
	snap, err := BuildSnapshot(in)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	h.store.trusted[harnessSituationID] = TrustedAssessment{Sequence: 1, FactHash: snap.MaterialHash, Trustworthy: true}
	h.store.prior[harnessSituationID] = &model.Assessment{SchemaVersion: AssessmentSchemaVersion, Attention: model.AttentionInvestigate, Lifecycle: situation.Lifecycle}

	if err := h.reconcile(); err != nil {
		t.Fatal(err)
	}
	if assessor.callCount() != 0 {
		t.Fatalf("assessor calls = %d, want 0 (already covered)", assessor.callCount())
	}
	if h.store.committedCount() != 0 {
		t.Fatalf("committed transitions = %d, want 0 (already covered)", h.store.committedCount())
	}
	h.assertL1State(L1StatusNotRequested)
}

// TestReconcileStaleCommitStoresStaleAndReschedules verifies a commit that
// arrives after the claimed input version has moved on is stored as
// `stale`, produces no outward transition, and reschedules the current
// input rather than failing the reconciliation.
func TestReconcileStaleCommitStoresStaleAndReschedules(t *testing.T) {
	assessor := &fakeAssessor{completions: []llm.Completion{validAssessmentCompletion(t)}}
	h := newControllerHarnessWithAssessor(t, noopInvestigator{}, assessor)
	h.seedSituation("duration_outlier", 0)
	h.store.staleNext = true

	if err := h.reconcile(); err != nil {
		t.Fatalf("Reconcile: %v (a stale commit must not fail reconciliation)", err)
	}
	if h.store.committedCount() != 0 {
		t.Fatalf("committed transitions = %d, want 0", h.store.committedCount())
	}
	if len(h.store.rescheduled) != 1 {
		t.Fatalf("rescheduled = %d, want 1", len(h.store.rescheduled))
	}
	found := false
	for _, attempt := range h.store.attempts {
		if attempt.Status == AttemptStatusStale {
			found = true
		}
	}
	if !found {
		t.Fatalf("attempts = %+v, want a stale attempt", h.store.attempts)
	}
}

// TestReconcileParksAfterMaxAttempts verifies an unchanged input that has
// already exhausted its attempt budget is parked — preserving whatever
// Assessment already stands — rather than attempting another L2 call or
// deriving terminality from the exhaustion.
func TestReconcileParksAfterMaxAttempts(t *testing.T) {
	assessor := &fakeAssessor{completions: []llm.Completion{validAssessmentCompletion(t)}}
	h := newControllerHarnessWithAssessor(t, noopInvestigator{}, assessor)
	h.seedSituation("duration_outlier", 5) // == default MaxAttemptsPerInput

	if err := h.reconcile(); err != nil {
		t.Fatal(err)
	}
	if assessor.callCount() != 0 {
		t.Fatalf("assessor calls = %d, want 0 (parked before attempting L2)", assessor.callCount())
	}
	if h.store.committedCount() != 0 {
		t.Fatalf("committed transitions = %d, want 0", h.store.committedCount())
	}
	if len(h.store.parked) != 1 {
		t.Fatalf("parked = %d, want 1", len(h.store.parked))
	}
}

// TestReconcileDegradesWhenAssessorUnavailable verifies a Situation with no
// deterministic floor and no wired assessor still gets an authoritative,
// honestly degraded Assessment (quiet, insufficient evidence quality) rather
// than being left without a current Assessment.
func TestReconcileDegradesWhenAssessorUnavailable(t *testing.T) {
	h := newControllerHarness(t, noopInvestigator{})
	h.seedSituation("duration_outlier", 0)

	if err := h.reconcile(); err != nil {
		t.Fatal(err)
	}
	if h.store.committedCount() != 1 {
		t.Fatalf("committed transitions = %d, want 1", h.store.committedCount())
	}
	tr := h.store.lastCommitted()
	if tr.Attention != model.AttentionObserve {
		t.Fatalf("committed attention = %s, want observe (safe degraded default)", tr.Attention)
	}
	if tr.Assessment == nil || tr.Assessment.EvidenceQuality != model.EvidenceQualityInsufficient {
		t.Fatalf("assessment = %+v, want insufficient evidence quality", tr.Assessment)
	}
}

// TestReconcileRetriesOnceOnMalformedJSON verifies a syntactically invalid
// first response gets one corrective retry (audited as a failed attempt),
// and a valid second response still commits within the two-call budget.
func TestReconcileRetriesOnceOnMalformedJSON(t *testing.T) {
	assessor := &fakeAssessor{completions: []llm.Completion{
		{Raw: json.RawMessage(`not json`), Model: "fake-model"},
		validAssessmentCompletion(t),
	}}
	h := newControllerHarnessWithAssessor(t, noopInvestigator{}, assessor)
	h.seedSituation("duration_outlier", 0)

	if err := h.reconcile(); err != nil {
		t.Fatal(err)
	}
	if assessor.callCount() != 2 {
		t.Fatalf("assessor calls = %d, want 2 (one corrective retry)", assessor.callCount())
	}
	if h.store.committedCount() != 1 {
		t.Fatalf("committed transitions = %d, want 1", h.store.committedCount())
	}
	if got := h.store.lastCommitted().Attention; got != model.AttentionInvestigate {
		t.Fatalf("committed attention = %s, want investigate", got)
	}
	found := false
	for _, attempt := range h.store.attempts {
		if attempt.Status == AttemptStatusFailed {
			found = true
		}
	}
	if !found {
		t.Fatalf("attempts = %+v, want a failed attempt recording the malformed response", h.store.attempts)
	}
}

// TestReconcilePolicyRejectionNeverRetries verifies a policy-violating
// proposal (an invented reason) is audited as rejected and never retried —
// only a syntactically invalid response earns the one corrective retry —
// and the cycle still ends in a safe deterministic degraded commit.
func TestReconcilePolicyRejectionNeverRetries(t *testing.T) {
	invalid := validInvestigateProposal(t)
	invalid.SufficientReason.CandidateID = "reason:invented:v1:nope"
	raw, err := json.Marshal(invalid)
	if err != nil {
		t.Fatal(err)
	}
	assessor := &fakeAssessor{completions: []llm.Completion{{Raw: raw, Model: "fake-model"}}}
	h := newControllerHarnessWithAssessor(t, noopInvestigator{}, assessor)
	h.seedSituation("duration_outlier", 0)

	if err := h.reconcile(); err != nil {
		t.Fatal(err)
	}
	if assessor.callCount() != 1 {
		t.Fatalf("assessor calls = %d, want 1 (policy rejection never retries)", assessor.callCount())
	}
	if h.store.committedCount() != 1 {
		t.Fatalf("committed transitions = %d, want 1 (deterministic degraded fallback)", h.store.committedCount())
	}
	if got := h.store.lastCommitted().Attention; got != model.AttentionObserve {
		t.Fatalf("committed attention = %s, want observe (degraded fallback after rejection)", got)
	}
	found := false
	for _, attempt := range h.store.attempts {
		if attempt.Status == AttemptStatusRejected {
			found = true
		}
	}
	if !found {
		t.Fatalf("attempts = %+v, want a rejected attempt recording the policy violation", h.store.attempts)
	}
}
