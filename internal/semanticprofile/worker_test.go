// SPDX-License-Identifier: FSL-1.1-ALv2

package semanticprofile_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/semanticprofile"
	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
)

// --------------------------------------------------------------------------
// Fakes.
// --------------------------------------------------------------------------

type fakeProfileStore struct {
	mu sync.Mutex

	claims     []profilemodel.JobClaim
	claimIdx   int
	claimErr   error
	claimCalls int

	reserveCallID  string
	reserveAttempt int
	reserveErr     error
	reserveCalls   []string // job IDs

	completeCalls []profilemodel.InferenceResult
	completeErr   error

	extendCalls int
	extendErr   error
}

func (f *fakeProfileStore) ClaimSemanticInferenceJob(ctx context.Context, owner string, now time.Time, lease time.Duration) (profilemodel.JobClaim, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claimCalls++
	if f.claimErr != nil {
		return profilemodel.JobClaim{}, false, f.claimErr
	}
	if f.claimIdx >= len(f.claims) {
		return profilemodel.JobClaim{}, false, nil
	}
	c := f.claims[f.claimIdx]
	f.claimIdx++
	return c, true, nil
}

func (f *fakeProfileStore) ReserveSemanticInferenceCall(ctx context.Context, jobID, owner string, token int64, now time.Time) (string, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reserveCalls = append(f.reserveCalls, jobID)
	if f.reserveErr != nil {
		return "", 0, f.reserveErr
	}
	id := f.reserveCallID
	if id == "" {
		id = "call-1"
	}
	attempt := f.reserveAttempt
	if attempt == 0 {
		attempt = 1
	}
	return id, attempt, nil
}

func (f *fakeProfileStore) CompleteSemanticInference(ctx context.Context, callID, owner string, token int64, result profilemodel.InferenceResult, now time.Time, retryAt *time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.completeCalls = append(f.completeCalls, result)
	return f.completeErr
}

func (f *fakeProfileStore) ExtendSemanticInferenceJobLease(ctx context.Context, jobID, owner string, token int64, now time.Time, lease time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.extendCalls++
	return f.extendErr
}

func (f *fakeProfileStore) snapshotComplete() []profilemodel.InferenceResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]profilemodel.InferenceResult(nil), f.completeCalls...)
}

type fakeCompletionClient struct {
	mu        sync.Mutex
	responses []func() (llm.OneShotCompletion, error)
	calls     int
	ctxFn     func(ctx context.Context) (llm.OneShotCompletion, error)
}

func (f *fakeCompletionClient) CompleteOnce(ctx context.Context, systemPrompt string, prompt llm.Prompt, requiredKeys []string) (llm.OneShotCompletion, error) {
	f.mu.Lock()
	idx := f.calls
	f.calls++
	fn := f.ctxFn
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx)
	}
	if idx >= len(f.responses) {
		return llm.OneShotCompletion{}, errors.New("fakeCompletionClient: no more scripted responses")
	}
	return f.responses[idx]()
}

type fakeInferenceObservation struct {
	finishErr *error
}

func (o *fakeInferenceObservation) Finish(err error) { *o.finishErr = err }

type fakeHealthObserver struct {
	mu       sync.Mutex
	begun    []string
	finished []error
}

func (f *fakeHealthObserver) BeginInferenceCall(signature string) semanticprofile.InferenceCallObservation {
	f.mu.Lock()
	f.begun = append(f.begun, signature)
	f.mu.Unlock()
	var errSlot error
	obs := &fakeInferenceObservation{finishErr: &errSlot}
	return &recordingObservation{inner: obs, tracker: f}
}

type recordingObservation struct {
	inner   *fakeInferenceObservation
	tracker *fakeHealthObserver
}

func (r *recordingObservation) Finish(err error) {
	r.inner.Finish(err)
	r.tracker.mu.Lock()
	r.tracker.finished = append(r.tracker.finished, err)
	r.tracker.mu.Unlock()
}

func validProfileJSON(t *testing.T) json.RawMessage {
	t.Helper()
	p := profilemodel.Profile{
		SubjectKind: "service", EventKind: "availability", PossibleRole: "symptom",
		CandidateScope: []string{"service"}, HorizonTier: "hours",
		UsefulCapabilities: []string{"prometheus_query"},
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal profile: %v", err)
	}
	return b
}

func frozenInputJSON(t *testing.T) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(profilemodel.SignatureInput{Source: "zabbix", AlertName: "DiskFull"})
	if err != nil {
		t.Fatalf("marshal frozen input: %v", err)
	}
	return b
}

func testClaim(jobID, signature string, frozen json.RawMessage) profilemodel.JobClaim {
	return profilemodel.JobClaim{
		JobID: jobID, Signature: signature, FrozenInputJSON: frozen,
		Owner: "worker-a", Token: 1, LeaseExpiresAt: time.Now().Add(time.Minute),
	}
}

func newTestWorker(store *fakeProfileStore, client *fakeCompletionClient, health *fakeHealthObserver, limiter *llm.InferenceLimiter) *semanticprofile.Worker {
	cfg := semanticprofile.WorkerConfig{Owner: "worker-a", Lease: time.Minute, AttemptWall: time.Second, Heartbeat: 50 * time.Millisecond}
	w := semanticprofile.NewWorker(store, client, limiter, cfg, nil, nil)
	if health != nil {
		w.SetHealthObserver(health)
	}
	return w
}

// --------------------------------------------------------------------------
// Tests.
// --------------------------------------------------------------------------

func TestWorkerRunOnceAcceptedProfileCompletesSuccessfully(t *testing.T) {
	claim := testClaim("job-1", "sig-1", frozenInputJSON(t))
	store := &fakeProfileStore{claims: []profilemodel.JobClaim{claim}}
	profile := validProfileJSON(t)
	client := &fakeCompletionClient{responses: []func() (llm.OneShotCompletion, error){
		func() (llm.OneShotCompletion, error) {
			return llm.OneShotCompletion{Completion: llm.Completion{Raw: profile, Model: "claude"}, RequestStarted: llm.RequestStartStatusTrue}, nil
		},
	}}
	health := &fakeHealthObserver{}
	limiter := llm.NewInferenceLimiter(2)
	w := newTestWorker(store, client, health, limiter)

	n, err := w.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 {
		t.Fatalf("handled = %d, want 1", n)
	}
	if len(store.reserveCalls) != 1 || store.reserveCalls[0] != "job-1" {
		t.Fatalf("reserve calls = %v, want [job-1]", store.reserveCalls)
	}
	results := store.snapshotComplete()
	if len(results) != 1 {
		t.Fatalf("complete calls = %d, want 1", len(results))
	}
	if results[0].Outcome != profilemodel.InferenceOutcomeAccepted {
		t.Fatalf("outcome = %q, want accepted", results[0].Outcome)
	}
	if results[0].Profile == nil || results[0].Profile.SubjectKind != "service" {
		t.Fatalf("profile = %+v, want the parsed subject_kind=service profile", results[0].Profile)
	}
	if len(health.finished) != 1 || health.finished[0] != nil {
		t.Fatalf("health.finished = %v, want one nil (success)", health.finished)
	}
	if len(health.begun) != 1 || health.begun[0] != "sig-1" {
		t.Fatalf("health.begun = %v, want [sig-1]", health.begun)
	}
}

func TestWorkerRunOnceMalformedResponseRecordsMalformedAndUnhealthy(t *testing.T) {
	claim := testClaim("job-2", "sig-2", frozenInputJSON(t))
	store := &fakeProfileStore{claims: []profilemodel.JobClaim{claim}}
	client := &fakeCompletionClient{responses: []func() (llm.OneShotCompletion, error){
		func() (llm.OneShotCompletion, error) {
			// "attention" and "apply_envelope" are forbidden nested policy/action
			// fields — ParseProfile must reject this outright.
			return llm.OneShotCompletion{
				Completion:     llm.Completion{Raw: json.RawMessage(`{"subject_kind":"service","event_kind":"availability","possible_role":"symptom","candidate_scope":["service"],"companion_signal_kinds":[],"horizon_tier":"hours","useful_capabilities":["prometheus_query"],"uncertainty":[],"attention":"observe","apply_envelope":true}`)},
				RequestStarted: llm.RequestStartStatusTrue,
			}, nil
		},
	}}
	health := &fakeHealthObserver{}
	w := newTestWorker(store, client, health, llm.NewInferenceLimiter(2))

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	results := store.snapshotComplete()
	if len(results) != 1 || results[0].Outcome != profilemodel.InferenceOutcomeMalformed {
		t.Fatalf("results = %+v, want one malformed outcome", results)
	}
	if len(health.finished) != 1 || health.finished[0] == nil {
		t.Fatal("expected health.Finish to be called with a non-nil error for a malformed response")
	}
}

func TestWorkerRunOnceTransportFailureRecordsFailed(t *testing.T) {
	claim := testClaim("job-3", "sig-3", frozenInputJSON(t))
	store := &fakeProfileStore{claims: []profilemodel.JobClaim{claim}}
	transportErr := errors.New("connection reset")
	client := &fakeCompletionClient{responses: []func() (llm.OneShotCompletion, error){
		func() (llm.OneShotCompletion, error) {
			return llm.OneShotCompletion{RequestStarted: llm.RequestStartStatusUnknown}, transportErr
		},
	}}
	health := &fakeHealthObserver{}
	w := newTestWorker(store, client, health, llm.NewInferenceLimiter(2))

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	results := store.snapshotComplete()
	if len(results) != 1 || results[0].Outcome != profilemodel.InferenceOutcomeFailed {
		t.Fatalf("results = %+v, want one failed outcome", results)
	}
	if len(health.finished) != 1 || health.finished[0] == nil {
		t.Fatal("expected health.Finish to be called with a non-nil error for a transport failure")
	}
}

func TestWorkerRunOnceNoDueJobIsANoop(t *testing.T) {
	store := &fakeProfileStore{}
	client := &fakeCompletionClient{}
	w := newTestWorker(store, client, nil, llm.NewInferenceLimiter(2))

	n, err := w.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 {
		t.Fatalf("handled = %d, want 0", n)
	}
	if len(store.reserveCalls) != 0 || client.calls != 0 {
		t.Fatalf("no due job must dispatch nothing: reserveCalls=%v CompleteOnce calls=%d", store.reserveCalls, client.calls)
	}
}

func TestWorkerRunOnceExhaustedReservationIsHandledWithoutDispatch(t *testing.T) {
	claim := testClaim("job-4", "sig-4", frozenInputJSON(t))
	store := &fakeProfileStore{claims: []profilemodel.JobClaim{claim}, reserveErr: semanticprofile.ErrAttemptsExhausted}
	client := &fakeCompletionClient{}
	w := newTestWorker(store, client, nil, llm.NewInferenceLimiter(2))

	n, err := w.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 {
		t.Fatalf("handled = %d, want 1 (the job was still claimed and processed, even though exhausted)", n)
	}
	if client.calls != 0 {
		t.Fatalf("CompleteOnce calls = %d, want 0: an exhausted reservation must never dispatch", client.calls)
	}
}

func TestWorkerRunOnceHeartbeatsDuringASlowCall(t *testing.T) {
	claim := testClaim("job-5", "sig-5", frozenInputJSON(t))
	store := &fakeProfileStore{claims: []profilemodel.JobClaim{claim}}
	profile := validProfileJSON(t)
	started := make(chan struct{})
	proceed := make(chan struct{})
	client := &fakeCompletionClient{ctxFn: func(ctx context.Context) (llm.OneShotCompletion, error) {
		close(started)
		<-proceed
		return llm.OneShotCompletion{Completion: llm.Completion{Raw: profile}, RequestStarted: llm.RequestStartStatusTrue}, nil
	}}
	w := newTestWorker(store, client, nil, llm.NewInferenceLimiter(2))

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := w.RunOnce(context.Background()); err != nil {
			t.Errorf("RunOnce: %v", err)
		}
	}()

	<-started
	time.Sleep(150 * time.Millisecond) // several heartbeat intervals (50ms) while the call is "in flight"
	close(proceed)
	<-done

	store.mu.Lock()
	extendCalls := store.extendCalls
	store.mu.Unlock()
	if extendCalls == 0 {
		t.Fatal("expected at least one heartbeat lease extension during the slow call")
	}
}

func TestWorkerRunOnceDispatchesThroughTheSharedLimiter(t *testing.T) {
	limiter := llm.NewInferenceLimiter(1)
	releaseActive, err := limiter.Acquire(context.Background(), llm.InferenceAssessment)
	if err != nil {
		t.Fatalf("pre-acquire the shared limiter's one slot: %v", err)
	}
	defer releaseActive()

	claim := testClaim("job-6", "sig-6", frozenInputJSON(t))
	store := &fakeProfileStore{claims: []profilemodel.JobClaim{claim}}
	client := &fakeCompletionClient{responses: []func() (llm.OneShotCompletion, error){
		func() (llm.OneShotCompletion, error) {
			return llm.OneShotCompletion{Completion: llm.Completion{Raw: validProfileJSON(t)}, RequestStarted: llm.RequestStartStatusTrue}, nil
		},
	}}
	cfg := semanticprofile.WorkerConfig{Owner: "worker-a", Lease: time.Minute, AttemptWall: 50 * time.Millisecond, Heartbeat: time.Second}
	w := semanticprofile.NewWorker(store, client, limiter, cfg, nil, nil)

	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if client.calls != 0 {
		t.Fatalf("CompleteOnce calls = %d, want 0: the shared limiter's one slot was held externally the whole time", client.calls)
	}
	results := store.snapshotComplete()
	if len(results) != 1 || results[0].Outcome != profilemodel.InferenceOutcomeFailed {
		t.Fatalf("results = %+v, want one failed outcome (AttemptWall expired while waiting for the shared limiter)", results)
	}
}

func TestWorkerDrainProcessesUntilEmpty(t *testing.T) {
	claims := []profilemodel.JobClaim{
		testClaim("job-a", "sig-a", frozenInputJSON(t)),
		testClaim("job-b", "sig-b", frozenInputJSON(t)),
	}
	store := &fakeProfileStore{claims: claims}
	client := &fakeCompletionClient{responses: []func() (llm.OneShotCompletion, error){
		func() (llm.OneShotCompletion, error) {
			return llm.OneShotCompletion{Completion: llm.Completion{Raw: validProfileJSON(t)}, RequestStarted: llm.RequestStartStatusTrue}, nil
		},
		func() (llm.OneShotCompletion, error) {
			return llm.OneShotCompletion{Completion: llm.Completion{Raw: validProfileJSON(t)}, RequestStarted: llm.RequestStartStatusTrue}, nil
		},
	}}
	w := newTestWorker(store, client, nil, llm.NewInferenceLimiter(2))

	n, err := w.Drain(context.Background())
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if n != 2 {
		t.Fatalf("drained = %d, want 2", n)
	}
	if len(store.snapshotComplete()) != 2 {
		t.Fatalf("complete calls = %d, want 2", len(store.snapshotComplete()))
	}
}

func TestWorkerStartWakeStop(t *testing.T) {
	claim := testClaim("job-start", "sig-start", frozenInputJSON(t))
	store := &fakeProfileStore{claims: []profilemodel.JobClaim{claim}}
	client := &fakeCompletionClient{responses: []func() (llm.OneShotCompletion, error){
		func() (llm.OneShotCompletion, error) {
			return llm.OneShotCompletion{Completion: llm.Completion{Raw: validProfileJSON(t)}, RequestStarted: llm.RequestStartStatusTrue}, nil
		},
	}}
	cfg := semanticprofile.WorkerConfig{Owner: "worker-a", Lease: time.Minute, AttemptWall: time.Second, Heartbeat: time.Second, Interval: 5 * time.Millisecond}
	w := semanticprofile.NewWorker(store, client, llm.NewInferenceLimiter(2), cfg, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for len(store.snapshotComplete()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(store.snapshotComplete()) == 0 {
		t.Fatal("expected Start's background loop to process the claimed job")
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
	defer stopCancel()
	if err := w.Stop(stopCtx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}
