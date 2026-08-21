// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// --------------------------------------------------------------------------
// Input worker
// --------------------------------------------------------------------------

type fakeInputStore struct {
	mu       sync.Mutex
	pending  []InputClaim
	applied  []string
	retries  []string
	terminal []string
	applyErr map[string]error
}

func newFakeInputStore(claims ...InputClaim) *fakeInputStore {
	return &fakeInputStore{pending: claims, applyErr: map[string]error{}}
}

func (f *fakeInputStore) ClaimSituationInputs(_ context.Context, owner string, _ time.Time, _ time.Duration, limit int) ([]InputClaim, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.pending) == 0 {
		return nil, nil
	}
	if limit > len(f.pending) {
		limit = len(f.pending)
	}
	out := make([]InputClaim, 0, limit)
	for _, claim := range f.pending[:limit] {
		claim.ClaimOwner = owner
		claim.ClaimToken = 1
		out = append(out, claim)
	}
	f.pending = f.pending[limit:]
	return out, nil
}

func (f *fakeInputStore) ApplySituationInput(_ context.Context, claim InputClaim) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.applyErr[claim.ID]; ok {
		return err
	}
	f.applied = append(f.applied, claim.ID)
	return nil
}

func (f *fakeInputStore) RetrySituationInput(_ context.Context, claim InputClaim, _ string, _ time.Time, terminal bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if terminal {
		f.terminal = append(f.terminal, claim.ID)
	} else {
		f.retries = append(f.retries, claim.ID)
	}
	return nil
}

func inputClaim(id string) InputClaim {
	return InputClaim{ID: id, IncidentID: "inc-" + id, GroupKey: "group", Kind: "incident_created"}
}

func TestInputWorkerDrainsEveryPendingInput(t *testing.T) {
	store := newFakeInputStore(inputClaim("a"), inputClaim("b"), inputClaim("c"))
	w := NewInputWorker(store, WorkerConfig{Owner: "worker-1", Batch: 2}, fixedClock("2026-08-20T10:00:00Z"), nil)
	applied, err := w.Drain(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if applied != 3 {
		t.Fatalf("applied=%d, want every pending input replayed", applied)
	}
	if len(store.applied) != 3 {
		t.Fatalf("store applied=%v", store.applied)
	}
}

func TestInputWorkerRetriesRetryableApplyFailure(t *testing.T) {
	store := newFakeInputStore(inputClaim("a"))
	store.applyErr["a"] = errors.New("database is locked")
	w := NewInputWorker(store, WorkerConfig{Owner: "worker-1", MaxAttempts: 3}, fixedClock("2026-08-20T10:00:00Z"), nil)
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.retries) != 1 || len(store.terminal) != 0 {
		t.Fatalf("retries=%v terminal=%v", store.retries, store.terminal)
	}
}

func TestInputWorkerDeadLettersAfterAttemptBudget(t *testing.T) {
	claim := inputClaim("a")
	claim.AttemptCount = 5
	store := newFakeInputStore(claim)
	store.applyErr["a"] = errors.New("boom")
	w := NewInputWorker(store, WorkerConfig{Owner: "worker-1", MaxAttempts: 3}, fixedClock("2026-08-20T10:00:00Z"), nil)
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.terminal) != 1 {
		t.Fatalf("terminal=%v retries=%v", store.terminal, store.retries)
	}
}

// --------------------------------------------------------------------------
// Controller worker pool
// --------------------------------------------------------------------------

type fakeControllerStore struct {
	mu          sync.Mutex
	pending     []DueClaim
	extended    int
	released    []string
	completed   []string
	completedAt []time.Time
	extendErr   error
}

func (f *fakeControllerStore) ClaimDueSituations(_ context.Context, owner string, _ time.Time, _ time.Duration, limit int) ([]DueClaim, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.pending) == 0 {
		return nil, nil
	}
	if limit > len(f.pending) {
		limit = len(f.pending)
	}
	out := make([]DueClaim, 0, limit)
	for _, claim := range f.pending[:limit] {
		claim.ClaimOwner = owner
		claim.ClaimToken = 1
		out = append(out, claim)
	}
	f.pending = f.pending[limit:]
	return out, nil
}

func (f *fakeControllerStore) ExtendSituationLease(_ context.Context, _, _ string, _ int64, _ time.Time, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.extended++
	return f.extendErr
}

func (f *fakeControllerStore) ReleaseSituation(_ context.Context, claim DueClaim, _ string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.released = append(f.released, claim.SituationID)
	return nil
}

func (f *fakeControllerStore) CompleteSituation(_ context.Context, claim DueClaim, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.completed = append(f.completed, claim.SituationID)
	f.completedAt = append(f.completedAt, at)
	return nil
}

type fakeReconciler struct {
	mu   sync.Mutex
	seen []string
	err  error
}

func (f *fakeReconciler) Reconcile(_ context.Context, situationID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, situationID)
	return f.err
}

func TestWorkerPoolReconcilesEveryClaimedSituation(t *testing.T) {
	store := &fakeControllerStore{pending: []DueClaim{{SituationID: "s-1"}, {SituationID: "s-2"}}}
	reconciler := &fakeReconciler{}
	pool := NewWorkerPool(store, reconciler, WorkerConfig{Owner: "worker-1", Batch: 5}, fixedClock("2026-08-20T10:00:00Z"), nil)
	handled, err := pool.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if handled != 2 || len(reconciler.seen) != 2 {
		t.Fatalf("handled=%d seen=%v", handled, reconciler.seen)
	}
}

func TestWorkerPoolAlwaysCompletesAClaimThatCommittedNothing(t *testing.T) {
	// A reconciliation that finds the current fact hash already covered
	// commits nothing at all. Without an explicit completion the aggregate
	// would stay due-and-unleased forever, and the pool would re-claim it in
	// a tight loop instead of waiting out its idle cadence.
	store := &fakeControllerStore{pending: []DueClaim{{SituationID: "s-1"}}}
	pool := NewWorkerPool(store, &fakeReconciler{}, WorkerConfig{Owner: "worker-1", IdleCadence: 5 * time.Minute},
		fixedClock("2026-08-20T10:00:00Z"), nil)
	if _, err := pool.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.completed) != 1 || store.completed[0] != "s-1" {
		t.Fatalf("completed=%v", store.completed)
	}
	want := fixedClock("2026-08-20T10:00:00Z")().Add(5 * time.Minute)
	if !store.completedAt[0].Equal(want) {
		t.Fatalf("next assessment scheduled at %s, want %s", store.completedAt[0], want)
	}
}

func TestWorkerPoolReleasesClaimOnReconcileFailure(t *testing.T) {
	store := &fakeControllerStore{pending: []DueClaim{{SituationID: "s-1"}}}
	reconciler := &fakeReconciler{err: errors.New("boom")}
	pool := NewWorkerPool(store, reconciler, WorkerConfig{Owner: "worker-1"}, fixedClock("2026-08-20T10:00:00Z"), nil)
	if _, err := pool.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.released) != 1 || store.released[0] != "s-1" {
		t.Fatalf("released=%v", store.released)
	}
}

// --------------------------------------------------------------------------
// Notification worker
// --------------------------------------------------------------------------

type fakeNotificationStore struct {
	mu        sync.Mutex
	pending   []model.NotificationIntent
	delivered []string
	retried   []time.Time
	terminal  []string
}

func (f *fakeNotificationStore) ClaimNotificationIntents(_ context.Context, _ time.Time, _ time.Duration, limit int) ([]model.NotificationIntent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.pending) == 0 {
		return nil, nil
	}
	if limit > len(f.pending) {
		limit = len(f.pending)
	}
	out := append([]model.NotificationIntent(nil), f.pending[:limit]...)
	f.pending = f.pending[limit:]
	return out, nil
}

func (f *fakeNotificationStore) MarkNotificationDelivered(_ context.Context, id, _, _ string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delivered = append(f.delivered, id)
	return nil
}

func (f *fakeNotificationStore) RetryNotificationIntent(_ context.Context, id, _ string, retryAt time.Time, terminal bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if terminal {
		f.terminal = append(f.terminal, id)
	} else {
		f.retried = append(f.retried, retryAt)
	}
	return nil
}

type fakeDeliverer struct {
	mu   sync.Mutex
	sent []string
	err  error
}

func (f *fakeDeliverer) Deliver(_ context.Context, intent model.NotificationIntent) (NotificationDelivery, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return NotificationDelivery{}, f.err
	}
	f.sent = append(f.sent, intent.ID)
	return NotificationDelivery{Channel: "C1", MessageTS: "1.1"}, nil
}

type fakeRateLimit struct{ after time.Duration }

func (e *fakeRateLimit) Error() string                         { return "rate limited" }
func (e *fakeRateLimit) NotificationRetryAfter() time.Duration { return e.after }

func pendingIntent(id string) model.NotificationIntent {
	situationID := "s-1"
	return model.NotificationIntent{
		ID: id, IdempotencyKey: "key:" + id, SubjectKind: model.NotificationSubjectSituation,
		SubjectID: situationID, SituationID: &situationID, Kind: model.NotificationSituationRootCreate,
		MainChannelPoke: true, Status: model.NotificationPending, ClientMessageID: "cmid-" + id,
		CreatedAt: time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC),
	}
}

func TestNotificationWorkerDeliversAndRecordsCoordinates(t *testing.T) {
	store := &fakeNotificationStore{pending: []model.NotificationIntent{pendingIntent("n-1")}}
	deliverer := &fakeDeliverer{}
	w := NewNotificationWorker(store, deliverer, WorkerConfig{Owner: "notify-1"}, fixedClock("2026-08-20T10:00:00Z"), nil)
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.delivered) != 1 || store.delivered[0] != "n-1" {
		t.Fatalf("delivered=%v", store.delivered)
	}
	if len(deliverer.sent) != 1 {
		t.Fatalf("sent=%v", deliverer.sent)
	}
}

func TestNotificationWorkerHonorsServerRetryTiming(t *testing.T) {
	store := &fakeNotificationStore{pending: []model.NotificationIntent{pendingIntent("n-1")}}
	deliverer := &fakeDeliverer{err: &fakeRateLimit{after: 42 * time.Second}}
	w := NewNotificationWorker(store, deliverer, WorkerConfig{Owner: "notify-1", MaxAttempts: 5}, fixedClock("2026-08-20T10:00:00Z"), nil)
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.retried) != 1 {
		t.Fatalf("retried=%v terminal=%v", store.retried, store.terminal)
	}
	want := fixedClock("2026-08-20T10:00:00Z")().Add(42 * time.Second)
	if !store.retried[0].Equal(want) {
		t.Fatalf("retry at %s, want the server's own %s", store.retried[0], want)
	}
}

func TestNotificationWorkerKeepsFailedIntentDurableUntilBudgetExhausted(t *testing.T) {
	intent := pendingIntent("n-1")
	intent.AttemptCount = 9
	store := &fakeNotificationStore{pending: []model.NotificationIntent{intent}}
	deliverer := &fakeDeliverer{err: errors.New("channel_not_found")}
	w := NewNotificationWorker(store, deliverer, WorkerConfig{Owner: "notify-1", MaxAttempts: 5}, fixedClock("2026-08-20T10:00:00Z"), nil)
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.terminal) != 1 {
		t.Fatalf("terminal=%v retried=%v", store.terminal, store.retried)
	}
}

func TestNotificationWorkerWithoutDelivererLeavesIntentsPending(t *testing.T) {
	store := &fakeNotificationStore{pending: []model.NotificationIntent{pendingIntent("n-1")}}
	w := NewNotificationWorker(store, nil, WorkerConfig{Owner: "notify-1"}, fixedClock("2026-08-20T10:00:00Z"), nil)
	handled, err := w.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if handled != 0 || len(store.delivered) != 0 {
		t.Fatalf("handled=%d delivered=%v; a Situation with no Slack sink must leave intents durable", handled, store.delivered)
	}
}

// --------------------------------------------------------------------------
// Readiness gate
// --------------------------------------------------------------------------

func TestRunOnceHonorsTheReadinessGateOnEveryEntryPoint(t *testing.T) {
	store := newFakeInputStore(inputClaim("a"))
	ready := false
	var observed []error
	cfg := WorkerConfig{
		Owner:   "worker-1",
		Ready:   func(context.Context) bool { return ready },
		OnRound: func(_ int, err error) { observed = append(observed, err) },
	}
	w := NewInputWorker(store, cfg, fixedClock("2026-08-20T10:00:00Z"), nil)

	// Gate closed: the round body never runs, so nothing is claimed and the
	// observer is not called (a skipped round is not an outcome).
	applied, err := w.RunOnce(context.Background())
	if err != nil || applied != 0 {
		t.Fatalf("gated round applied=%d err=%v", applied, err)
	}
	if len(store.applied) != 0 || len(observed) != 0 {
		t.Fatalf("gate did not stop the round: applied=%v observed=%v", store.applied, observed)
	}

	// Gate reopened: the very next call runs for real and reports its outcome.
	ready = true
	applied, err = w.RunOnce(context.Background())
	if err != nil || applied != 1 {
		t.Fatalf("reopened round applied=%d err=%v", applied, err)
	}
	if len(observed) != 1 || observed[0] != nil {
		t.Fatalf("observed=%v, want one successful round", observed)
	}
}

func TestDrainHonorsTheReadinessGate(t *testing.T) {
	store := newFakeInputStore(inputClaim("a"))
	w := NewInputWorker(store, WorkerConfig{Owner: "worker-1", Ready: func(context.Context) bool { return false }},
		fixedClock("2026-08-20T10:00:00Z"), nil)
	applied, err := w.Drain(context.Background())
	if err != nil || applied != 0 {
		t.Fatalf("drain applied=%d err=%v", applied, err)
	}
	if len(store.applied) != 0 {
		t.Fatalf("startup replay ran against unwritable storage: %v", store.applied)
	}
}
