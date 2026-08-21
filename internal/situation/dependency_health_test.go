// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/health"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// fakeDependencyHealthStore is an in-memory DependencyHealthStore used only
// by this package's own tests.
type fakeDependencyHealthStore struct {
	mu sync.Mutex

	states   map[string]DependencyHealthState // dependency -> current durable state
	statuses map[string]bool                  // dependency -> healthy (true) / degraded-or-unavailable (false)

	rootIntents     map[string]bool // dependency -> has a health_root intent
	createdIntents  []model.NotificationIntent
	scheduledCalls  []scheduledCall
	scheduleErr     error
	recoverNotFound map[string]bool
}

type scheduledCall struct {
	dependency string
	reason     model.DueReason
}

func newFakeDependencyHealthStore() *fakeDependencyHealthStore {
	return &fakeDependencyHealthStore{
		states:          map[string]DependencyHealthState{},
		statuses:        map[string]bool{},
		rootIntents:     map[string]bool{},
		recoverNotFound: map[string]bool{},
	}
}

func (f *fakeDependencyHealthStore) RecordDependencyDegraded(_ context.Context, dependency string, _ bool, observedAt time.Time) (DependencyHealthState, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	healthy, seen := f.statuses[dependency]
	transitioned := !seen || healthy
	state, ok := f.states[dependency]
	if !ok || transitioned {
		since := observedAt
		state = DependencyHealthState{Dependency: dependency, DegradedSince: &since}
	}
	f.statuses[dependency] = false
	f.states[dependency] = state
	return state, transitioned, nil
}

func (f *fakeDependencyHealthStore) RecordDependencyRecovered(_ context.Context, dependency string, _ time.Time) (DependencyHealthState, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.recoverNotFound[dependency] {
		return DependencyHealthState{}, false, ErrDependencyNotObserved
	}
	healthy, seen := f.statuses[dependency]
	transitioned := seen && !healthy
	f.statuses[dependency] = true
	state := DependencyHealthState{Dependency: dependency}
	f.states[dependency] = state
	return state, transitioned, nil
}

func (f *fakeDependencyHealthStore) HasDependencyRootIntent(_ context.Context, dependency string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rootIntents[dependency], nil
}

func (f *fakeDependencyHealthStore) CreateNotificationIntent(_ context.Context, in model.NotificationIntent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createdIntents = append(f.createdIntents, in)
	if in.Kind == model.NotificationHealthRoot {
		f.rootIntents[in.SubjectID] = true
	}
	return nil
}

func (f *fakeDependencyHealthStore) ScheduleAffectedSituations(_ context.Context, dependency string, reason model.DueReason, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.scheduleErr != nil {
		return f.scheduleErr
	}
	f.scheduledCalls = append(f.scheduledCalls, scheduledCall{dependency: dependency, reason: reason})
	return nil
}

func (f *fakeDependencyHealthStore) rootIntentCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, in := range f.createdIntents {
		if in.Kind == model.NotificationHealthRoot {
			n++
		}
	}
	return n
}

func (f *fakeDependencyHealthStore) updateIntentCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, in := range f.createdIntents {
		if in.Kind == model.NotificationHealthUpdate {
			n++
		}
	}
	return n
}

func (f *fakeDependencyHealthStore) scheduledCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.scheduledCalls)
}

// TestSharedOutageCreatesOneHealthRoot drives the sink directly with a
// sequence of failing observations spanning past the sustained-outage
// threshold (mirroring 20 probe cycles of a real outage), then one
// recovery — verifying at most one health root and one recovery update are
// ever created, regardless of how many failing observations were reported
// along the way.
func TestSharedOutageCreatesOneHealthRoot(t *testing.T) {
	store := newFakeDependencyHealthStore()
	sink := NewDependencyHealthSink(store, 5*time.Minute)
	start := mustTime(t, "2026-08-20T10:00:00Z")

	for i := 0; i < 20; i++ {
		status := health.Status{Name: "zabbix", OK: false, Error: "connection refused", CheckedAt: start.Add(time.Duration(i) * 30 * time.Second)}
		if err := sink.RecordDependencyStatus(context.Background(), status); err != nil {
			t.Fatalf("RecordDependencyStatus(fail #%d): %v", i, err)
		}
	}
	if got := store.rootIntentCount(); got != 1 {
		t.Fatalf("health root intents = %d, want 1", got)
	}
	if got := store.scheduledCount(); got != 1 {
		t.Fatalf("scheduled affected situations = %d, want 1 (only the first failing transition)", got)
	}

	recoverAt := start.Add(20 * 30 * time.Second)
	if err := sink.RecordDependencyStatus(context.Background(), health.Status{Name: "zabbix", OK: true, CheckedAt: recoverAt}); err != nil {
		t.Fatalf("RecordDependencyStatus(recover): %v", err)
	}
	if got := store.updateIntentCount(); got != 1 {
		t.Fatalf("health update intents = %d, want 1", got)
	}

	// A second recovery call (Registry would not normally re-call the sink
	// here, but the sink itself must still be idempotent) must not create a
	// second update.
	if err := sink.RecordDependencyStatus(context.Background(), health.Status{Name: "zabbix", OK: true, CheckedAt: recoverAt.Add(time.Minute)}); err != nil {
		t.Fatalf("RecordDependencyStatus(recover again): %v", err)
	}
	if got := store.updateIntentCount(); got != 1 {
		t.Fatalf("health update intents after a second recovery call = %d, want still 1", got)
	}
}

// TestDependencyHealthSinkWithholdsRootBeforeSustainedThreshold verifies a
// transient blip that never crosses the sustained-outage threshold never
// creates a health root.
func TestDependencyHealthSinkWithholdsRootBeforeSustainedThreshold(t *testing.T) {
	store := newFakeDependencyHealthStore()
	sink := NewDependencyHealthSink(store, 5*time.Minute)
	start := mustTime(t, "2026-08-20T10:00:00Z")

	if err := sink.RecordDependencyStatus(context.Background(), health.Status{Name: "zabbix", OK: false, CheckedAt: start}); err != nil {
		t.Fatalf("RecordDependencyStatus: %v", err)
	}
	if got := store.rootIntentCount(); got != 0 {
		t.Fatalf("health root intents = %d, want 0 (not yet sustained)", got)
	}
	if err := sink.RecordDependencyStatus(context.Background(), health.Status{Name: "zabbix", OK: true, CheckedAt: start.Add(time.Minute)}); err != nil {
		t.Fatalf("RecordDependencyStatus(recover): %v", err)
	}
	if got := store.updateIntentCount(); got != 0 {
		t.Fatalf("health update intents = %d, want 0 (never rooted, recovery stays silent)", got)
	}
}

// TestDependencyHealthSinkScheduleAffectedSituationsOnlyOnceEvery
// verifies ScheduleAffectedSituations fires once entering degraded and once
// on genuine recovery, not on every repeated observation.
func TestDependencyHealthSinkSchedulesAffectedSituationsOnTransitionsOnly(t *testing.T) {
	store := newFakeDependencyHealthStore()
	sink := NewDependencyHealthSink(store, 5*time.Minute)
	start := mustTime(t, "2026-08-20T10:00:00Z")
	for i := 0; i < 3; i++ {
		_ = sink.RecordDependencyStatus(context.Background(), health.Status{Name: "llm", OK: false, CheckedAt: start.Add(time.Duration(i) * time.Second)})
	}
	if got := store.scheduledCount(); got != 1 {
		t.Fatalf("scheduled affected situations after 3 failing calls = %d, want 1", got)
	}
	_ = sink.RecordDependencyStatus(context.Background(), health.Status{Name: "llm", OK: true, CheckedAt: start.Add(time.Minute)})
	if got := store.scheduledCount(); got != 2 {
		t.Fatalf("scheduled affected situations after recovery = %d, want 2", got)
	}
}

// TestDependencyHealthSinkRecoveryNeverObservedIsNoop verifies a recovery
// observation for a dependency that was never recorded degraded is a quiet
// no-op (the store contract: RecordDependencyRecovered on an unobserved
// dependency reports transitioned=false).
func TestDependencyHealthSinkRecoveryNeverObservedIsNoop(t *testing.T) {
	store := newFakeDependencyHealthStore()
	store.recoverNotFound["prometheus"] = true
	sink := NewDependencyHealthSink(store, 5*time.Minute)
	if err := sink.RecordDependencyStatus(context.Background(), health.Status{Name: "prometheus", OK: true, CheckedAt: mustTime(t, "2026-08-20T10:00:00Z")}); err != nil {
		t.Fatalf("RecordDependencyStatus: %v", err)
	}
	if got := store.updateIntentCount(); got != 0 {
		t.Fatalf("health update intents = %d, want 0", got)
	}
}

// TestDependencyHealthSinkRequiresNameAndTime verifies input validation.
func TestDependencyHealthSinkRequiresNameAndTime(t *testing.T) {
	sink := NewDependencyHealthSink(newFakeDependencyHealthStore(), 5*time.Minute)
	if err := sink.RecordDependencyStatus(context.Background(), health.Status{OK: true, CheckedAt: mustTime(t, "2026-08-20T10:00:00Z")}); err == nil {
		t.Fatal("empty dependency name accepted")
	}
	if err := sink.RecordDependencyStatus(context.Background(), health.Status{Name: "llm", OK: true}); err == nil {
		t.Fatal("zero observation time accepted")
	}
}
