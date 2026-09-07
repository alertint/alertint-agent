// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	model "github.com/alertint/alertint-agent/internal/observation/model"
)

var errBoom = errors.New("boom")

type fakeLocalStore struct {
	situations []model.LocalSituationSummary
	findings   []model.LocalFinding
	err        error
}

func (f *fakeLocalStore) PriorTerminalSituationSummaries(ctx context.Context, groupKey, excludeSituationID string, limit int) ([]model.LocalSituationSummary, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.situations, nil
}

func (f *fakeLocalStore) RecentFindingsForGroup(ctx context.Context, groupKey string, since time.Time, limit int) ([]model.LocalFinding, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.findings, nil
}

type noopRecorder struct{ calls int }

func (r *noopRecorder) BeforeRequest(ctx context.Context) (model.RequestReservation, error) {
	r.calls++
	return model.RequestReservation{}, nil
}
func (r *noopRecorder) AfterRequest(ctx context.Context, outcome model.RequestOutcome) error {
	r.calls++
	return nil
}

func testStorePlan() model.Plan {
	return model.Plan{
		ID: "plan-1", CycleID: "cycle-1", Capability: model.CapabilityStoreRead, Phase: model.PhaseAssessment,
		Scope: model.Scope{GroupKey: "service=checkout", Source: "local", SubjectID: "checkout"},
		Start: time.Now().Add(-time.Hour), End: time.Now(), Limit: 20, MaxRequests: 1, Purpose: "corroborate_member",
	}
}

func TestStoreReadExecutorNeverUsesRequestRecorder(t *testing.T) {
	store := &fakeLocalStore{situations: []model.LocalSituationSummary{{ID: "s1"}}}
	e := &StoreReadExecutor{Store: store}
	rec := &noopRecorder{}
	if _, err := e.Execute(context.Background(), testStorePlan(), rec); err != nil {
		t.Fatal(err)
	}
	if rec.calls != 0 {
		t.Fatalf("recorder calls = %d, want 0 (store_read is local, not a physical request)", rec.calls)
	}
}

func TestStoreReadExecutorConfirmedValueWithFacts(t *testing.T) {
	store := &fakeLocalStore{
		situations: []model.LocalSituationSummary{{ID: "s1", TerminalReason: "recovered"}},
		findings:   []model.LocalFinding{{IncidentID: "i1", Summary: "disk full"}},
	}
	e := &StoreReadExecutor{Store: store}
	run, err := e.Execute(context.Background(), testStorePlan(), &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != model.ResultConfirmedValue {
		t.Fatalf("status = %q, want confirmed_value", run.Status)
	}
	if len(run.Facts) != 2 {
		t.Fatalf("facts = %d, want 2 (situations + findings)", len(run.Facts))
	}
	for _, f := range run.Facts {
		var decoded any
		if err := json.Unmarshal(f.Value, &decoded); err != nil {
			t.Fatalf("fact value not valid JSON: %v", err)
		}
		if !f.Material {
			t.Fatal("expected store_read facts to be material")
		}
	}
}

// TestStoreReadExecutorPriorSituationFactUsesCapabilityResultKind guards
// against a naming collision with migration 0022's DEDICATED
// "source_lifecycle" fact kind (Plan 4 Task 6: per-Alert firing/resolved
// SourceObservation evidence a lifecycle-phase connector writes). store_read
// has no lifecycle evidence of its own — the "prior Situations" fact must
// use the same generic "capability_result" kind findingsFact already uses,
// never "source_lifecycle": tagging it that way would make
// internal/store's prepared-state reload misread unrelated prior-Situation
// summaries as source lifecycle observations.
func TestStoreReadExecutorPriorSituationFactUsesCapabilityResultKind(t *testing.T) {
	store := &fakeLocalStore{situations: []model.LocalSituationSummary{{ID: "s1", TerminalReason: "recovered"}}}
	e := &StoreReadExecutor{Store: store}
	run, err := e.Execute(context.Background(), testStorePlan(), &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if len(run.Facts) != 1 {
		t.Fatalf("facts = %d, want 1 (situations only)", len(run.Facts))
	}
	if run.Facts[0].Kind != "capability_result" {
		t.Fatalf("prior situation fact kind = %q, want capability_result (source_lifecycle is reserved for Task 6 lifecycle evidence)", run.Facts[0].Kind)
	}
}

func TestStoreReadExecutorConfirmedEmptyWithNoRows(t *testing.T) {
	store := &fakeLocalStore{}
	e := &StoreReadExecutor{Store: store}
	run, err := e.Execute(context.Background(), testStorePlan(), &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != model.ResultConfirmedEmpty {
		t.Fatalf("status = %q, want confirmed_empty", run.Status)
	}
	if len(run.Facts) != 0 {
		t.Fatalf("facts = %d, want 0", len(run.Facts))
	}
}

func TestStoreReadExecutorUnresolvedWhenNoGroupKey(t *testing.T) {
	store := &fakeLocalStore{}
	e := &StoreReadExecutor{Store: store}
	plan := testStorePlan()
	plan.Scope.GroupKey = ""
	run, err := e.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != model.ResultVocabularyUnresolved {
		t.Fatalf("status = %q, want vocabulary_unresolved", run.Status)
	}
}

func TestStoreReadExecutorPropagatesStoreError(t *testing.T) {
	store := &fakeLocalStore{err: errBoom}
	e := &StoreReadExecutor{Store: store}
	if _, err := e.Execute(context.Background(), testStorePlan(), &noopRecorder{}); err == nil {
		t.Fatal("expected store error to propagate")
	}
}
