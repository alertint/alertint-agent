// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	model "github.com/alertint/alertint-agent/internal/observation/model"
)

type fakeChangesStore struct {
	changes   []model.LocalChange
	truncated bool
	err       error
}

func (f *fakeChangesStore) ChangesInScopeWindow(ctx context.Context, labels map[string]string, start, end time.Time, limit int) ([]model.LocalChange, bool, error) {
	if f.err != nil {
		return nil, false, f.err
	}
	return f.changes, f.truncated, nil
}

func TestChangesExecutorNeverUsesRequestRecorder(t *testing.T) {
	store := &fakeChangesStore{changes: []model.LocalChange{{ID: "c1"}}}
	e := &ChangesExecutor{Store: store}
	plan := testStorePlan()
	plan.Scope.Labels = map[string]string{"service": "checkout"}
	rec := &noopRecorder{}

	if _, err := e.Execute(context.Background(), plan, rec); err != nil {
		t.Fatal(err)
	}
	if rec.calls != 0 {
		t.Fatalf("recorder calls = %d, want 0 (change_events is a local read)", rec.calls)
	}
}

func TestChangesExecutorConfirmedValueAndEmpty(t *testing.T) {
	plan := testStorePlan()
	plan.Scope.Labels = map[string]string{"service": "checkout"}

	withChanges := &ChangesExecutor{Store: &fakeChangesStore{changes: []model.LocalChange{{ID: "c1"}}}}
	run, err := withChanges.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "confirmed_value" {
		t.Fatalf("status = %q, want confirmed_value", run.Status)
	}

	empty := &ChangesExecutor{Store: &fakeChangesStore{}}
	run, err = empty.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "confirmed_empty" {
		t.Fatalf("status = %q, want confirmed_empty", run.Status)
	}
}

func TestChangesExecutorTruncated(t *testing.T) {
	store := &fakeChangesStore{changes: []model.LocalChange{{ID: "c1"}}, truncated: true}
	e := &ChangesExecutor{Store: store}
	plan := testStorePlan()
	plan.Scope.Labels = map[string]string{"service": "checkout"}

	run, err := e.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "truncated" {
		t.Fatalf("status = %q, want truncated", run.Status)
	}
}

// TestChangesExecutorCapsFactBytes proves the change_event fact never
// exceeds model.MaxFactBytes even for a wide local change ledger.
func TestChangesExecutorCapsFactBytes(t *testing.T) {
	changes := make([]model.LocalChange, 40)
	for i := range changes {
		changes[i] = model.LocalChange{ID: strconv.Itoa(i), Title: strings.Repeat("t", 800), OccurredAt: time.Unix(int64(i), 0).UTC()}
	}
	e := &ChangesExecutor{Store: &fakeChangesStore{changes: changes}}
	plan := testStorePlan()
	plan.Scope.Labels = map[string]string{"service": "checkout"}
	plan.Limit = 50

	run, err := e.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if len(run.Facts) != 1 || len(run.Facts[0].Value) > model.MaxFactBytes {
		t.Fatalf("fact value = %d bytes, must never exceed %d", len(run.Facts[0].Value), model.MaxFactBytes)
	}
	if !slices.Contains(run.LimitationCodes, "fact_bytes_capped") || run.Coverage.Complete || run.Status != model.ResultTruncated {
		t.Fatalf("run = status %q complete=%v codes=%v, want truncated/fact_bytes_capped", run.Status, run.Coverage.Complete, run.LimitationCodes)
	}
	if run.Coverage.Returned+run.Coverage.Omitted != 40 || run.Coverage.Omitted < 1 {
		t.Fatalf("coverage returned=%d omitted=%d, want a sum of 40 with omitted >= 1", run.Coverage.Returned, run.Coverage.Omitted)
	}
}

func TestChangesExecutorUnresolvedWithoutScopeLabels(t *testing.T) {
	e := &ChangesExecutor{Store: &fakeChangesStore{}}
	plan := testStorePlan()
	plan.Scope.Labels = nil

	run, err := e.Execute(context.Background(), plan, &noopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "vocabulary_unresolved" {
		t.Fatalf("status = %q, want vocabulary_unresolved", run.Status)
	}
}
