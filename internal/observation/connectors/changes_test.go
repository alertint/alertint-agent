// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
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
