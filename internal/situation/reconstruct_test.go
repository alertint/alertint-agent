// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// fakeReconstructStore is an in-memory ReconstructStore. It records the exact
// order of the startup steps so the spec's ordering is testable.
type fakeReconstructStore struct {
	steps       []string
	leases      LeaseRecovery
	unattached  []UpgradeIncident
	groups      map[string][]string // group key -> attached incident ids
	created     []string
	failGroups  map[string]error
	unattachErr error
}

func newFakeReconstructStore(incidents ...UpgradeIncident) *fakeReconstructStore {
	return &fakeReconstructStore{
		leases:     LeaseRecovery{AlertDispatches: 1, SituationInputs: 2, Situations: 3},
		unattached: incidents,
		groups:     map[string][]string{},
		failGroups: map[string]error{},
	}
}

func (f *fakeReconstructStore) RecoverExpiredLeases(_ context.Context, _ time.Time) (LeaseRecovery, error) {
	f.steps = append(f.steps, "recover_leases")
	return f.leases, nil
}

func (f *fakeReconstructStore) UnrepresentedActiveIncidents(_ context.Context) ([]UpgradeIncident, error) {
	f.steps = append(f.steps, "load_unrepresented")
	if f.unattachErr != nil {
		return nil, f.unattachErr
	}
	return f.unattached, nil
}

func (f *fakeReconstructStore) ReconstructSituation(_ context.Context, groupKey string, incidents []UpgradeIncident, _ time.Time) (string, error) {
	f.steps = append(f.steps, "reconstruct:"+groupKey)
	if err, ok := f.failGroups[groupKey]; ok {
		return "", err
	}
	for _, incident := range incidents {
		f.groups[groupKey] = append(f.groups[groupKey], incident.IncidentID)
	}
	id := "situation-" + groupKey
	f.created = append(f.created, id)
	return id, nil
}

type fakeReplayer struct {
	name    string
	steps   *[]string
	drained int
	err     error
}

func (f *fakeReplayer) Drain(_ context.Context) (int, error) {
	*f.steps = append(*f.steps, f.name)
	return f.drained, f.err
}

func upgradeIncident(id, groupKey string) UpgradeIncident {
	at := time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC)
	return UpgradeIncident{
		IncidentID: id, GroupKey: groupKey,
		EffectiveStartedAt: at, EffectiveStartedAtBasis: model.SourceTimeBasisReceiptFallback,
		FirstReceivedAt: at, LastLifecycleObservedAt: at,
	}
}

func fixedClock(value string) func() time.Time {
	at, err := time.Parse(time.RFC3339, value)
	if err != nil {
		panic(err)
	}
	return func() time.Time { return at.UTC() }
}

func TestReconstructActiveUpgradeWithoutPublishing(t *testing.T) {
	store := newFakeReconstructStore(
		upgradeIncident("inc-a", "group-one"),
		upgradeIncident("inc-b", "group-one"),
		upgradeIncident("inc-c", "group-two"),
	)
	r := NewReconstructor(store, fixedClock("2026-08-20T10:00:00Z"))
	report, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Reconstructed != 2 {
		t.Fatalf("reconstructed=%d, want one Situation per exact group", report.Reconstructed)
	}
	if report.AttachedIncidents != 3 {
		t.Fatalf("attached=%d, want every active Incident attached exactly once", report.AttachedIncidents)
	}
	if got := len(store.groups["group-one"]); got != 2 {
		t.Fatalf("group-one attachments=%d", got)
	}
	if got := len(store.groups["group-two"]); got != 1 {
		t.Fatalf("group-two attachments=%d", got)
	}
	// Reconstruction never plans a notification: ReconstructStore has no
	// notification seam, so the type system already proves an upgrade cannot
	// poke the main channel. The durable counterpart of this assertion —
	// zero notification_intents rows after a real reconstruction — lives in
	// internal/store's own runtime test.
}

func TestReconstructRunsSpecStepOrder(t *testing.T) {
	store := newFakeReconstructStore(upgradeIncident("inc-a", "group-one"))
	deliveries := &fakeReplayer{name: "replay_deliveries", steps: &store.steps, drained: 2}
	inputs := &fakeReplayer{name: "replay_inputs", steps: &store.steps, drained: 3}
	r := NewReconstructor(store, fixedClock("2026-08-20T10:00:00Z")).WithReplay(deliveries, inputs)

	report, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"recover_leases", "replay_deliveries", "replay_inputs", "load_unrepresented", "reconstruct:group-one"}
	if len(store.steps) != len(want) {
		t.Fatalf("steps=%v, want %v", store.steps, want)
	}
	for i := range want {
		if store.steps[i] != want[i] {
			t.Fatalf("step %d = %q, want %q (all=%v)", i, store.steps[i], want[i], store.steps)
		}
	}
	if report.ReplayedDeliveries != 2 || report.ReplayedInputs != 3 {
		t.Fatalf("replay counts = %d/%d", report.ReplayedDeliveries, report.ReplayedInputs)
	}
	if report.Leases != store.leases {
		t.Fatalf("leases=%+v", report.Leases)
	}
}

func TestReconstructIsIdempotentAcrossRestarts(t *testing.T) {
	store := newFakeReconstructStore(upgradeIncident("inc-a", "group-one"))
	r := NewReconstructor(store, fixedClock("2026-08-20T10:00:00Z"))
	if _, err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A second start finds nothing unrepresented: the durable attachment from
	// the first run is what makes reconstruction a one-time upgrade population.
	store.unattached = nil
	report, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Reconstructed != 0 || report.AttachedIncidents != 0 {
		t.Fatalf("second run reconstructed=%d attached=%d", report.Reconstructed, report.AttachedIncidents)
	}
}

func TestReconstructGroupFailureDoesNotAbortRemainingGroups(t *testing.T) {
	store := newFakeReconstructStore(
		upgradeIncident("inc-a", "group-one"),
		upgradeIncident("inc-c", "group-two"),
	)
	store.failGroups["group-one"] = errors.New("boom")
	r := NewReconstructor(store, fixedClock("2026-08-20T10:00:00Z"))
	report, err := r.Run(context.Background())
	if err == nil {
		t.Fatal("expected the failed group to be reported")
	}
	if report.Reconstructed != 1 {
		t.Fatalf("reconstructed=%d, want the healthy group still populated", report.Reconstructed)
	}
	if len(store.groups["group-two"]) != 1 {
		t.Fatalf("group-two attachments=%v", store.groups["group-two"])
	}
}

func TestReconstructRequiresStore(t *testing.T) {
	if _, err := NewReconstructor(nil, nil).Run(context.Background()); err == nil {
		t.Fatal("expected an error without a durable store")
	}
}
