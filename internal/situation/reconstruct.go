// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// LeaseRecovery counts the abandoned claims one startup sweep released. Every
// count is durable work that became claimable again, never work that was
// discarded. Bounded observation work carries no lease of its own — every
// observation run is fenced by the Situation claim that authorized it — so
// recovering Situations recovers observation work with it.
type LeaseRecovery struct {
	AlertDispatches int64
	SituationInputs int64
	Situations      int64
}

// UpgradeIncident is one persisted nonterminal Incident that no Situation
// represents yet — the one-time pre-0011 upgrade population. Its canonical
// times come from the durable Incident/delivery rows, never from wall clock.
type UpgradeIncident struct {
	IncidentID              string
	GroupKey                string
	EffectiveStartedAt      time.Time
	EffectiveStartedAtBasis model.SourceTimeBasis
	FirstReceivedAt         time.Time
	LastLifecycleObservedAt time.Time
}

// ReconstructStore is the narrow durable boundary startup reconstruction
// needs. Like Controller.Store it is situation-owned rather than *store.Store:
// internal/store already imports internal/situation, so this package cannot
// import it back.
type ReconstructStore interface {
	// RecoverExpiredLeases releases every abandoned alert-dispatch,
	// Situation-input, and Situation-claim lease (the last of which also
	// covers in-flight bounded observation work, fenced by that same claim).
	// Pending notification intents need no sweep: their claim is a retry_at
	// lease deadline that simply lapses.
	RecoverExpiredLeases(ctx context.Context, now time.Time) (LeaseRecovery, error)
	// UnrepresentedActiveIncidents returns every nonterminal Incident that no
	// Situation owns yet, carrying the exact persisted group identity.
	UnrepresentedActiveIncidents(ctx context.Context) ([]UpgradeIncident, error)
	// ReconstructSituation creates (or joins) exactly one nonterminal
	// Situation for the exact group key, attaches every supplied Incident
	// once, seeds input_version=1 with upgrade_reconstruction, and schedules
	// reconciliation. It performs no outward effect: nothing about a binary
	// restart may publish.
	ReconstructSituation(ctx context.Context, groupKey string, incidents []UpgradeIncident, now time.Time) (string, error)
}

// Replayer drains one durable startup queue, returning how many units it
// applied. The concrete implementations are the correlation dispatch worker
// and the Situation input worker, which already own claim/apply/retry.
type Replayer interface {
	Drain(ctx context.Context) (int, error)
}

// Reconstruction is the report one startup pass produced. There is
// deliberately no poke count: ReconstructStore has no notification seam at
// all, so reconstruction cannot publish. It schedules reconciliation and lets
// current evidence decide, which is what stops an upgrade storming Slack.
type Reconstruction struct {
	Leases             LeaseRecovery
	ReplayedDeliveries int
	ReplayedInputs     int
	Reconstructed      int
	AttachedIncidents  int
}

// Reconstructor performs the spec's startup recovery, in its exact order,
// after migrations and before normal reconciliation.
type Reconstructor struct {
	store      ReconstructStore
	clock      func() time.Time
	deliveries Replayer
	inputs     Replayer
}

// NewReconstructor constructs a Reconstructor. clock nil uses UTC wall time.
func NewReconstructor(store ReconstructStore, clock func() time.Time) *Reconstructor {
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &Reconstructor{store: store, clock: clock}
}

// WithReplay attaches the durable queues replayed before reconstruction:
// accepted deliveries first (they can still produce Incidents), then Situation
// inputs (they attach those Incidents). Either may be nil, which skips that
// replay — the ordinary workers drain it moments later regardless.
func (r *Reconstructor) WithReplay(deliveries, inputs Replayer) *Reconstructor {
	r.deliveries = deliveries
	r.inputs = inputs
	return r
}

// Run executes startup reconstruction in the spec's exact order: recover
// expired leases, replay pending deliveries, replay pending Situation inputs,
// then populate one nonterminal Situation per exact group for every active
// Incident no Situation represents. A group that fails to reconstruct is
// reported without abandoning the remaining groups — a single bad group must
// not leave the rest of the installation unrepresented.
func (r *Reconstructor) Run(ctx context.Context) (Reconstruction, error) {
	var report Reconstruction
	if r == nil || r.store == nil {
		return report, errors.New("situation: reconstruction requires a durable store")
	}
	now := r.clock().UTC()

	leases, err := r.store.RecoverExpiredLeases(ctx, now)
	if err != nil {
		return report, fmt.Errorf("situation: reconstruct: recover expired leases: %w", err)
	}
	report.Leases = leases

	if r.deliveries != nil {
		applied, err := r.deliveries.Drain(ctx)
		report.ReplayedDeliveries = applied
		if err != nil {
			return report, fmt.Errorf("situation: reconstruct: replay pending deliveries: %w", err)
		}
	}
	if r.inputs != nil {
		applied, err := r.inputs.Drain(ctx)
		report.ReplayedInputs = applied
		if err != nil {
			return report, fmt.Errorf("situation: reconstruct: replay pending situation inputs: %w", err)
		}
	}

	incidents, err := r.store.UnrepresentedActiveIncidents(ctx)
	if err != nil {
		return report, fmt.Errorf("situation: reconstruct: load unrepresented incidents: %w", err)
	}

	var failures []error
	for _, key := range groupOrder(incidents) {
		members := incidentsForGroup(incidents, key)
		if _, err := r.store.ReconstructSituation(ctx, key, members, now); err != nil {
			failures = append(failures, fmt.Errorf("situation: reconstruct group %q: %w", key, err))
			continue
		}
		report.Reconstructed++
		report.AttachedIncidents += len(members)
	}
	return report, errors.Join(failures...)
}

// groupOrder returns the distinct exact group keys in deterministic order, so
// a restart reconstructs the same groups in the same sequence.
func groupOrder(incidents []UpgradeIncident) []string {
	seen := make(map[string]struct{}, len(incidents))
	keys := make([]string, 0, len(incidents))
	for _, incident := range incidents {
		if _, ok := seen[incident.GroupKey]; ok {
			continue
		}
		seen[incident.GroupKey] = struct{}{}
		keys = append(keys, incident.GroupKey)
	}
	sort.Strings(keys)
	return keys
}

func incidentsForGroup(incidents []UpgradeIncident, groupKey string) []UpgradeIncident {
	out := make([]UpgradeIncident, 0, len(incidents))
	for _, incident := range incidents {
		if incident.GroupKey == groupKey {
			out = append(out, incident)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].FirstReceivedAt.Equal(out[j].FirstReceivedAt) {
			return out[i].FirstReceivedAt.Before(out[j].FirstReceivedAt)
		}
		return out[i].IncidentID < out[j].IncidentID
	})
	return out
}
