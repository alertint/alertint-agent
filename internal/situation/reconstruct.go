// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

// ----------------------------------------------------------------------
// Startup reconstruction orchestration (Task 8)
//
// Reconstructor performs the zero-outward-effect pass a restart needs to
// converge correctly: recover expired leases, drain the durable delivery
// and Situation input queues to completion, then represent every
// operational Incident that still has no Situation. It never calls a
// notifier, LLM, connector, or Slack dependency.
//
// LeaseRecovery and UpgradeIncident are internal/store's own types (see
// internal/store/situation_reconstruction.go), re-exported here as type
// aliases rather than redefined: this package already imports
// internal/store — InputStore below (input_worker.go) names
// store.SituationClaim directly — so internal/store cannot import this
// package back without a cycle. Aliasing, instead of duplicating the
// struct, is what lets *store.Store satisfy ReconstructStore without
// store ever importing situation.
// ----------------------------------------------------------------------

// LeaseRecovery reports how many rows one lease-recovery pass moved from
// an expired claim back to unclaimed, per fenced table.
type LeaseRecovery = store.LeaseRecovery

// UpgradeIncident is one operational Incident with no Situation
// membership yet, carrying the persisted Incident/delivery-derived times
// ReconstructSituation needs to represent it.
type UpgradeIncident = store.UpgradeIncident

// DeadLetterCounts reports how many rows in each fenced dispatch/input
// outbox table have permanently exhausted retries (status='failed') — see
// store.DeadLetterCounts for why this exists.
type DeadLetterCounts = store.DeadLetterCounts

// ReconstructStore is the narrow slice of *store.Store the Reconstructor
// depends on: recovering expired leases, counting dead-lettered work, and
// representing every operational Incident that has no Situation yet.
// Every method here is either a straight lease release or a database
// projection — none of them may call a notifier, LLM, connector, or Slack
// dependency, and the Reconstructor never asks them to.
type ReconstructStore interface {
	RecoverExpiredFoundationLeases(ctx context.Context, now time.Time) (LeaseRecovery, error)
	CountDeadLetteredFoundationWork(ctx context.Context) (DeadLetterCounts, error)
	UnrepresentedOperationalIncidents(ctx context.Context) ([]UpgradeIncident, error)
	ReconstructSituation(ctx context.Context, groupKey string, incidents []UpgradeIncident, now time.Time) (string, error)
}

// Replayer drains a durable outbox worker to completion without starting
// its background schedule. *correlator.DispatchWorker and *InputWorker
// both satisfy this directly via their existing Drain method.
type Replayer interface {
	Drain(ctx context.Context) (int, error)
}

// Reconstruction reports what one Reconstructor.Run pass did — purely
// descriptive counters, never itself a trigger for anything outward.
type Reconstruction struct {
	RecoveredLeases      LeaseRecovery
	ReplayedDeliveries   int
	ReplayedInputs       int
	RepresentedGroups    int
	RepresentedIncidents int
	DeadLettered         DeadLetterCounts
}

// Reconstructor performs the fixed startup order recover expired leases
// -> drain delivery dispatches -> drain Situation inputs -> represent
// unowned operational Incidents. It is safe to run repeatedly: a second
// Run against already-represented state finds nothing left to recover,
// drain, or represent, and reports zero for every counter.
type Reconstructor struct {
	store    ReconstructStore
	now      func() time.Time
	dispatch Replayer
	inputs   Replayer
}

// NewReconstructor creates a Reconstructor. now must not be nil — callers
// (including tests) always supply their own clock explicitly; unlike the
// workers this package runs alongside, this deliberately has no
// time.Now fallback, since a startup reconstruction report is the kind of
// thing worth pinning to an exact, test-visible instant.
func NewReconstructor(store ReconstructStore, now func() time.Time) *Reconstructor {
	return &Reconstructor{store: store, now: now}
}

// WithReplay attaches the delivery-dispatch and Situation-input drains
// Run drives before representing Incidents. Either may be nil — Run skips
// a nil Replayer's drain phase — but production always supplies both.
func (r *Reconstructor) WithReplay(dispatch, inputs Replayer) *Reconstructor {
	r.dispatch = dispatch
	r.inputs = inputs
	return r
}

// Run executes the fixed startup order: recover expired leases, drain
// delivery dispatches, drain Situation inputs, then represent unowned
// operational Incidents. It returns as soon as a lease-recovery or drain
// phase fails, since the represent phase assumes those queues are caught
// up; the represent phase itself instead collects one error per malformed
// group with errors.Join, so a single bad group's data never prevents
// every other group from becoming represented in the same pass. A
// non-nil error here — whole-phase or joined — means the pass is
// incomplete and the caller must not start accepting new inbound work.
func (r *Reconstructor) Run(ctx context.Context) (Reconstruction, error) {
	var report Reconstruction
	now := r.now()

	recovered, err := r.store.RecoverExpiredFoundationLeases(ctx, now)
	if err != nil {
		return report, fmt.Errorf("situation: recover expired foundation leases: %w", err)
	}
	report.RecoveredLeases = recovered

	if r.dispatch != nil {
		n, err := r.dispatch.Drain(ctx)
		if err != nil {
			return report, fmt.Errorf("situation: drain alert dispatches: %w", err)
		}
		report.ReplayedDeliveries = n
	}

	if r.inputs != nil {
		n, err := r.inputs.Drain(ctx)
		if err != nil {
			return report, fmt.Errorf("situation: drain situation inputs: %w", err)
		}
		report.ReplayedInputs = n
	}

	incidents, err := r.store.UnrepresentedOperationalIncidents(ctx)
	if err != nil {
		return report, fmt.Errorf("situation: list unrepresented operational incidents: %w", err)
	}

	var errs []error
	for _, group := range groupUpgradeIncidents(incidents) {
		if _, err := r.store.ReconstructSituation(ctx, group.key, group.incidents, now); err != nil {
			errs = append(errs, fmt.Errorf("situation: reconstruct group %q: %w", group.key, err))
			continue
		}
		report.RepresentedGroups++
		report.RepresentedIncidents += len(group.incidents)
	}

	deadLettered, err := r.store.CountDeadLetteredFoundationWork(ctx)
	if err != nil {
		errs = append(errs, fmt.Errorf("situation: count dead-lettered foundation work: %w", err))
	} else {
		report.DeadLettered = deadLettered
	}

	return report, errors.Join(errs...)
}

// upgradeIncidentGroup is one exact group's batch, in the stable order
// groupUpgradeIncidents produces.
type upgradeIncidentGroup struct {
	key       string
	incidents []UpgradeIncident
}

// groupUpgradeIncidents partitions incidents by exact GroupKey and returns
// the groups sorted by key (and each group's incidents sorted by
// IncidentID), so ReconstructSituation always runs in the same
// deterministic order regardless of the store's own return order.
func groupUpgradeIncidents(incidents []UpgradeIncident) []upgradeIncidentGroup {
	byKey := make(map[string][]UpgradeIncident)
	for _, inc := range incidents {
		byKey[inc.GroupKey] = append(byKey[inc.GroupKey], inc)
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	groups := make([]upgradeIncidentGroup, 0, len(keys))
	for _, k := range keys {
		group := byKey[k]
		sort.Slice(group, func(i, j int) bool { return group[i].IncidentID < group[j].IncidentID })
		groups = append(groups, upgradeIncidentGroup{key: k, incidents: group})
	}
	return groups
}
