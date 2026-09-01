// SPDX-License-Identifier: FSL-1.1-ALv2

package model

import (
	"errors"
	"time"
)

// ----------------------------------------------------------------------
// Situation foundation vocabulary shared with internal/store
//
// The types and sentinel errors below were originally defined in
// internal/store (situations.go, situation_reconstruction.go, store.go) and
// re-exported from internal/situation as type aliases. That direction
// stopped working once internal/store itself needed to depend on types
// declared in internal/situation for its controller-facing methods:
// internal/situation already imported internal/store (InputWorker's
// InputStore interface named store.SituationClaim directly; Reconstructor's
// ReconstructStore interface named store.LeaseRecovery/UpgradeIncident/
// DeadLetterCounts), so the reverse import store -> situation would cycle.
//
// internal/situation/model is a leaf package both internal/store and
// internal/situation already import one-directionally without issue, so
// these are defined here instead and re-exported as type aliases (and, for
// the two sentinel errors, value aliases) from internal/store — the mirror
// image of how internal/situation used to alias internal/store's types. All
// ~40+ existing store.X call sites across internal/store and its tests keep
// compiling unchanged; internal/situation now references these directly as
// model.X, with no import of internal/store at all.
// ----------------------------------------------------------------------

// ErrNotFound is returned when a lookup finds no matching row.
var ErrNotFound = errors.New("store: not found")

// ErrSituationLeaseLost means a caller no longer owns the lease it is trying
// to act on — either a claimed situation_input_outbox row (ApplySituationInput,
// RetrySituationInput) or a claimed Situation aggregate (ReleaseSituationClaim)
// — because the lease's (owner, claim_token) pair was superseded, most often
// by another worker reclaiming it after the original lease expired. Callers
// must discard the stale claim, not retry with it, on receiving this error.
var ErrSituationLeaseLost = errors.New("store: situation lease lost")

// SituationInput is one durable, deterministically-idempotent fact destined
// for the situation_input_outbox — the only channel through which a
// correlation-side mutation (a correlated delivery, an Incident's ready
// transition, ...) hands work to the Situation controller.
type SituationInput struct {
	ID             string
	IdempotencyKey string
	IncidentID     string
	Kind           string
	GroupKey       string
	DeliveryID     *string
	OccurredAt     time.Time
}

// SituationClaim is one claimed situation_input_outbox row: the input's own
// identity (embedded SituationInput) plus the lease-fencing triple recorded
// at claim time. ApplySituationInput and RetrySituationInput both re-verify
// this triple against the row's current state before writing anything —
// receiving a SituationClaim is never itself proof the claim still holds.
type SituationClaim struct {
	SituationInput

	LeaseOwner   string
	ClaimToken   int64
	AttemptCount int
}

// LeaseRecovery reports how many rows RecoverExpiredFoundationLeases moved
// from an expired claim back to unclaimed, per fenced table.
type LeaseRecovery struct {
	AlertDispatches int64
	SituationInputs int64
	Situations      int64
}

// DeadLetterCounts reports how many rows in each fenced dispatch/input
// outbox table have permanently exhausted retries (status='failed') —
// dead-lettered work this plan promises is "never silently dropped"
// (docs/concepts/architecture.md): the row is durably on disk, but is
// excluded from every future claim and otherwise invisible without
// hand-written SQL. CountDeadLetteredFoundationWork surfaces it once per
// Reconstructor.Run pass so a stuck delivery or Situation input has a
// startup-visible tripwire.
type DeadLetterCounts struct {
	AlertDispatches int
	SituationInputs int
}

// UpgradeIncident is one operational Incident with no Situation membership
// yet, carrying the persisted Incident/delivery-derived times
// ReconstructSituation needs to represent it — never a live read of
// anything outward.
type UpgradeIncident struct {
	IncidentID              string
	GroupKey                string
	EffectiveStartedAt      time.Time
	EffectiveStartedAtBasis SourceTimeBasis
	FirstReceivedAt         time.Time
	LastLifecycleObservedAt time.Time
}
