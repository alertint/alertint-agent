// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// PreparationRequest is one preparation-phase dispatch: the exact claim and
// coherent input this phase must prepare evidence under, and which of the
// two phases (lifecycle runs first and decides recovery/closure; assessment
// runs only while active) to execute.
type PreparationRequest struct {
	Claim Claim
	Input SnapshotInput
	Phase observationmodel.Phase
	Now   time.Time
}

// PreparedState is EvidencePreparer.Prepare's execution receipt — never
// trusted as authoritative evidence on its own. The real prepared state a
// commit reasons from is always reloaded from the store immediately after
// (SnapshotInput.Prepared, populated by LoadReconciliationInput), so a
// concurrent head-change or a crash between preparation and reload can
// never let a stale in-memory receipt substitute for durable truth.
type PreparedState struct {
	CycleID    string
	Generation int64
	// Runs is the latest bounded evidence per capability/subject across
	// compatible cycles, not just the reads dispatched this cycle. Audit
	// APIs continue to expose immutable per-cycle runs separately.
	Runs              []observationmodel.Run
	ProfileVersionIDs []string
	ProfileGuidance   []observationmodel.ProfileGuidance
	NextRefreshAt     *time.Time
	Lifecycle         []SourceObservation
	// SourceDefinitions is the durable current head for source-rule
	// configuration observations. Unavailable heads are retained explicitly;
	// callers must never fall back to an older successful version.
	SourceDefinitions []observationmodel.SourceDefinitionObservation
	Limitations       []model.Limitation
	// Deferred lists the capability:subject reads this cycle could not
	// admit under its request cap or credit (frozen in the cycle's
	// allocation) — surfaced to the Assessment as an explicit limitation
	// rather than silently discarded.
	Deferred []string
	// PlansByID maps each frozen plan ID of the cycle to its plan, so the
	// projection can name the capability/subject behind every run.
	PlansByID map[string]observationmodel.Plan
	// LoadedAt is the coherent read time the store reloaded this state at
	// — the clock expiry classes are computed against.
	LoadedAt time.Time
}

func (p PreparedState) now() time.Time {
	return p.LoadedAt
}

// EvidencePreparer performs one bounded preparation phase — planning,
// executing, and durably committing this cycle's evidence — under the
// existing Situation claim's fence. The concrete adapter (cmd/alertint)
// bridges this package's Claim into the narrow observationmodel.Fence
// Task 2's store methods require; internal/situation itself never imports
// internal/store or internal/observation's connectors.
type EvidencePreparer interface {
	Prepare(ctx context.Context, req PreparationRequest) (PreparedState, error)
}

// SetEvidencePreparer wires the production preparer. Call once, after
// construction, before the first Reconcile — mirroring
// SetAssessmentHealthObserver's own established pattern. A nil preparer
// (the default, and every existing local-only test fixture) makes
// Reconcile skip preparation entirely rather than falsely reporting
// support: no lifecycle/assessment phase runs, and PreparationCycleID stays
// empty so CommitController's cycle-sealing step is a no-op.
func (c *Controller) SetEvidencePreparer(p EvidencePreparer) {
	c.preparer = p
}
