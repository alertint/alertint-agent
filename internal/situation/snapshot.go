// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// SnapshotInput is the raw, transport-neutral material Task 4's pure
// functions (DeriveStoreFacts, BuildSnapshot, MembershipDigest,
// IncidentInputDigest, EligibleReasons, MaterialFactHash,
// AssessmentBasisHash) reduce into facts, digests, and hashes. It carries
// only durable local truth already read inside LoadReconciliationInput's
// one coherent transaction — no external I/O, no derived/computed content.
// now enters the pure layer through Now rather than a global clock.
type SnapshotInput struct {
	Situation         model.Situation
	Deliveries        []Delivery
	Incidents         []IncidentState
	PriorSituations   []CompletedSituation
	CurrentAssessment *AuthoritativeAssessment
	Now               time.Time
}

// Delivery is one immutable Alert delivery belonging to a member Incident of
// the Situation being reconciled — the lean, transport-neutral trim of
// store.AlertDelivery's identity-relevant fields (this package must never
// import internal/store, so it cannot reuse that type directly). It
// deliberately excludes store.Alert's mutable "latest wins" projection and
// SQL-facing internals (labels/annotations, fingerprint, provenance mode):
// Status is read from alert_deliveries.status, the immutable per-delivery
// source lifecycle, never inferred from the mutable Alert row.
type Delivery struct {
	ID               string
	IncidentID       string
	Status           model.DeliveryStatus
	PayloadDigest    string
	SourceStartedAt  *time.Time
	StartedAtBasis   model.SourceTimeBasis
	SourceResolvedAt *time.Time
	ResolvedAtBasis  model.SourceTimeBasis
	ReceivedAt       time.Time
}

// TriageState is Acute Triage's durable per-Incident state, as far as this
// task's LoadReconciliationInput reads it: the incident_triage schedule row's
// phase/attempt/due state plus, once decided, the exact snapshot the
// controller's request/skip judgment was made against. The zero value
// (Phase == "") means no incident_triage row exists yet — an Incident that
// has never reached "ready". Deliberately excludes lease/claim fields
// (non-material per the spec's Incident-coverage-digest exclusions) and any
// Finding/output content: Task 4's "acute_finding" fact and the Snapshot's
// "normalized Finding state" need a normalized (not raw-prose) Finding
// source, and the best such source is incident_triage_attempts' completed
// row (result_code, output_digest, finding_id, evidence_pack_digest) — a
// table this task's LoadReconciliationInput does not yet read because
// nothing durable populates it before Task 6 lands. Task 4 (or Task 6) adds
// that field here when it is needed; see the Task 3 report.
type TriageState struct {
	Phase                string
	Attempts             int
	NextAt               *time.Time
	Decision             *string
	DecisionReason       *string
	DecisionInputVersion *int
	MaterialFactHash     *string
	MembershipDigest     *string
	IncidentInputDigest  *string
	AssessmentID         *string
	DecidedAt            *time.Time
}

// IncidentState is one member Incident's durable identity/status/timing
// plus its current Triage state, as far as this task's LoadReconciliationInput
// reads it — the lean, transport-neutral trim of store.Incident's
// durable fields. It deliberately excludes store.Incident's LLM output
// fields (Summary, RootCause, Confidence, OutputJSON, EnrichmentJSON):
// those are store/MCP-facing prose projections, not the normalized Finding
// evidence Task 4 needs (see TriageState's doc comment).
type IncidentState struct {
	ID           string
	GroupKey     string
	Status       string
	FirstAlertAt time.Time
	LastAlertAt  time.Time
	ReadyAt      time.Time
	AlertCount   int
	Triage       TriageState
}

// CompletedSituation is one prior terminal Situation in the same exact-group
// lineage — just enough raw identity/timing for Task 4's later
// "prior_situation_duration_distribution" fact to reduce a duration from
// (TerminalAt - EffectiveStartedAt). This task does not compute that
// duration itself; deriving it is Task 4's pure-function job.
type CompletedSituation struct {
	ID                 string
	GroupKey           string
	EffectiveStartedAt time.Time
	TerminalAt         time.Time
	TerminalReason     model.TerminalReason
}
