// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"sort"
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

	// LatestAttempt is the most recent completed incident_triage_attempts
	// row's normalized result, when one exists — nil until Task 6 adds the
	// store-side writer and a later task wires LoadReconciliationInput to
	// populate it. DeriveStoreFacts's acute_finding fact must treat nil as
	// "no Finding yet" (a legitimate state for a pending/in-flight
	// Incident), never as confirmed-empty evidence.
	LatestAttempt *TriageAttemptResult
}

// TriageAttemptResult is the most recent completed incident_triage_attempts
// row's normalized result for one Incident. Its fields mirror that table's
// completion columns exactly (migration 0016_incident_triage_controller.sql:
// result_code, output_digest, finding_id, evidence_pack_digest,
// completed_at) — the row's frozen claim-time identity/digest columns
// belong to the store's own attempt ledger, not this snapshot-facing
// projection of its outcome.
type TriageAttemptResult struct {
	ResultCode         string
	OutputDigest       string
	FindingID          *string
	EvidencePackDigest *string
	CompletedAt        time.Time
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

// ----------------------------------------------------------------------
// Task 4: pure Snapshot/fact/hash/reason reduction over SnapshotInput. See
// facts.go (DeriveStoreFacts, MaterialFactHash, AssessmentBasisHash),
// incident_digest.go (MembershipDigest, IncidentInputDigest), and
// reasons.go (EligibleReasons) for the rest of this task's pure functions.
// ----------------------------------------------------------------------

// Symptom is one normalized active symptom derived from a Situation's
// immutable Deliveries. Plan 2's situation.Delivery (Task 3's deliberate
// trim of store.AlertDelivery) carries no field distinguishing "the same
// underlying Alert re-firing" from "a different Alert" beyond its own
// Delivery.ID and its owning Incident's IncidentID — no alertname, no
// labels, no fingerprint reach this pure layer. The finest symptom-identity
// granularity actually available is therefore one Incident's own aggregate
// delivery lifecycle: Key == IncidentID. Status is the status of the
// Incident's most-recently-received Delivery (ReceivedAt order, not
// SourceStartedAt order — the freshest thing the store actually heard is
// what "currently observed" means); FirstObservedAt is the earliest
// Delivery's ReceivedAt. This collapses what a later plan may split into a
// genuine per-Alert-pattern symptom identity distinct from delivery
// grouping; see the Task 4 report for the full reasoning.
type Symptom struct {
	Key             string
	Status          model.DeliveryStatus
	FirstObservedAt time.Time
}

// Snapshot is the canonical, deterministic reduction of one SnapshotInput:
// everything a Situation controller cycle needs to validate an Assessment
// proposal or derive a deterministic one, with stable hashes over only its
// material content. BuildSnapshot is the sole producer.
type Snapshot struct {
	SituationID         string
	InputVersion        int
	Lifecycle           model.Lifecycle
	ElapsedSeconds      int64
	DurationClass       string
	Facts               []model.Fact
	Symptoms            []Symptom
	Incidents           []IncidentState
	EligibleReasons     []model.ReasonCandidate
	MaterialFactHash    string
	AssessmentBasisHash string
}

// Duration classes. Boundaries are half-open on the low end: subminute
// covers [0, 1m), short [1m, 15m), medium [15m, 1h), long [1h, inf). These
// are the only closed values DurationClass returns.
const (
	DurationClassSubminute = "subminute"
	DurationClassShort     = "short"
	DurationClassMedium    = "medium"
	DurationClassLong      = "long"
)

// DurationClass reduces an elapsed duration to its closed class. A negative
// elapsed value (defensive only — callers clamp via elapsedDuration) is
// treated as subminute.
func DurationClass(elapsed time.Duration) string {
	switch {
	case elapsed < time.Minute:
		return DurationClassSubminute
	case elapsed < 15*time.Minute:
		return DurationClassShort
	case elapsed < time.Hour:
		return DurationClassMedium
	default:
		return DurationClassLong
	}
}

// durationClassLowerBound returns the elapsed-duration lower bound at which
// class begins — the "threshold crossing" offset added to
// EffectiveStartedAt to get the current_duration fact's stable
// threshold_crossed_at value. Unknown classes return 0 defensively; every
// class DurationClass can return is handled explicitly.
func durationClassLowerBound(class string) time.Duration {
	switch class {
	case DurationClassSubminute:
		return 0
	case DurationClassShort:
		return time.Minute
	case DurationClassMedium:
		return 15 * time.Minute
	case DurationClassLong:
		return time.Hour
	default:
		return 0
	}
}

// elapsedDuration is in.Now - in.Situation.EffectiveStartedAt, clamped to a
// minimum of 0 so a clock/data anomaly (Now before EffectiveStartedAt)
// never produces a negative elapsed value.
func elapsedDuration(in SnapshotInput) time.Duration {
	elapsed := in.Now.Sub(in.Situation.EffectiveStartedAt)
	if elapsed < 0 {
		return 0
	}
	return elapsed
}

// deriveSymptoms reduces deliveries to one Symptom per distinct IncidentID,
// sorted by Key so the result never depends on deliveries' input order (row
// order, map iteration, or receipt/retry order). See Symptom's doc comment
// for why Key == IncidentID in this reduction.
func deriveSymptoms(deliveries []Delivery) []Symptom {
	byIncident := make(map[string][]Delivery, len(deliveries))
	for _, d := range deliveries {
		byIncident[d.IncidentID] = append(byIncident[d.IncidentID], d)
	}
	keys := make([]string, 0, len(byIncident))
	for k := range byIncident {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]Symptom, 0, len(keys))
	for _, k := range keys {
		ds := append([]Delivery(nil), byIncident[k]...)
		sort.Slice(ds, func(i, j int) bool {
			if !ds[i].ReceivedAt.Equal(ds[j].ReceivedAt) {
				return ds[i].ReceivedAt.Before(ds[j].ReceivedAt)
			}
			return ds[i].ID < ds[j].ID
		})
		out = append(out, Symptom{
			Key:             k,
			Status:          ds[len(ds)-1].Status,
			FirstObservedAt: ds[0].ReceivedAt,
		})
	}
	return out
}

// sortIncidentsByID returns a copy of incidents ordered by ID, never
// mutating the caller's slice — Snapshot.Incidents must never depend on
// database row order.
func sortIncidentsByID(incidents []IncidentState) []IncidentState {
	out := append([]IncidentState(nil), incidents...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// BuildSnapshot is the canonical, deterministic reduction of in into a
// Snapshot. It is pure: no I/O, no randomness, no clock read beyond in.Now.
func BuildSnapshot(in SnapshotInput) Snapshot {
	symptoms := deriveSymptoms(in.Deliveries)
	elapsed := elapsedDuration(in)
	class := DurationClass(elapsed)
	facts := deriveStoreFactsWith(in, symptoms, class)
	eligible := EligibleReasons(in, symptoms, class)
	materialHash := MaterialFactHash(in, symptoms, class)
	basisHash := AssessmentBasisHash(in, materialHash, eligible)

	return Snapshot{
		SituationID:         in.Situation.ID,
		InputVersion:        in.Situation.InputVersion,
		Lifecycle:           in.Situation.Lifecycle,
		ElapsedSeconds:      int64(elapsed.Seconds()),
		DurationClass:       class,
		Facts:               facts,
		Symptoms:            symptoms,
		Incidents:           sortIncidentsByID(in.Incidents),
		EligibleReasons:     eligible,
		MaterialFactHash:    materialHash,
		AssessmentBasisHash: basisHash,
	}
}
