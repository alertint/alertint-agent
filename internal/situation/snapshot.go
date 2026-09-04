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

	// ControllerParked is the Situation's current controller_parked_at/
	// controller_parked_reason projection, plus the material fact hash the
	// park was recorded against — read directly off situations' raw ALTER
	// TABLE columns (migration 0015), which carry no model.Situation Go
	// struct field of their own (see store's BeginControllerAttempt doc
	// comment for why: Plan 1's model.Situation predates Plan 2's controller
	// projection columns). Reconcile uses this to decide whether a policy/
	// capability park still covers the CURRENT basis before dispatching new
	// L2 work (Finding I1 — spec.md: "Policy rejection, unsupported scope,
	// and unsupported capability are permanent for the unchanged basis").
	ControllerParked ControllerParkedState
}

// ControllerParkedState is SnapshotInput's own read of the Situation's
// current controller_parked_at/controller_parked_reason columns plus the
// material fact hash they were recorded against. Zero value (Reason=="")
// means "not currently parked." MaterialFactHash reliably names the exact
// basis a currently-active park refers to because situations.
// current_material_fact_hash is refreshed on every CommitController commit
// regardless of whether that commit touches Parked (ControllerCommit's own
// doc comment) — so as long as Parked stays untouched, MaterialFactHash and
// the park it pairs with always move together.
type ControllerParkedState struct {
	At               *time.Time
	Reason           string
	MaterialFactHash string
}

// Delivery is one immutable Alert delivery belonging to a member Incident of
// the Situation being reconciled — the lean, transport-neutral trim of
// store.AlertDelivery's identity-relevant fields (this package must never
// import internal/store, so it cannot reuse that type directly). It
// deliberately excludes store.Alert's mutable "latest wins" projection and
// most SQL-facing internals (the full labels/annotations map, fingerprint,
// provenance mode): Status is read from alert_deliveries.status, the
// immutable per-delivery source lifecycle, never inferred from the mutable
// Alert row. Two narrow exceptions are extracted from the immutable
// alert_deliveries row at the store layer and threaded through as plain
// values rather than a raw label map — see AlertID, Severity, and Drill
// below; this pure package never parses labels JSON itself.
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

	// AlertID is the immutable alert_deliveries.alert_id foreign key — the
	// underlying Alert this delivery represents, distinct from ID (this
	// delivery's own identity). Alertmanager's routine re-send of an
	// unchanged alert appends a new alert_deliveries row (a new ID) that
	// still names the same AlertID; MembershipDigest uses this to collapse
	// "the same Alert re-firing" into one member instead of manufacturing a
	// new one on every routine re-fire. See incident_digest.go.
	AlertID string

	// Severity is the raw alert_deliveries.labels_json["severity"] value for
	// this delivery, exactly as received from the source — empty when the
	// label is absent. This package's pure layer, not the store, decides
	// what counts as "critical" (via internal/severity.Rank); see
	// criticalAnchorEligible in reasons.go.
	Severity string

	// Drill reports whether this delivery's labels carry the Drill marker —
	// alert_deliveries.labels_json[store.DrillMarkerLabel] == "true", the
	// same marker store.Alert.IsDrill checks, read here directly off the
	// immutable per-delivery labels rather than the mutable Alert
	// projection.
	Drill bool
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
// immutable Deliveries, one per member Incident: Key == IncidentID. Status
// is the Incident's aggregate source lifecycle reduced PER ALERT: each
// distinct Delivery.AlertID contributes only its chronologically latest
// delivery (deliveryLess' total order, the same one MembershipDigest and
// criticalAnchorEligible use), and the Incident is "firing" while ANY of its
// Alerts' latest deliveries is firing — it is "resolved" only once every
// Alert's latest delivery has resolved. One Alert resolving while a sibling
// still fires must never read as a recovered Incident (external review of
// 2026-09-05: the earlier "status of the Incident's most recently received
// delivery" reduction let a single resolved sibling drive
// active → recovery_pending → recovered under a still-firing Alert).
// FirstObservedAt is the earliest Delivery's ReceivedAt.
//
// Key stays the Incident ID rather than a per-Alert-pattern identity: the
// Incident is Plan 2's unit of Acute Triage coverage and the symptom facts,
// lifecycle summary, and material hash are all keyed on it. A later plan may
// split this into genuine per-Alert symptom identity (which novel_symptom
// needs — see reasons.go); the per-Alert reduction inside each Incident is
// what this slice needs for lifecycle truth.
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
// order, map iteration, or receipt/retry order). Status is per-Alert-latest
// any-firing — see Symptom's doc comment for the rule and why.
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
		ds := byIncident[k]
		first := ds[0].ReceivedAt
		for _, d := range ds[1:] {
			if d.ReceivedAt.Before(first) {
				first = d.ReceivedAt
			}
		}
		out = append(out, Symptom{
			Key:             k,
			Status:          incidentSymptomStatus(ds),
			FirstObservedAt: first,
		})
	}
	return out
}

// incidentSymptomStatus is one Incident's aggregate source lifecycle: firing
// while any distinct Alert's chronologically latest delivery is firing,
// resolved once every Alert's latest delivery has resolved. Alert identity
// is Delivery.AlertID (alert_deliveries.alert_id, NOT NULL); a delivery
// with no AlertID (test fixtures only) counts as its own Alert so it can
// never be superseded by an unrelated row.
func incidentSymptomStatus(deliveries []Delivery) model.DeliveryStatus {
	latestByAlert := make(map[string]Delivery, len(deliveries))
	for _, d := range deliveries {
		alertKey := d.AlertID
		if alertKey == "" {
			alertKey = "delivery:" + d.ID
		}
		cur, ok := latestByAlert[alertKey]
		if !ok || deliveryLess(cur, d) {
			latestByAlert[alertKey] = d
		}
	}
	for _, d := range latestByAlert {
		if d.Status == model.DeliveryStatusFiring {
			return model.DeliveryStatusFiring
		}
	}
	return model.DeliveryStatusResolved
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
