// SPDX-License-Identifier: FSL-1.1-ALv2

// Package model defines the transport-neutral shapes shared by the bounded
// evidence preparation path: frozen cycles, canonical plans, durable request
// reservations, normalized runs/facts, and their fixed versioned caps. It
// imports only the standard library so both internal/observation (the
// planner/runner) and internal/store (the durable persistence layer) can
// depend on it without creating an import cycle.
package model

import (
	"encoding/json"
	"errors"
	"time"
)

// Capability is the closed seven-name proactive evidence-source vocabulary
// (spec.md "Deterministic planning and connector contracts"). No other value
// is ever planned or persisted.
type Capability string

const (
	CapabilityStoreRead         Capability = "store_read"
	CapabilityPrometheusQuery   Capability = "prometheus_query"
	CapabilityZabbixMetricRange Capability = "zabbix_metric_range"
	CapabilityZabbixProblemHist Capability = "zabbix_problem_history"
	CapabilityLokiQuery         Capability = "loki_query"
	CapabilitySentryIssues      Capability = "sentry_issues"
	CapabilityChangeEvents      Capability = "change_events"
)

// Capabilities is the closed, ordered set every planner/validator/prompt
// vocabulary agrees on.
var Capabilities = []Capability{
	CapabilityStoreRead,
	CapabilityPrometheusQuery,
	CapabilityZabbixMetricRange,
	CapabilityZabbixProblemHist,
	CapabilityLokiQuery,
	CapabilitySentryIssues,
	CapabilityChangeEvents,
}

// ValidCapability reports whether c is one of the closed seven capability
// names.
func ValidCapability(c Capability) bool {
	for _, v := range Capabilities {
		if v == c {
			return true
		}
	}
	return false
}

// Phase is a preparation phase: lifecycle reads run first and decide
// recovery/closure; assessment reads run only while the Situation remains
// active.
type Phase string

const (
	PhaseLifecycle  Phase = "lifecycle"
	PhaseAssessment Phase = "assessment"
)

func validPhase(p Phase) bool {
	return p == PhaseLifecycle || p == PhaseAssessment
}

// ResultStatus is the closed nine-name normalized-evidence result vocabulary
// (spec.md "Normalized evidence and lifecycle").
type ResultStatus string

const (
	ResultConfirmedValue       ResultStatus = "confirmed_value"
	ResultConfirmedEmpty       ResultStatus = "confirmed_empty"
	ResultUnconfirmedEmpty     ResultStatus = "unconfirmed_empty"
	ResultUnavailable          ResultStatus = "unavailable"
	ResultFailed               ResultStatus = "failed"
	ResultStale                ResultStatus = "stale"
	ResultTruncated            ResultStatus = "truncated"
	ResultWithheldByBudget     ResultStatus = "withheld_by_budget"
	ResultVocabularyUnresolved ResultStatus = "vocabulary_unresolved"
)

// ResultStatuses is the closed, ordered set of valid ResultStatus values.
var ResultStatuses = []ResultStatus{
	ResultConfirmedValue, ResultConfirmedEmpty, ResultUnconfirmedEmpty,
	ResultUnavailable, ResultFailed, ResultStale, ResultTruncated,
	ResultWithheldByBudget, ResultVocabularyUnresolved,
}

// ValidResultStatus reports whether s is one of the closed nine result
// states.
func ValidResultStatus(s ResultStatus) bool {
	for _, v := range ResultStatuses {
		if v == s {
			return true
		}
	}
	return false
}

// Freshness separates "was this evidence obtained now" from its result
// content.
type Freshness string

const (
	FreshnessFresh   Freshness = "fresh"
	FreshnessStale   Freshness = "stale"
	FreshnessUnknown Freshness = "unknown"
)

func validFreshness(f Freshness) bool {
	return f == FreshnessFresh || f == FreshnessStale || f == FreshnessUnknown
}

// Fixed versioned caps (spec.md "Defaults and hard limits"). These are not
// configuration: every adapter, planner, and validator in this slice agrees
// on these exact numbers, and a schema/validator version bump is required to
// ever change one.
const (
	MaxPlansPerCycle           = 16
	MaxFactsPerRun             = 100
	MaxFactBytes               = 16 * 1024
	MaxNormalizedBytesPerCycle = 256 * 1024
	MaxDecodedResponseBytes    = 1024 * 1024
	MaxEvidenceRefsPerFact     = 50

	// MaxWindowHoursMetricsLogs / MaxWindowDaysHistory are the hard window
	// caps metric/log reads and source/local event-history reads may never
	// exceed, regardless of source configuration or profile widening.
	MaxWindowHoursMetricsLogs = 24
	MaxWindowDaysHistory      = 7

	// MaxPlanParametersBytes bounds one plan's typed Parameters payload — a
	// planner-authored (never model-authored) JSON document. It is sized
	// generously above any real capability-specific parameter shape so a
	// genuine plan never trips it, while still refusing an unbounded or
	// malformed payload outright (never silently truncated).
	MaxPlanParametersBytes = 8 * 1024

	// FactSchemaVersion, MaterialHashVersion, AssessmentBasisHashVersion, and
	// ValidatorVersion are Task 6's exact version bump targets (spec.md
	// "Normalized evidence and lifecycle": "Advance fact schema to 2,
	// material hash to 3, Assessment-basis hash to 4, and validator to 2").
	FactSchemaVersion          = 2
	MaterialHashVersion        = 3
	AssessmentBasisHashVersion = 4
	ValidatorVersion           = 2

	// planIDSchemaVersion is CanonicalPlanID's own encoding-schema version —
	// distinct from FactSchemaVersion, and bumped only if the canonical
	// encoding itself changes shape.
	planIDSchemaVersion = 1
)

// ErrBudgetExhausted is returned by ReserveObservationRequest when a cycle's
// physical request budget (cycle-wide or per-plan) is already spent.
var ErrBudgetExhausted = errors.New("observation: request budget exhausted")

// ErrConflictingReplay is returned by CommitObservationRun when a run ID
// already has a committed run with different normalized content — a replay
// safety violation, never silently overwritten.
var ErrConflictingReplay = errors.New("observation: conflicting replay for an already-committed run")

// Fence identifies the exact Situation claim a preparation operation is
// performed under — the transport-neutral counterpart of situation.Claim's
// (ClaimOwner, ClaimToken) pair plus the Situation's current input version.
// Every durable preparation write requires a Fence and fails closed if it no
// longer matches the live claim.
type Fence struct {
	SituationID  string
	InputVersion int
	Owner        string
	Token        int64
}

// Scope is one plan's exact source/member targeting: existing configured
// group/member identity plus the deterministic label/selector assertions
// carried into every constructed query (ADR-0035). SubjectID identifies the
// specific member/host/service the plan targets within the group.
type Scope struct {
	GroupKey  string            `json:"group_key"`
	Source    string            `json:"source"`
	SubjectID string            `json:"subject_id"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// Plan is one canonical, frozen unit of preparation work: capability, exact
// scope, typed parameters, UTC window, limits, phase, purpose, and stop/
// reconsider conditions. ID is a full content digest of cycle identity plus
// canonical plan (CanonicalPlanID) — no UUID or retry timestamp ever enters
// plan identity.
type Plan struct {
	ID           string          `json:"id"`
	CycleID      string          `json:"cycle_id"`
	Capability   Capability      `json:"capability"`
	Phase        Phase           `json:"phase"`
	Scope        Scope           `json:"scope"`
	Parameters   json.RawMessage `json:"parameters,omitempty"`
	Start        time.Time       `json:"start"`
	End          time.Time       `json:"end"`
	EligibleAt   time.Time       `json:"eligible_at"`
	Limit        int             `json:"limit"`
	MaxRequests  int             `json:"max_requests"`
	Purpose      string          `json:"purpose"`
	ReconsiderOn []string        `json:"reconsider_on,omitempty"`
	StopOn       []string        `json:"stop_on,omitempty"`
	// Tier is the investigative-fairness tier the planner froze this plan
	// into (Tier* constants); it decides execution order and which
	// reservations debit optional credit. Empty means routine.
	Tier string `json:"tier,omitempty"`
	// ReuseRunID names the still-fresh prior run this plan projects into the
	// current cycle by explicit reference instead of a fresh read (Tier ==
	// TierReuse). Such a plan never performs I/O and never spends a request.
	ReuseRunID string `json:"reuse_run_id,omitempty"`
}

// Plan tiers — the closed vocabulary situation_observation_plans.tier
// accepts. local marks a plan that consumes no physical request (store_read,
// change_events); reuse marks an explicit projection of a prior run.
const (
	TierTimeSensitive = "time_sensitive"
	TierOptional      = "optional"
	TierRoutine       = "routine"
	TierLocal         = "local"
	TierReuse         = "reuse"
)

// ValidTier reports whether t is one of the closed plan tiers (an empty
// tier is treated as routine by every consumer).
func ValidTier(t string) bool {
	switch t {
	case "", TierTimeSensitive, TierOptional, TierRoutine, TierLocal, TierReuse:
		return true
	}
	return false
}

// PhaseAllocation freezes, once per cycle, the investigative-fairness
// allocation spec.md's "Defaults and hard limits" defines: how many
// time-sensitive lifecycle, routine lifecycle, and optional (credit-earned)
// requests this cycle may spend, which optional plan (if any) is protected,
// and how much of the preparation wall that protected plan reserves.
type PhaseAllocation struct {
	TimeSensitiveRequests    int    `json:"time_sensitive_requests"`
	RoutineLifecycleRequests int    `json:"routine_lifecycle_requests"`
	OptionalRequests         int    `json:"optional_requests"`
	OptionalPlanID           string `json:"optional_plan_id,omitempty"`
	OptionalWallMilliseconds int64  `json:"optional_wall_milliseconds"`
	// Deferred lists (bounded, MaxPlansPerCycle entries) the capability:
	// subject keys this cycle could not admit under its request cap or
	// credit, so a deferral is durable and visible rather than discarded.
	Deferred []string `json:"deferred,omitempty"`
}

// ProfileGuidance is the bounded, frozen advisory guidance from one semantic
// profile version admitted into a cycle's plan set — enough for the planner
// to widen horizon/capabilities within hard caps, never enough to grant
// authority over identity or lifecycle.
type ProfileGuidance struct {
	SignatureKey       string       `json:"signature_key"`
	VersionID          string       `json:"version_id"`
	HorizonTier        string       `json:"horizon_tier"`
	UsefulCapabilities []Capability `json:"useful_capabilities,omitempty"`
	CandidateScope     []string     `json:"candidate_scope,omitempty"`
}

// CycleDraft is BeginPreparation's input: the proposed frozen cycle content
// before it is durably assigned an ID and (on first commit) frozen forever.
// A retry recomputes its own CycleDraft, but BeginPreparation returns the
// EXISTING cycle's Draft unchanged when one is already open for this Fence.
type CycleDraft struct {
	Anchor       time.Time
	ConfigDigest string
	// RefreshInterval is the source cadence frozen into the cycle: the
	// first durable request reservation records fresh-read admission as
	// Anchor+RefreshInterval without consulting live configuration.
	RefreshInterval   time.Duration
	ProfileVersionIDs []string
	ProfileGuidance   []ProfileGuidance
	Plans             []Plan
	Allocation        PhaseAllocation
}

// Cycle is one durable, frozen preparation cycle keyed by (situation_id,
// input_version, preparation_generation). Its Draft is authoritative from
// first commit forward; retries and restarts reuse it verbatim.
type Cycle struct {
	ID          string
	Fence       Fence
	Generation  int64
	Draft       CycleDraft
	MaxRequests int
	Sealed      bool
}

// RequestReservation is the durable, pre-dispatch reservation for exactly
// one physical HTTP/RPC request. Its identity (ID, CycleID, PlanID, Ordinal)
// is immutable; a crash after reservation but before a recorded outcome
// still consumes the slot.
type RequestReservation struct {
	ID, CycleID, PlanID string
	Ordinal             int
	ReservedAt          time.Time
}

// RequestOutcome finishes one reservation: whether the request actually
// started (a crash before the wire write leaves this legitimately unknown),
// and a closed transport/content/limit outcome code — never the provider's
// raw error body.
type RequestOutcome struct {
	ReservationID string
	// RequestStarted is "true" | "false" | "unknown" — see the
	// RequestStarted* constants.
	RequestStarted string
	Code           string
	CompletedAt    time.Time
}

// Request-started outcome states — closed three-value vocabulary.
const (
	RequestStartedTrue    = "true"
	RequestStartedFalse   = "false"
	RequestStartedUnknown = "unknown"
)

// Coverage separates a run's query window/completeness from its result
// content: how much of [Start, End] was actually returned versus omitted by
// truncation or a hard cap, never asserting whole-episode or whole-source
// health.
type Coverage struct {
	Start, End time.Time
	Complete   bool
	Returned   int
	Omitted    int
}

// Fact is one normalized, typed observation derived from a Run — the only
// shape that ever crosses into situation_observation_facts. Material marks
// whether this fact's normalized content changed the cycle's material hash;
// EvidenceRefs cite the durable evidence (bounded, spec cap
// MaxEvidenceRefsPerFact) this fact rests on.
type Fact struct {
	ID, RunID, Kind, Subject, Digest string
	SchemaVersion                    int
	Value                            json.RawMessage
	ResultStatus                     ResultStatus
	Freshness                        Freshness
	ObservedAt, ExpiresAt            time.Time
	EvidenceRefs                     []string
	Material                         bool
}

// Run is one completed (or explicitly limited/failed) execution of a Plan:
// its normalized Facts, coverage, and any limitation codes. CompletedAt is
// the store's own durable completion clock — the retention anchor (ADR-0051)
// — distinct from ObservedAt (source observation time) and from collection/
// generation churn, which never enters material identity.
type Run struct {
	// ScopeKey and Capability are read projections from the owning plan. They
	// identify an evidence slot across collection cycles, never a dispatch.
	ScopeKey            string
	Capability          Capability
	Scope               *Scope
	Parameters          json.RawMessage
	ID, CycleID, PlanID string
	Status              ResultStatus
	Coverage            Coverage
	Facts               []Fact
	LimitationCodes     []string
	ObservedAt          time.Time
	ExpiresAt           time.Time
	CompletedAt         time.Time
	ReusedFromRunID     *string
}

// Detail states for archive reads (spec.md "Observation history retention").
const (
	DetailStateRetained = "retained"
	DetailStateExpired  = "expired"
)

// RunRecord is an archive-safe read of a Run: DetailState reports whether
// its normalized detail (Facts/Value payloads) is still present or has
// expired under the ten-day unused-detail retention rule. An expired record
// never enters the live reducer — only immutable identity/accounting
// survives expiry.
type RunRecord struct {
	Run             Run
	DetailState     string
	DetailExpiredAt *time.Time

	// Plan identity behind the run (review F23): which capability read
	// which subject, in which phase and fairness tier.
	Capability Capability
	Subject    string
	Phase      Phase
	Tier       string
	// Request ledger (immutable reservations/outcomes): how many physical
	// requests were reserved for this plan, how many recorded an outcome,
	// and how many remain reserved with no outcome (a crash before the
	// outcome was written — legitimately unknown, never invented).
	RequestsReserved  int
	RequestsCompleted int
	RequestsUnknown   int
}

// SourceLifecycleObservation is one member Alert's authoritative lifecycle
// observation as the store_read lifecycle phase emits it (fact kind
// "source_lifecycle", Value = JSON array of these). Its JSON shape is
// exactly internal/situation.SourceObservation's, so the controller's
// reload decodes it without this package ever importing internal/situation.
type SourceLifecycleObservation struct {
	AlertID             string     `json:"alert_id"`
	EpisodeKey          string     `json:"episode_key"`
	Source              string     `json:"source"`
	State               string     `json:"state"`
	ObservedAt          time.Time  `json:"observed_at"`
	EventStartedAt      *time.Time `json:"event_started_at,omitempty"`
	EventResolvedAt     *time.Time `json:"event_resolved_at,omitempty"`
	TimeBasis           string     `json:"time_basis,omitempty"`
	AcquisitionMode     string     `json:"acquisition_mode"`
	PollIntervalSeconds int        `json:"poll_interval_seconds,omitempty"`
	DeadlineAt          time.Time  `json:"deadline_at"`
	HorizonTier         string     `json:"horizon_tier,omitempty"`
	EvidenceRefs        []string   `json:"evidence_refs,omitempty"`
}

// Lifecycle horizon tiers (spec.md "Normalized evidence and lifecycle"):
// the default unknown horizon is 24 h; a profile may widen to hours (24 h)
// or days (7 d), never shorten the baseline.
const (
	HorizonTierUnknown = "unknown"
	HorizonTierMinutes = "minutes"
	HorizonTierHours   = "hours"
	HorizonTierDays    = "days"

	DefaultLifecycleHorizon = 24 * time.Hour
)

// LifecycleHorizon resolves the observation horizon for tier, widening
// only: minutes/unknown/empty keep the 24 h default, hours is 24 h, days is
// 7 d.
func LifecycleHorizon(tier string) time.Duration {
	if tier == HorizonTierDays {
		return MaxWindowDaysHistory * 24 * time.Hour
	}
	return DefaultLifecycleHorizon
}

// WidestHorizonTier picks the widest tier among guidance — the effective
// advisory widening a cycle applies uniformly to its members.
func WidestHorizonTier(guidance []ProfileGuidance) string {
	widest := HorizonTierUnknown
	for _, g := range guidance {
		if g.HorizonTier == HorizonTierDays {
			return HorizonTierDays
		}
		if g.HorizonTier == HorizonTierHours {
			widest = HorizonTierHours
		}
	}
	return widest
}

// LocalSituationSummary is one bounded, existing-delivery-truth prior
// Situation the store_read capability may cite — durable Situation
// lifecycle history, never a lack-of-prior-rows-implies-anything claim
// (spec.md: "a lack of prior rows is insufficient history").
type LocalSituationSummary struct {
	ID                 string    `json:"id"`
	EffectiveStartedAt time.Time `json:"effective_started_at"`
	TerminalAt         time.Time `json:"terminal_at,omitempty"`
	TerminalReason     string    `json:"terminal_reason,omitempty"`
}

// LocalFinding is one bounded, durable Acute Triage finding the store_read
// capability may cite as prior evidence for the same group.
type LocalFinding struct {
	IncidentID string    `json:"incident_id"`
	AnalyzedAt time.Time `json:"analyzed_at"`
	Summary    string    `json:"summary,omitempty"`
	RootCause  string    `json:"root_cause,omitempty"`
	Confidence float64   `json:"confidence"`
}

// LocalChange is one bounded, locally ingested change-ledger event the
// change_events capability may cite — temporal correlation evidence only,
// never supported causality or an urgent policy signal.
type LocalChange struct {
	ID         string            `json:"id"`
	Source     string            `json:"source"`
	Kind       string            `json:"kind"`
	Title      string            `json:"title"`
	Labels     map[string]string `json:"labels,omitempty"`
	Version    string            `json:"version,omitempty"`
	Link       string            `json:"link,omitempty"`
	OccurredAt time.Time         `json:"occurred_at"`
}
