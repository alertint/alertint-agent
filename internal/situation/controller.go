// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/google/uuid"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// Package situation is transport-neutral: it must never import
// internal/store. This file's types are the data shapes that
// internal/store's controller-facing methods (Task 3) return/accept so
// they structurally satisfy the ControllerStore interface Task 8 declares
// in this same file. Task 8 adds ControllerStore, AssessmentClient,
// AuditSink, Controller, NewController, and Reconcile here — extend this
// file, do not recreate it.

// Claim is one claimed Situation: its own current durable state (Situation)
// plus the lease-fencing pair (ClaimOwner, ClaimToken) a controller cycle
// holds it under. It is the transport-neutral counterpart to
// internal/store's ClaimDueSituations result — Task 8's ClaimControllerWork
// converts model.Situation (whose own LeaseOwner/ClaimToken fields already
// carry this pair) into a Claim.
type Claim struct {
	Situation  model.Situation
	ClaimOwner string
	ClaimToken int64
}

// AssessmentCall is one immutable L2 provider dispatch record — the row
// RecordAssessmentCall persists durably before the physical HTTP request,
// proving the call budget was consumed regardless of what the request
// itself returns. Its fields mirror situation_assessment_calls (migration
// 0015) exactly: MaterialFactHash and ProviderProfile replace this file's
// literal plan.md snippet's "AssessmentBasisHash" field, which named a
// column that table does not have (situation_assessment_calls carries
// material_fact_hash and provider_profile, not assessment_basis_hash — that
// column exists only on situation_assessment_attempts). This is a deviation
// from the plan's Cross-Task Contracts snippet made for concrete
// schema-fidelity reasons (0015 is this task's binding ground truth); see
// the Task 3 report for the full rationale.
type AssessmentCall struct {
	ID, SituationID, MaterialFactHash                 string
	ProviderProfile                                   *string
	InputVersion, RetryEpoch, WorkAttempt, CallNumber int
	DispatchedAt                                      time.Time
}

// AssessmentAttempt is one immutable Assessment outcome — a validated,
// rejected, failed, or stale L2 result, or (authoritative only, written
// exclusively by fenced CommitController) a non-model derivation. Its
// fields mirror situation_assessment_attempts (migration 0015) exactly:
// UsageInputTokens/UsageOutputTokens replace this file's literal plan.md
// snippet's single "ModelUsage json.RawMessage" field, and
// "ValidationAdjustments json.RawMessage" is dropped — the table carries
// usage_input_tokens/usage_output_tokens as two separate nullable INTEGER
// columns (not one JSON blob), and has no column at all for a separate
// typed "adjustments" list distinct from validation_errors_json. This is a
// deviation from the plan's Cross-Task Contracts snippet made for concrete
// schema-fidelity reasons (0015 is this task's binding ground truth); see
// the Task 3 report for the full rationale. A future task that needs typed
// adjustment records distinct from errors will need either a migration
// change or a documented convention for encoding both inside
// validation_errors_json — Task 3 does not decide that.
type AssessmentAttempt struct {
	ID, SituationID, AssessmentBasisHash            string
	CallID                                          *string
	InputVersion, RetryEpoch, WorkAttempt, Sequence int
	Derivation                                      model.AssessmentDerivation
	Status                                          string // authoritative | rejected | failed | stale
	Proposal, Validated                             json.RawMessage
	ValidationErrors                                json.RawMessage
	ProviderRequestStarted                          *model.ProviderRequestStarted
	UsageInputTokens, UsageOutputTokens             *int
	ReusedFromAssessmentID                          *string
	CreatedAt, CompletedAt                          time.Time
}

// AuthoritativeAssessment is one Situation's current (or, when returned by
// a future LastTrustworthyAssessment, most recent trustworthy)
// authoritative Assessment: the attempt's own identity and derivation
// provenance, its full Assessment content, and the bounded per-Incident
// coverage tuples it recorded.
type AuthoritativeAssessment struct {
	ID, SituationID, AssessmentBasisHash string
	// MaterialFactHash is the attempt's own situation_assessment_attempts.
	// material_fact_hash column — the exact material fact hash this
	// authoritative Assessment was derived against. Added for Task 6: the
	// B+ Triage skip decision must compare a trustworthy Assessment's own
	// material fact hash against the CURRENT Snapshot's MaterialFactHash
	// (spec: "skip only when a trustworthy Assessment covers the unchanged
	// material fact hash and current membership and Incident-input
	// digests") — a check distinct from, and stricter-scoped than,
	// AssessmentBasisHash equality (which RevalidateReuse uses for a
	// different purpose: whether the whole reuse-eligible basis, including
	// eligible reasons/lifecycle/attention/floor/schema versions, is
	// unchanged).
	MaterialFactHash       string
	InputVersion           int
	Assessment             model.Assessment
	Coverage               []model.IncidentCoverage
	Derivation             model.AssessmentDerivation
	ReusedFromAssessmentID *string
}

// TriageDecision is one Incident's request/skip Acute Triage decision, made
// against the exact snapshot (Situation input version, material fact hash,
// and both Incident digests) it was decided from. Task 6's DecideTriage
// produces these; Task 8's CommitController persists them alongside the
// Assessment they share one atomic commit with.
type TriageDecision struct {
	IncidentID, Decision, DecisionReason, SituationID       string
	SituationInputVersion                                   int
	CoveredAssessmentID                                     *string
	MaterialFactHash, MembershipDigest, IncidentInputDigest string
	DecidedAt                                               time.Time
}

// ControllerCommit is everything one fenced CommitController transaction
// commits together: the Assessment attempt and its content, the Triage
// decisions sharing that commit, the projected lifecycle/Attention/
// recovery/terminal fields, the next deterministic checkpoint, which due
// reasons the claim consumed, and retry/error state. Task 8 completes the
// decision/projection behavior that produces and applies this; Task 3
// declares the type and CommitController's fenced-transaction skeleton
// only.
//
// Attempt, MaterialFactHash, AssessmentBasisHash, and Coverage — Task 8
// additive fields, following the same pattern Task 6 used to add
// MaterialFactHash to AuthoritativeAssessment:
//
//   - Attempt is the zero value (Attempt.ID == "") on a cycle that produces
//     no NEW authoritative attempt row — "reconciliation churn within an
//     unchanged basis" that only refreshes the bounded current projection
//     (e.g. a still-parked cycle with nothing new to report, or one that
//     newly parks/unparks without a fresh semantic judgment). CommitController
//     inserts a row and advances current_assessment_id only when Attempt.ID
//     is non-empty.
//   - MaterialFactHash/AssessmentBasisHash are the CURRENT snapshot's own
//     hashes, refreshed onto situations.current_material_fact_hash/
//     current_assessment_basis_hash on every commit regardless of whether
//     Attempt is populated (Attempt's own copy of these, when present, is
//     what the durable row itself carries).
//   - Coverage is the bounded per-Incident coverage tuple set persisted
//     alongside a NEW Attempt only; empty/ignored when Attempt is empty.
//
// Parked is Task 8's explicit instruction for the controller_parked_at/
// controller_parked_reason projection.
type ControllerCommit struct {
	Attempt             AssessmentAttempt
	Assessment          model.Assessment
	MaterialFactHash    string
	AssessmentBasisHash string
	Coverage            []model.IncidentCoverage
	TriageDecisions     []TriageDecision
	Lifecycle           model.Lifecycle
	Attention           model.Attention
	RecoveryObservedAt  *time.Time
	GraceUntil          *time.Time
	TerminalAt          *time.Time
	TerminalReason      *model.TerminalReason
	NextAssessmentAt    time.Time
	ConsumedDueReasons  []model.DueReason
	RetryAt             *time.Time
	LastErrorClass      *string
	Parked              ParkedState
}

// ParkedState is CommitController's explicit instruction for the
// controller_parked_at/controller_parked_reason projection. The zero value
// (Touch=false) leaves both columns exactly as currently persisted — the
// common case for a cycle that neither newly parks nor newly clears a park
// (an ordinary success, or a still-parked cycle with nothing new to
// report). Touch=true with Reason=="" clears both to NULL (a fresh epoch —
// material input changed, or a dependency-recovery generation reset the
// attempt counter — or work simply succeeded). Touch=true with a non-empty
// Reason sets controller_parked_at=At and controller_parked_reason=Reason:
// this cycle is the one that newly parks the unchanged input.
type ParkedState struct {
	Touch  bool
	At     time.Time
	Reason string
}

// Parked reason codes — Task 8's own closed vocabulary for the
// controller_parked_reason column (migration 0015 declares it a free TEXT
// column with no CHECK-enforced enum; this package owns its closed meaning,
// the same pattern Task 6 used for TriageDecision's DecisionReason codes).
// Only ParkedReasonDependency is eligible for the dependency-recovery-
// generation re-arm (spec.md: "typed dependency recovery for dependency
// failures only"); the other three are permanent for the unchanged basis
// until a fresh material input arrives (spec.md: "Policy rejection,
// unsupported scope, and unsupported capability are permanent for the
// unchanged basis. Dependency recovery cannot re-arm them.").
const (
	// ParkedReasonMalformedExhausted means five controller attempts were
	// spent on an unchanged input and the model's response never validated
	// (malformed JSON/schema, even after one immediate correction).
	ParkedReasonMalformedExhausted = "malformed_exhausted"
	// ParkedReasonDependency means five controller attempts were spent on
	// an unchanged input and every one failed with a transport failure or
	// rate limit — a provider/dependency-class failure, the only class a
	// durable dependency-recovery generation may re-arm.
	ParkedReasonDependency = "dependency_exhausted"
	// ParkedReasonPolicyRejected means the model's proposal was
	// deterministically policy-rejected — permanent for this basis.
	ParkedReasonPolicyRejected = "policy_rejected"
	// ParkedReasonCapabilityRejected means the model's proposal cited an
	// unsupported capability or scope — permanent for this basis.
	ParkedReasonCapabilityRejected = "capability_rejected"
)

// ----------------------------------------------------------------------
// Task 8: ControllerStore, AssessmentClient, AuditSink, Controller,
// NewController, Reconcile — the fenced Situation controller. Reconcile
// orchestrates Task 4's Snapshot/hash/reason reduction, Task 5's Assessment
// derivation/validation/reuse, Task 6's DecideTriage, and this file's own
// Task 8 lifecycle timing extension (lifecycle.go) into the exact sequence
// spec.md's runtime-ownership diagram names, ending in one fenced
// CommitController call. It never imports internal/store.
// ----------------------------------------------------------------------

// ErrControllerAttemptsExhausted is returned by ControllerStore's
// BeginControllerAttempt when the claimed Situation's current unchanged
// input has already spent every durable controller attempt its retry epoch
// permits. Reconcile treats it not as a failure to propagate, but as the
// signal that this cycle must park (or stay parked) rather than dispatch
// any further L2 work. Declared here (not in internal/store) so both this
// package's Reconcile and internal/store's concrete implementation can
// reference the exact same sentinel without either importing the other.
var ErrControllerAttemptsExhausted = errors.New("situation: controller work attempts exhausted for this input")

// ControllerStore is the narrow persistence boundary Reconcile depends on.
// internal/store's *Store structurally satisfies it via wrapper methods
// that convert Plan 1's SituationClaim/model.Situation shapes into this
// package's transport-neutral Claim — see store/situation_controller.go.
type ControllerStore interface {
	LoadReconciliationInput(context.Context, Claim, time.Time) (SnapshotInput, error)
	AppendSituationFacts(context.Context, Claim, []model.Fact) error
	BeginControllerAttempt(context.Context, Claim, string, time.Time) (retryEpoch int, workAttempt int, err error)
	RecordAssessmentCall(context.Context, Claim, AssessmentCall) error
	AppendAssessmentOutcome(context.Context, AssessmentAttempt) error
	LastTrustworthyAssessment(context.Context, Claim) (*AuthoritativeAssessment, error)
	CommitController(context.Context, Claim, ControllerCommit) error
}

// AssessmentClient is the one-shot provider surface Reconcile's L2 dispatch
// uses — internal/llm/anthropic and internal/llm/openaicompat's CompleteOnce
// both satisfy it structurally. Reconcile never uses the hidden-retry
// Complete method: each dispatch permits at most one physical HTTP request.
type AssessmentClient interface {
	CompleteOnce(context.Context, string, llm.Prompt, []string) (llm.OneShotCompletion, error)
}

// AuditSink is the narrow audit-append surface Reconcile emits to —
// *audit.Auditor satisfies it structurally. May be nil (audit disabled).
type AuditSink interface {
	Append(context.Context, string, string, any) error
}

// Clock returns the current time. Production callers pass
// func() time.Time { return time.Now().UTC() }; tests pass a fixed or
// scripted clock.
type Clock func() time.Time

// RetryConfig bounds the controller's own transient-error retry range and
// jitter fraction — the transport-neutral counterpart of
// config.SituationsConfig.Retry.
type RetryConfig struct {
	Min, Max      time.Duration
	JitterPercent int
}

// ControllerConfig is internal/situation's own transport-neutral config
// shape for Controller — mirroring the Claim pattern (this file's own doc
// comment), it is populated from config.SituationsConfig's fields by
// whatever wires Controller up (Task 9). Zero-valued fields fall back to
// the documented defaults below, mirroring WorkerConfig/TriageWorkerConfig's
// own "zero means default" convention (input_worker.go, triage_worker.go).
//
// PollingIntervalSeconds has no config.SituationsConfig source today: no
// connector in this build ever writes a source_api-basis delivery, and
// config.SituationsConfig carries no live per-source poll interval field —
// see RecoveryGraceDuration's doc comment (lifecycle.go). It exists so
// RecoveryGraceDuration's polling-grace formula is real, total, and
// unit-tested ahead of a later plan's real polling connector; Task 9's
// wiring leaves it at its zero-value default (floor-clamped) until then.
//
// Cadence (fast/normal/slow durations) is deliberately NOT a field here:
// assessment.go's DeriveCadence/cadenceInterval hardcode their own fixed
// durations (cadenceFastInterval etc.) with no parameter to inject a
// config value into, so a ControllerConfig field for it would be inert
// decoration. See this task's report for the resulting fast-cadence
// discrepancy against config.SituationsConfig.Cadence.FastSeconds's own
// default (2m hardcoded vs. 60s configured) — a pre-existing Task 5
// mismatch this task does not silently patch.
type ControllerConfig struct {
	// MaxL2CallsPerAttempt bounds the durable dispatch slots one
	// work-bearing controller attempt may consume: the draft call plus at
	// most one immediate malformed-shape correction. Default 2
	// (config.SituationsConfig's own fixed, non-tunable ceiling).
	MaxL2CallsPerAttempt int

	// MaxWorkAttemptsPerInput bounds the durable controller attempts one
	// unchanged input may consume before semantic work parks. Default 5.
	MaxWorkAttemptsPerInput int

	// AttemptWall bounds one controller cycle's own wall-clock budget —
	// Reconcile derives a context.WithTimeout from it. Default 180s.
	AttemptWall time.Duration

	// WebhookRecoveryGrace is the fixed recovery-grace/observation-deadline
	// base for a webhook (or receipt_fallback) provenance delivery.
	// Default 120s.
	WebhookRecoveryGrace time.Duration

	// PollingIntervalSeconds is the assumed poll interval for a
	// source_api-provenance delivery's own recovery grace. Default 0
	// (floor-clamped) — see the type doc comment above.
	PollingIntervalSeconds int

	// Retry bounds the transient transport-failure/rate-limit retry
	// schedule. Default Min=5s, Max=300s, JitterPercent=20.
	Retry RetryConfig
}

const (
	defaultControllerMaxL2CallsPerAttempt    = 2
	defaultControllerMaxWorkAttemptsPerInput = 5
	defaultControllerAttemptWall             = 180 * time.Second
	defaultControllerWebhookRecoveryGrace    = 120 * time.Second
	defaultControllerRetryMin                = 5 * time.Second
	defaultControllerRetryMax                = 300 * time.Second
	defaultControllerRetryJitterPercent      = 20
)

func (c ControllerConfig) withDefaults() ControllerConfig {
	if c.MaxL2CallsPerAttempt <= 0 {
		c.MaxL2CallsPerAttempt = defaultControllerMaxL2CallsPerAttempt
	}
	if c.MaxWorkAttemptsPerInput <= 0 {
		c.MaxWorkAttemptsPerInput = defaultControllerMaxWorkAttemptsPerInput
	}
	if c.AttemptWall <= 0 {
		c.AttemptWall = defaultControllerAttemptWall
	}
	if c.WebhookRecoveryGrace <= 0 {
		c.WebhookRecoveryGrace = defaultControllerWebhookRecoveryGrace
	}
	if c.Retry.Min <= 0 {
		c.Retry.Min = defaultControllerRetryMin
	}
	if c.Retry.Max <= 0 {
		c.Retry.Max = defaultControllerRetryMax
	}
	if c.Retry.JitterPercent <= 0 {
		c.Retry.JitterPercent = defaultControllerRetryJitterPercent
	}
	return c
}

// Controller is the fenced Situation controller: one Reconcile call performs
// exactly one claimed Situation's reconciliation cycle end to end.
type Controller struct {
	store  ControllerStore
	client AssessmentClient
	cfg    ControllerConfig
	clock  Clock
	audit  AuditSink
	logger *slog.Logger
}

// NewController constructs a Controller. clock and logger may be nil
// (fall back to the UTC wall clock and slog.Default()); audit may be nil
// (audit disabled).
func NewController(store ControllerStore, client AssessmentClient, cfg ControllerConfig, clock Clock, auditSink AuditSink, logger *slog.Logger) *Controller {
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Controller{
		store:  store,
		client: client,
		cfg:    cfg.withDefaults(),
		clock:  clock,
		audit:  auditSink,
		logger: logger,
	}
}

func (c *Controller) auditAppend(ctx context.Context, actor, kind string, payload any) {
	if c.audit == nil {
		return
	}
	if err := c.audit.Append(ctx, actor, kind, payload); err != nil {
		c.logger.Warn("situation: controller audit append failed", "kind", kind, "err", err)
	}
}

// ----------------------------------------------------------------------
// Small local helpers.
// ----------------------------------------------------------------------

func timePtr(t time.Time) *time.Time                                 { return &t }
func stringPtrOf(s string) *string                                   { return &s }
func terminalReasonPtr(r model.TerminalReason) *model.TerminalReason { return &r }

func anyDeliveryResolved(deliveries []Delivery) bool {
	for _, d := range deliveries {
		if d.Status == model.DeliveryStatusResolved {
			return true
		}
	}
	return false
}

// proposalFromAssessment rebuilds the L2-authored subset of an existing
// Assessment as an AssessmentProposal — the same subset AssessmentProposal's
// own Go struct carries (Lifecycle/ActionContract/Cadence deliberately
// excluded), so an existing authoritative Assessment's semantic content can
// be re-run through DeriveAssessment to refresh only its controller-owned
// fields (a fresh ActionContract/Cadence/EvidenceQuality) without a new L2
// call or a new durable row.
func proposalFromAssessment(a model.Assessment) model.AssessmentProposal {
	return model.AssessmentProposal{
		SchemaVersion:    a.SchemaVersion,
		Persistence:      a.Persistence,
		Impact:           a.Impact,
		Novelty:          a.Novelty,
		Causality:        a.Causality,
		Attention:        a.Attention,
		SufficientReason: a.SufficientReason,
		Limitations:      a.Limitations,
	}
}

// retryBackoff derives a jittered backoff for workAttempt (1-based) from
// cfg: exponential from cfg.Min, capped at cfg.Max, with up to
// cfg.JitterPercent%% of the capped value added or subtracted at random.
// Never returns a negative or zero duration.
func retryBackoff(cfg RetryConfig, workAttempt int) time.Duration {
	if workAttempt < 1 {
		workAttempt = 1
	}
	shift := workAttempt - 1
	if shift > 30 { // guard against an absurd shift overflowing time.Duration
		shift = 30
	}
	d := cfg.Min * time.Duration(uint64(1)<<uint(shift)) //nolint:gosec // shift bounded to <=30 immediately above
	if d <= 0 || d > cfg.Max {
		d = cfg.Max
	}
	if cfg.JitterPercent > 0 {
		frac := float64(cfg.JitterPercent) / 100
		jitter := time.Duration(float64(d) * frac * (rand.Float64()*2 - 1))
		d += jitter
	}
	if d <= 0 {
		d = cfg.Min
	}
	return d
}

// earliestTriageDue returns the earliest NextAt among incidents' pending or
// backoff Triage rows, treating any Incident this cycle's decisions just
// moved from awaiting_decision to pending as due immediately (now) — the
// exact timing applyRequestFromAwaitingDecisionTx persists (next_at=now).
// Returns nil when no Incident carries pending/backoff Triage work.
func earliestTriageDue(incidents []IncidentState, decisions []TriageDecision, now time.Time) *time.Time {
	freshlyRequested := make(map[string]bool, len(decisions))
	for _, d := range decisions {
		if d.Decision == TriageDecisionRequest {
			freshlyRequested[d.IncidentID] = true
		}
	}

	var earliest *time.Time
	consider := func(t time.Time) {
		if earliest == nil || t.Before(*earliest) {
			earliest = timePtr(t)
		}
	}
	for _, inc := range incidents {
		if freshlyRequested[inc.ID] {
			consider(now)
			continue
		}
		switch inc.Triage.Phase {
		case "pending", "backoff":
			if inc.Triage.NextAt != nil {
				consider(*inc.Triage.NextAt)
			} else {
				consider(now)
			}
		}
	}
	return earliest
}

// aggregateTriagePhase reduces every member Incident's Triage phase (as it
// will read AFTER this cycle's decisions apply — a fresh request decision
// moves an awaiting_decision row to pending) to the single closed TriagePhase
// DeriveActionContract's priority list consumes: in_flight outranks
// awaiting/pending, which outranks backoff, which outranks "no AlertINT
// Triage work pending at all".
func aggregateTriagePhase(incidents []IncidentState, decisions []TriageDecision) TriagePhase {
	freshlyRequested := make(map[string]bool, len(decisions))
	for _, d := range decisions {
		if d.Decision == TriageDecisionRequest {
			freshlyRequested[d.IncidentID] = true
		}
	}

	hasInFlight, hasAwaiting, hasBackoff := false, false, false
	for _, inc := range incidents {
		phase := inc.Triage.Phase
		if freshlyRequested[inc.ID] {
			phase = "pending"
		}
		switch phase {
		case "in_flight":
			hasInFlight = true
		case "awaiting_decision", "pending":
			hasAwaiting = true
		case "backoff":
			hasBackoff = true
		}
	}
	switch {
	case hasInFlight:
		return TriagePhaseInFlight
	case hasAwaiting:
		return TriagePhaseAwaitingDecision
	case hasBackoff:
		return TriagePhaseBackoff
	default:
		return TriagePhaseNone
	}
}

// ----------------------------------------------------------------------
// Lifecycle resolution.
// ----------------------------------------------------------------------

// lifecycleResolution is resolveLifecycle's output: the Situation's new
// Lifecycle for this cycle plus the recovery/terminal fields
// ControllerCommit projects — a shape carrying exactly the columns
// migration 0014's situations CHECK constraint requires travel together
// per lifecycle value (see resolveLifecycle's own doc comment).
type lifecycleResolution struct {
	Lifecycle          model.Lifecycle
	RecoveryObservedAt *time.Time
	GraceUntil         *time.Time
	TerminalAt         *time.Time
	TerminalReason     *model.TerminalReason
}

// resolveLifecycle derives cur's next Lifecycle plus its recovery/terminal
// fields from durable local truth alone (spec.md "Lifecycle, Attention, and
// cadence"): source lifecycle is authoritative, so this reads only
// deliveries/symptoms already coherently loaded, never external state, and
// L2 has no vote. It uses AdvanceLifecycle for every genuine transition
// (never invents a transition AdvanceLifecycle's own table does not allow)
// and returns cur.Lifecycle unchanged with cur's own recovery/terminal
// fields carried through when nothing has changed this cycle.
//
// The four field-combinations returned exactly satisfy migration 0014's
// situations CHECK constraint: active carries all four nil; recovery_pending
// carries RecoveryObservedAt+GraceUntil non-nil, both terminal fields nil;
// recovered carries RecoveryObservedAt+GraceUntil+TerminalAt non-nil,
// TerminalReason nil; closed_unknown carries TerminalAt+TerminalReason
// non-nil (RecoveryObservedAt/GraceUntil unconstrained either way).
func (c *Controller) resolveLifecycle(cur model.Situation, in SnapshotInput, snap Snapshot, now time.Time) lifecycleResolution {
	firing := AnyFiring(snap.Symptoms)
	resolved := anyDeliveryResolved(in.Deliveries)
	deadline := ObservationDeadlineAt(cur.EffectiveStartedAt, snap.DurationClass)
	pastDeadline := !now.Before(deadline)

	switch cur.Lifecycle {
	case model.LifecycleActive:
		switch {
		case firing:
			return lifecycleResolution{Lifecycle: model.LifecycleActive}
		case pastDeadline:
			reason := ClosedUnknownReason(cur.EffectiveStartedAtBasis, resolved)
			lc, _ := AdvanceLifecycle(cur.Lifecycle, EventLifecycleUnobservable)
			return lifecycleResolution{Lifecycle: lc, TerminalAt: timePtr(now), TerminalReason: terminalReasonPtr(reason)}
		case len(snap.Symptoms) > 0:
			lc, _ := AdvanceLifecycle(cur.Lifecycle, EventRecoveryObserved)
			graceUntil := RecoveryGraceUntil(now, in.Deliveries, c.cfg.WebhookRecoveryGrace, c.cfg.PollingIntervalSeconds)
			return lifecycleResolution{Lifecycle: lc, RecoveryObservedAt: timePtr(now), GraceUntil: timePtr(graceUntil)}
		default:
			return lifecycleResolution{Lifecycle: model.LifecycleActive}
		}
	case model.LifecycleRecoveryPending:
		switch {
		case firing:
			lc, _ := AdvanceLifecycle(cur.Lifecycle, EventRefired)
			return lifecycleResolution{Lifecycle: lc}
		case cur.GraceUntil != nil && !now.Before(*cur.GraceUntil):
			lc, _ := AdvanceLifecycle(cur.Lifecycle, EventGraceExpired)
			return lifecycleResolution{Lifecycle: lc, RecoveryObservedAt: cur.RecoveryObservedAt, GraceUntil: cur.GraceUntil, TerminalAt: timePtr(now)}
		case pastDeadline:
			reason := ClosedUnknownReason(cur.EffectiveStartedAtBasis, resolved)
			lc, _ := AdvanceLifecycle(cur.Lifecycle, EventLifecycleUnobservable)
			return lifecycleResolution{Lifecycle: lc, RecoveryObservedAt: cur.RecoveryObservedAt, TerminalAt: timePtr(now), TerminalReason: terminalReasonPtr(reason)}
		default:
			return lifecycleResolution{Lifecycle: model.LifecycleRecoveryPending, RecoveryObservedAt: cur.RecoveryObservedAt, GraceUntil: cur.GraceUntil}
		}
	case model.LifecycleRecovered, model.LifecycleClosedUnknown: // terminal: never reopen.
		return lifecycleResolution{Lifecycle: cur.Lifecycle, RecoveryObservedAt: cur.RecoveryObservedAt, GraceUntil: cur.GraceUntil, TerminalAt: cur.TerminalAt, TerminalReason: cur.TerminalReason}
	default:
		// Unreachable: model.Lifecycle is a closed four-value enum and every
		// value is handled explicitly above. Defensive fallback only.
		return lifecycleResolution{Lifecycle: cur.Lifecycle, RecoveryObservedAt: cur.RecoveryObservedAt, GraceUntil: cur.GraceUntil, TerminalAt: cur.TerminalAt, TerminalReason: cur.TerminalReason}
	}
}

// ----------------------------------------------------------------------
// Attempt/outcome row construction.
// ----------------------------------------------------------------------

// synthesizeSequence derives a per-situation-unique sequence value from
// bounded local identity Reconcile already has, for the mid-cycle
// AppendAssessmentOutcome rows it appends directly (no store round-trip
// available to learn the true current MAX(sequence) — see this function's
// callers' doc comments and the Task 8 report for the full rationale).
// callNumber 0 marks a no-call derivation (reuse/deterministic/fallback).
// The generous per-field multiplier bands (inputVersion*1e6,
// retryEpoch*1e4, workAttempt*100) comfortably avoid collision for any
// realistic Situation lifetime (workAttempt<=5, callNumber<=2; retryEpoch —
// bounded by how many LLM-outage recovery generations one Situation lives
// through — would need to reach 100 before this formula's bands could ever
// overlap). CommitController computes its OWN authoritative row's sequence
// independently (a real MAX(sequence)+1 read inside its own transaction),
// so this formula's only job is giving AppendAssessmentOutcome's mid-cycle
// rejected/failed rows a value guaranteed not to collide with each other or
// with any row this or a later cycle appends.
func synthesizeSequence(inputVersion, retryEpoch, workAttempt, callNumber int) int {
	return inputVersion*1_000_000 + retryEpoch*10_000 + workAttempt*100 + callNumber
}

// buildAuthoritativeAttempt constructs the immutable, authoritative
// (status="authoritative") durable row for result — the shape Reconcile
// hands CommitController as ControllerCommit.Attempt. callID is nil for
// every non-model derivation (deterministic_controller, deterministic_
// fallback, revalidated_reuse — mirroring migration 0015's own CHECK that
// forbids call_id on any derivation but model_validated); retryEpoch/
// workAttempt are BeginControllerAttempt's own return values for a
// work-bearing cycle, or the harmless nominal (0,1) for a cycle that never
// called it (reuse, deterministic floor, or a preserve-existing/fallback
// commit built without a fresh work-bearing attempt). Sequence is left at
// its zero value: CommitController computes the real next sequence for
// this situation inside its own fenced transaction and ignores whatever
// value this function's result carries — see synthesizeSequence's doc
// comment.
func buildAuthoritativeAttempt(situationID string, result AssessmentResult, callID *string, retryEpoch, workAttempt int, now time.Time) AssessmentAttempt {
	started := model.ProviderRequestStartedFalse
	if callID != nil {
		started = model.ProviderRequestStartedTrue
	}
	assessmentJSON, err := json.Marshal(result.Assessment)
	if err != nil {
		// result.Assessment is always this package's own closed struct —
		// a marshal failure here is a programming-time invariant
		// violation, matching facts.go's mustMarshal panic convention.
		panic(fmt.Sprintf("situation: marshal authoritative assessment: %v", err))
	}
	return AssessmentAttempt{
		ID:                     uuid.NewString(),
		SituationID:            situationID,
		AssessmentBasisHash:    result.AssessmentBasisHash,
		CallID:                 callID,
		InputVersion:           result.InputVersion,
		RetryEpoch:             retryEpoch,
		WorkAttempt:            workAttempt,
		Derivation:             result.Derivation,
		Status:                 "authoritative",
		Validated:              assessmentJSON,
		ProviderRequestStarted: &started,
		ReusedFromAssessmentID: result.ReusedFromAssessmentID,
		CreatedAt:              now,
		CompletedAt:            now,
	}
}

// buildOutcomeAttempt constructs one immutable, non-authoritative
// (status="rejected"|"failed") outcome row for AppendAssessmentOutcome —
// the record of one dispatched call's rejected or failed result. vr is
// non-nil for a validated-but-rejected proposal (policy/capability/
// malformed-shape); transportErr is non-nil for a transport-layer failure
// (timeout, network error, rate limit, malformed transport/decode error).
// Exactly one of the two is meaningful, matching ClassifyL2Outcome's own
// contract. sequence must already be unique for this situation — Reconcile
// computes it via synthesizeSequence before calling this.
func buildOutcomeAttempt(situationID, callID string, inputVersion, retryEpoch, workAttempt, sequence int, vr *ValidationResult, transportErr error, started model.ProviderRequestStarted, now time.Time) AssessmentAttempt {
	status := "failed"
	var proposalJSON, validationErrorsJSON json.RawMessage
	if vr != nil {
		status = "rejected"
		if b, err := json.Marshal(vr.Proposal); err == nil {
			proposalJSON = b
		}
		if errs, err := json.Marshal(outcomeErrorCodes(vr.Errors)); err == nil {
			validationErrorsJSON = errs
		}
	} else if transportErr != nil {
		if errs, err := json.Marshal([]string{sanitizeTransportError(transportErr)}); err == nil {
			validationErrorsJSON = errs
		}
	}
	return AssessmentAttempt{
		ID:                     uuid.NewString(),
		SituationID:            situationID,
		CallID:                 stringPtrOf(callID),
		InputVersion:           inputVersion,
		RetryEpoch:             retryEpoch,
		WorkAttempt:            workAttempt,
		Sequence:               sequence,
		Status:                 status,
		Proposal:               proposalJSON,
		ValidationErrors:       validationErrorsJSON,
		ProviderRequestStarted: &started,
		CreatedAt:              now,
		CompletedAt:            now,
	}
}

// outcomeErrorCodes reduces issues to their bare Code strings — the bounded,
// grep-able content validation_errors_json carries (never raw prompts,
// provider bodies, or chain-of-thought).
func outcomeErrorCodes(issues []ValidationIssue) []string {
	out := make([]string, 0, len(issues))
	for _, i := range issues {
		out = append(out, i.Code)
	}
	return out
}

// sanitizeTransportError reduces a transport-layer error to a bounded,
// grep-able class string — never the raw error text, which may embed a
// provider response body, a URL with query parameters, or similar.
func sanitizeTransportError(err error) string {
	switch {
	case errors.Is(err, llm.ErrSchemaViolation):
		return "schema_violation"
	case errors.Is(err, llm.ErrResponseTruncated):
		return "response_truncated"
	case errors.Is(err, llm.ErrResponseInvalid):
		return "response_invalid"
	default:
		var retry *llm.RetryableError
		if errors.As(err, &retry) {
			return fmt.Sprintf("retryable_http_%d", retry.StatusCode)
		}
		var api *llm.APIError
		if errors.As(err, &api) {
			return fmt.Sprintf("api_http_%d", api.StatusCode)
		}
		return "transport_failure"
	}
}

// parkedReasonForOutcome maps a bounded, unrecoverable-for-this-cycle
// L2Outcome onto Task 8's own closed parked-reason vocabulary.
func parkedReasonForOutcome(outcome L2Outcome) string {
	switch outcome {
	case L2OutcomePolicyRejected:
		return ParkedReasonPolicyRejected
	case L2OutcomeCapabilityRejected:
		return ParkedReasonCapabilityRejected
	case L2OutcomeTransportFailure, L2OutcomeRateLimited:
		return ParkedReasonDependency
	case L2OutcomeMalformed:
		return ParkedReasonMalformedExhausted
	case L2OutcomeAccepted, L2OutcomeContradicted, L2OutcomeStaleBasis:
		// Unreachable given this function's only two call sites in
		// Reconcile: Accepted/Contradicted always short-circuit to
		// commitResult before this is ever called, and StaleBasis can never
		// arise from a call this SAME cycle's own dispatch loop dispatched
		// (its AssessmentCall.InputVersion is always snap.InputVersion — the
		// current input — by construction). Defensive fallback only.
		return ParkedReasonMalformedExhausted
	default:
		return ParkedReasonMalformedExhausted
	}
}

// fallbackOrPreserve builds the commit.Assessment/Attempt/Coverage triple
// for a cycle that ends WITHOUT a fresh accepted/contradicted L2 result:
// when in.CurrentAssessment already exists and is trustworthy (Task 5's own
// trustworthy — model-validated or deterministically complete, never a
// stale fallback), its existing semantic content is preserved and only its
// controller-owned fields (ActionContract/Cadence/EvidenceQuality) are
// refreshed against state — no new durable row (the returned Attempt is the
// zero value, so CommitController advances no current_assessment_id).
// Otherwise (no prior at all, or the prior itself is untrustworthy) a fresh
// DeterministicFallback becomes the new authoritative row — spec.md's
// "Deterministic fallback when L2 is unavailable and no trustworthy prior
// Assessment exists."
func (c *Controller) fallbackOrPreserve(situationID string, snap Snapshot, in SnapshotInput, state ControllerState, retryEpoch, workAttempt int, now time.Time) (model.Assessment, AssessmentAttempt, []model.IncidentCoverage) {
	if in.CurrentAssessment != nil {
		if _, ok := trustworthy(*in.CurrentAssessment); ok {
			proposal := proposalFromAssessment(in.CurrentAssessment.Assessment)
			result := DeriveAssessment(proposal, snap, in, state, in.CurrentAssessment.Derivation, in.CurrentAssessment.ReusedFromAssessmentID, now)
			return result.Assessment, AssessmentAttempt{}, nil
		}
	}
	result := DeterministicFallback(snap, in, state, now)
	attempt := buildAuthoritativeAttempt(situationID, result, nil, retryEpoch, workAttempt, now)
	return result.Assessment, attempt, result.Coverage
}

// buildControllerState composes the durable controller/Triage/lifecycle
// state DeriveActionContract/DeriveCadence need, from data already coherent
// as of this cycle's load plus what THIS cycle itself has decided so far
// (lc, the resolved lifecycle; triageDecisions, DecideTriage's own output).
// The semantic-retry fields (SemanticRetry/SemanticRetryAt) are left at
// their zero value here — the caller sets them once it has decided this
// cycle's own retry/park outcome, since that decision depends on state
// derived partly from Assessment content this same state feeds into
// (DeriveAssessment).
func (c *Controller) buildControllerState(snap Snapshot, in SnapshotInput, lc lifecycleResolution, triageDecisions []TriageDecision, now time.Time) ControllerState {
	var deadline *time.Time
	if !lc.Lifecycle.Terminal() {
		d := ObservationDeadlineAt(in.Situation.EffectiveStartedAt, snap.DurationClass)
		deadline = &d
	}
	return ControllerState{
		TriagePhase:                    aggregateTriagePhase(snap.Incidents, triageDecisions),
		TriageDueAt:                    earliestTriageDue(snap.Incidents, triageDecisions, now),
		RecoveryGraceUntil:             lc.GraceUntil,
		LifecycleObservationDeadlineAt: deadline,
	}
}

// commit calls c.store.CommitController and logs/audits the outcome —
// including a stale-claim failure, which Reconcile treats as a clean,
// expected race (spec.md: "the controller fails closed and the newer input
// remains due") rather than an unexpected error.
func (c *Controller) commit(ctx context.Context, claim Claim, commit ControllerCommit) error {
	err := c.store.CommitController(ctx, claim, commit)
	if err != nil {
		c.logger.Warn("situation: controller commit failed", "situation_id", claim.Situation.ID, "err", err)
		c.auditAppend(ctx, "situation.controller", "situation.controller.commit_failed", map[string]any{
			"situation_id": claim.Situation.ID, "error": err.Error(),
		})
		return err
	}
	c.auditAppend(ctx, "situation.controller", "situation.controller.committed", map[string]any{
		"situation_id":  claim.Situation.ID,
		"input_version": claim.Situation.InputVersion,
		"lifecycle":     string(commit.Lifecycle),
		"attention":     string(commit.Attention),
		"has_attempt":   commit.Attempt.ID != "",
	})
	return nil
}

// Reconcile performs one claimed Situation's full reconciliation cycle:
// coherent load; local fact derivation/append; Snapshot/hashes/reasons/
// floors; pure Triage decisions; deterministic/reuse check; only then
// consuming a work attempt if provider work is required; durable
// dispatch-slot record; one-shot provider I/O outside any transaction;
// validate/classify; one optional malformed correction using the second
// durable slot; one fenced final commit. See spec.md's own runtime-
// ownership diagram (plan.md Task 8) for the exact order this mirrors.
func (c *Controller) Reconcile(ctx context.Context, claim Claim) error {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.AttemptWall)
	defer cancel()
	now := c.clock()
	situationID := claim.Situation.ID

	// 1. Coherent load.
	in, err := c.store.LoadReconciliationInput(ctx, claim, now)
	if err != nil {
		return fmt.Errorf("situation: controller reconcile: load: %w", err)
	}

	// 2. Local fact derivation/append.
	facts := DeriveStoreFacts(in)
	if err := c.store.AppendSituationFacts(ctx, claim, facts); err != nil {
		return fmt.Errorf("situation: controller reconcile: append facts: %w", err)
	}

	// 3. Snapshot/hashes/reasons/floors.
	snap := BuildSnapshot(in)

	// Lifecycle timing (Task 8's own extension) resolves BEFORE Assessment
	// derivation: DeriveAssessment reads state.Lifecycle == snap.Lifecycle,
	// so a fresh transition this cycle discovers must already be reflected
	// on snap before any derivation path runs.
	lc := c.resolveLifecycle(in.Situation, in, snap, now)
	snap.Lifecycle = lc.Lifecycle

	// 4. Pure Triage decisions.
	triageDecisions := DecideTriage(snap, in, now)

	state := c.buildControllerState(snap, in, lc, triageDecisions, now)

	base := ControllerCommit{
		MaterialFactHash:    snap.MaterialFactHash,
		AssessmentBasisHash: snap.AssessmentBasisHash,
		TriageDecisions:     triageDecisions,
		Lifecycle:           lc.Lifecycle,
		RecoveryObservedAt:  lc.RecoveryObservedAt,
		GraceUntil:          lc.GraceUntil,
		TerminalAt:          lc.TerminalAt,
		TerminalReason:      lc.TerminalReason,
		ConsumedDueReasons:  claim.Situation.DueReasons,
	}

	// 5. Deterministic/reuse check — no L2 call, no work attempt consumed.
	if in.CurrentAssessment != nil {
		rr := RevalidateReuse(*in.CurrentAssessment, snap, in, state, now)
		if rr.Ok {
			return c.commitResult(ctx, claim, base, rr.Result, nil, 0, 0, now)
		}
	}
	if hasDeterministicFloor(snap.EligibleReasons) {
		result := DeterministicAssessment(snap, in, state, model.DerivationDeterministic, nil, now)
		return c.commitResult(ctx, claim, base, result, nil, 0, 0, now)
	}

	// 6. Work-bearing: consume a work attempt before any provider I/O.
	retryEpoch, workAttempt, err := c.store.BeginControllerAttempt(ctx, claim, snap.MaterialFactHash, now)
	if err != nil {
		if errors.Is(err, ErrControllerAttemptsExhausted) {
			// Already parked from a prior cycle on this unchanged input:
			// refresh the bounded projection only, touch no parked state.
			assessment, attempt, coverage := c.fallbackOrPreserveBlocked(situationID, snap, in, state, now)
			base.Assessment, base.Attempt, base.Coverage = assessment, attempt, coverage
			c.finalizeCheckpoint(&base, now)
			return c.commit(ctx, claim, base)
		}
		return fmt.Errorf("situation: controller reconcile: begin attempt: %w", err)
	}
	freshEpoch := workAttempt == 1

	proposal, vr, lastCallID, correctionUsed, transportErr := c.dispatchWorkBearing(ctx, claim, snap, retryEpoch, workAttempt, now)
	if proposal != nil {
		result := DeriveAssessment(*proposal, snap, in, state, model.DerivationModelValidated, nil, now)
		return c.commitResult(ctx, claim, base, result, &lastCallID, retryEpoch, workAttempt, now)
	}

	// No accepted/contradicted result: classify the last outcome (using
	// dispatchWorkBearing's own real correctionUsed, not an assumption) and
	// decide retry vs. permanent park vs. bounded park.
	policy := ClassifyL2Outcome(vr, transportErr, correctionUsed)

	switch {
	case !policy.DurableRetry:
		base.Parked = ParkedState{Touch: true, At: now, Reason: parkedReasonForOutcome(policy.Outcome)}
		base.RetryAt = nil
	case workAttempt >= c.cfg.MaxWorkAttemptsPerInput:
		base.Parked = ParkedState{Touch: true, At: now, Reason: parkedReasonForOutcome(policy.Outcome)}
		base.RetryAt = nil
	default:
		base.RetryAt = timePtr(now.Add(retryBackoff(c.cfg.Retry, workAttempt)))
		if freshEpoch {
			base.Parked = ParkedState{Touch: true, Reason: ""}
		}
	}
	base.LastErrorClass = stringPtrOf(string(policy.Outcome))
	state.SemanticRetry = SemanticRetryPhaseBlocked
	if base.RetryAt != nil {
		state.SemanticRetry = SemanticRetryPhaseDue
		state.SemanticRetryAt = base.RetryAt
	}

	assessment, attempt, coverage := c.fallbackOrPreserve(situationID, snap, in, state, retryEpoch, workAttempt, now)
	base.Assessment, base.Attempt, base.Coverage = assessment, attempt, coverage
	c.finalizeCheckpoint(&base, now)
	return c.commit(ctx, claim, base)
}

// commitResult finishes building base from a successful (no-L2-needed, or
// accepted/contradicted L2) AssessmentResult and commits it. It always
// clears any stale parked state — success (or a no-call derivation) proves
// the Situation is not stuck.
func (c *Controller) commitResult(ctx context.Context, claim Claim, base ControllerCommit, result AssessmentResult, callID *string, retryEpoch, workAttempt int, now time.Time) error {
	base.Attempt = buildAuthoritativeAttempt(claim.Situation.ID, result, callID, retryEpoch, workAttempt, now)
	base.Assessment = result.Assessment
	base.Coverage = result.Coverage
	base.Parked = ParkedState{Touch: true, Reason: ""}
	base.RetryAt = nil
	base.LastErrorClass = nil

	c.finalizeCheckpoint(&base, now)
	err := c.commit(ctx, claim, base)
	if err != nil && callID != nil {
		// spec.md: "A stale proposal/attempt is retained as `stale` but
		// changes no projection, Triage state, lifecycle, or outward
		// effect." A concurrent Situation input invalidated the claim
		// between dispatch and this fenced commit — the call's own budget
		// was already durably consumed (RecordAssessmentCall, before I/O),
		// so its now-discarded result is retained for provenance via the
		// same unfenced, non-authoritative AppendAssessmentOutcome path
		// every rejected/failed outcome already uses — never via
		// CommitController, which never partially commits (and, being
		// already fenced-rejected, could not accept it as authoritative
		// even if asked to).
		stale := buildStaleOutcome(base.Attempt, *callID)
		if appendErr := c.store.AppendAssessmentOutcome(ctx, stale); appendErr != nil {
			c.logger.Error("situation: controller: append stale outcome after commit failure",
				"situation_id", claim.Situation.ID, "call_id", *callID, "err", appendErr)
		}
	}
	return err
}

// buildStaleOutcome converts attempt — the would-have-been authoritative
// row commitResult built for CommitController — into a valid, immutable
// status="stale" outcome row for AppendAssessmentOutcome: authoritative-only
// fields (Derivation, ReusedFromAssessmentID) cleared, and a fresh
// per-situation-unique Sequence (reserved callNumber band 3, distinct from
// either real dispatch's own rejected/failed row at callNumber 1 or 2 for
// the identical input_version/retry_epoch/work_attempt tuple — see
// synthesizeSequence's doc comment).
func buildStaleOutcome(attempt AssessmentAttempt, callID string) AssessmentAttempt {
	attempt.CallID = stringPtrOf(callID)
	attempt.Status = "stale"
	attempt.Derivation = ""
	attempt.ReusedFromAssessmentID = nil
	attempt.Sequence = synthesizeSequence(attempt.InputVersion, attempt.RetryEpoch, attempt.WorkAttempt, 3)
	return attempt
}

// finalizeCheckpoint sets base.Attention/NextAssessmentAt from
// base.Assessment's own already-derived fields, and a defensive fallback
// next_assessment_at (now + lead) for the rare shape where ActionContract
// carries no NextUpdateAt at all despite a nonterminal lifecycle (should
// not happen given DeriveActionContract's own guarantees, but
// ControllerCommit.NextAssessmentAt has no NULL representation to fall
// back to).
func (c *Controller) finalizeCheckpoint(base *ControllerCommit, now time.Time) {
	base.Attention = base.Assessment.Attention
	if at := base.Assessment.ActionContract.NextUpdateAt; at != nil {
		base.NextAssessmentAt = *at
		return
	}
	if base.Lifecycle.Terminal() {
		base.NextAssessmentAt = now
		return
	}
	base.NextAssessmentAt = now.Add(time.Minute)
}

// fallbackOrPreserveBlocked is fallbackOrPreserve's counterpart for a cycle
// that discovers it is ALREADY parked (BeginControllerAttempt returned
// ErrControllerAttemptsExhausted) before attempting any work this cycle —
// it must still refresh the bounded projection (a fresh ActionContract
// timing promise), using SemanticRetryPhaseBlocked state, without touching
// controller_parked_at/reason (base.Parked stays the zero value/untouched
// by the caller).
func (c *Controller) fallbackOrPreserveBlocked(situationID string, snap Snapshot, in SnapshotInput, state ControllerState, now time.Time) (model.Assessment, AssessmentAttempt, []model.IncidentCoverage) {
	state.SemanticRetry = SemanticRetryPhaseBlocked
	return c.fallbackOrPreserve(situationID, snap, in, state, 0, 1, now)
}

// dispatchWorkBearing runs one work-bearing controller attempt's L2 dispatch
// loop: draft call, then — only for a malformed outcome, and only once —
// one immediate correction call, per the outcome matrix's "at most one
// immediate correction" rule. Each dispatch's durable call row commits
// (RecordAssessmentCall) before the physical HTTP request, so the call
// budget is consumed regardless of what the request itself returns; a
// rejected or failed outcome appends immediately (AppendAssessmentOutcome)
// before the loop continues or returns. It returns a non-nil proposal only
// on an accepted or contradicted response; otherwise proposal is nil and
// the caller classifies vr/transportErr via ClassifyL2Outcome to decide
// retry vs. park. lastCallID is always the most recent dispatch's call ID,
// for the caller to link a subsequent authoritative row to. correctionUsed
// reports whether this cycle actually spent its one immediate-correction
// call — false when the FIRST call itself was never eligible for one (a
// permanent rejection or a non-malformed transport failure), so the
// caller's own ClassifyL2Outcome re-classification of the final outcome
// passes the real value rather than assuming the correction was always
// spent.
func (c *Controller) dispatchWorkBearing(ctx context.Context, claim Claim, snap Snapshot, retryEpoch, workAttempt int, now time.Time) (proposal *model.AssessmentProposal, lastVR *ValidationResult, lastCallID string, correctionUsed bool, lastTransportErr error) {
	prompt, err := BuildAssessmentPrompt(snap)
	if err != nil {
		return nil, nil, "", false, fmt.Errorf("situation: build assessment prompt: %w", err)
	}

	for callNumber := 1; callNumber <= c.cfg.MaxL2CallsPerAttempt; callNumber++ {
		callID := uuid.NewString()
		call := AssessmentCall{
			ID: callID, SituationID: claim.Situation.ID, MaterialFactHash: snap.MaterialFactHash,
			InputVersion: snap.InputVersion, RetryEpoch: retryEpoch, WorkAttempt: workAttempt,
			CallNumber: callNumber, DispatchedAt: now,
		}
		if err := c.store.RecordAssessmentCall(ctx, claim, call); err != nil {
			return nil, nil, callID, correctionUsed, fmt.Errorf("situation: record assessment call: %w", err)
		}
		c.auditAppend(ctx, "situation.controller", "situation.controller.l2_dispatch", map[string]any{
			"situation_id": claim.Situation.ID, "call_id": callID, "call_number": callNumber,
			"retry_epoch": retryEpoch, "work_attempt": workAttempt,
		})

		oneShot, callErr := c.client.CompleteOnce(ctx, "", prompt, nil)
		// oneShot.RequestStarted is the AssessmentClient's own authoritative
		// classification (llm.ClassifyRequestStart, already applied inside
		// CompleteOnce) — trust it directly rather than reclassifying callErr
		// a second time here, which would silently diverge from whatever the
		// client itself determined.
		started := model.ProviderRequestStarted(oneShot.RequestStarted)

		var vr *ValidationResult
		var transportErr error
		if callErr != nil {
			transportErr = callErr
		} else {
			v := ValidateAssessmentProposal(oneShot.Raw, snap, call, now)
			vr = &v
		}
		lastVR, lastTransportErr, lastCallID = vr, transportErr, callID

		policy := ClassifyL2Outcome(vr, transportErr, correctionUsed)
		if policy.Outcome == L2OutcomeAccepted || policy.Outcome == L2OutcomeContradicted {
			p := vr.Proposal
			return &p, nil, callID, correctionUsed, nil
		}

		outcomeSequence := synthesizeSequence(snap.InputVersion, retryEpoch, workAttempt, callNumber)
		outcome := buildOutcomeAttempt(claim.Situation.ID, callID, snap.InputVersion, retryEpoch, workAttempt, outcomeSequence, vr, transportErr, started, now)
		if err := c.store.AppendAssessmentOutcome(ctx, outcome); err != nil {
			c.logger.Error("situation: controller: append assessment outcome failed", "situation_id", claim.Situation.ID, "call_id", callID, "err", err)
		}
		c.auditAppend(ctx, "situation.controller", "situation.controller.l2_outcome", map[string]any{
			"situation_id": claim.Situation.ID, "call_id": callID, "outcome": string(policy.Outcome),
		})

		if policy.ImmediateCorrection && !correctionUsed && callNumber < c.cfg.MaxL2CallsPerAttempt {
			correctionUsed = true
			continue
		}
		break
	}
	return nil, lastVR, lastCallID, correctionUsed, lastTransportErr
}
