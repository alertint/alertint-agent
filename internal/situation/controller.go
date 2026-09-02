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
// The field-combinations returned exactly satisfy migration 0014's two
// situations CHECK constraints: the per-lifecycle combination check (active
// carries all four nil; recovery_pending carries RecoveryObservedAt+
// GraceUntil non-nil, both terminal fields nil; recovered carries
// RecoveryObservedAt+GraceUntil+TerminalAt non-nil, TerminalReason nil;
// closed_unknown carries TerminalAt+TerminalReason non-nil, RecoveryObservedAt/
// GraceUntil unconstrained BY THAT check) AND the separate, UNCONDITIONAL
// recovery-field pairing check CHECK ((recovery_observed_at IS NULL) =
// (grace_until IS NULL)) — which applies regardless of lifecycle. This second
// check is why closed_unknown reached FROM recovery_pending (the
// pastDeadline branch below) must still carry GraceUntil alongside
// RecoveryObservedAt even though the per-lifecycle check alone would not
// have required it: cur.RecoveryObservedAt is already non-nil on entry to
// that branch (recovery_pending's own invariant), so GraceUntil must travel
// with it or the pairing check fails closed. closed_unknown reached FROM
// active (no recovery ever observed) correctly leaves both nil instead, since
// neither was ever set on this Situation.
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
			// Finding C2 fix: cur.RecoveryObservedAt is already non-nil here
			// (recovery_pending's own invariant) — migration 0014's recovery-
			// field pairing CHECK is unconditional, so GraceUntil must be
			// carried forward alongside it (cur.GraceUntil, the Situation's
			// existing recorded grace deadline — mirroring the sibling
			// grace-expiry branch above, which carries both fields for the
			// same reason) or this commit fails closed against a real schema.
			reason := ClosedUnknownReason(cur.EffectiveStartedAtBasis, resolved)
			lc, _ := AdvanceLifecycle(cur.Lifecycle, EventLifecycleUnobservable)
			return lifecycleResolution{Lifecycle: lc, RecoveryObservedAt: cur.RecoveryObservedAt, GraceUntil: cur.GraceUntil, TerminalAt: timePtr(now), TerminalReason: terminalReasonPtr(reason)}
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
// called it (revalidated reuse, or a blocked preserve-existing/fallback
// commit built without a fresh work-bearing attempt — commitBlocked). 0 is
// never valid here: migration 0015's CHECK requires work_attempt BETWEEN 1
// AND 5 (Finding C1). Sequence is left at
// its zero value: CommitController computes the real next sequence for
// this situation inside its own fenced transaction and ignores whatever
// value this function's result carries — see synthesizeSequence's doc
// comment.
//
// duration is the REAL measured wall-clock time the backing L2 call took
// (llm.OneShotCompletion.Latency, already computed by the provider client
// itself — see dispatchWorkBearing's own CompleteOnce call site), or zero
// for every derivation that never called out (callID == nil: deterministic/
// fallback/reuse). CreatedAt is backdated by duration from now (the point
// this row is being built, after the call — or immediately, for a no-call
// derivation — has already finished) so CompletedAt.Sub(CreatedAt), the
// value every "duration_ms" audit attribute actually reads, reflects a real
// measurement instead of always being exactly zero (Task 9 fix round,
// Finding #4: the prior version set CreatedAt=CompletedAt=now
// unconditionally, so the duration these attempts recorded — durably, and
// in every audit payload deriving it — could never be anything but zero).
func buildAuthoritativeAttempt(situationID string, result AssessmentResult, callID *string, retryEpoch, workAttempt int, duration time.Duration, now time.Time) AssessmentAttempt {
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
		CreatedAt:              now.Add(-duration),
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
// computes it via synthesizeSequence before calling this. duration is the
// REAL measured wall-clock time this call took (llm.OneShotCompletion.
// Latency) — every outcome row built here is, by construction, backed by an
// actual dispatched call (buildAuthoritativeAttempt's own doc comment
// explains the CreatedAt backdating this shares).
func buildOutcomeAttempt(situationID, callID string, inputVersion, retryEpoch, workAttempt, sequence int, vr *ValidationResult, transportErr error, started model.ProviderRequestStarted, duration time.Duration, now time.Time) AssessmentAttempt {
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
		CreatedAt:              now.Add(-duration),
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

// controllerParkBlocksDispatch reports whether p is a currently-active
// PERMANENT park (Finding I1: policy_rejected or capability_rejected — never
// malformed_exhausted or dependency_exhausted, which are attempt-budget-
// bounded and re-armable by dependency recovery respectively, and are
// already correctly blocked by BeginControllerAttempt's own 5-attempt
// ceiling once genuinely exhausted) recorded against currentMaterialFactHash
// — the SAME comparison BeginControllerAttempt itself makes against
// situations.current_material_fact_hash to decide "unchanged input." A park
// recorded against a DIFFERENT (older) basis no longer applies: the basis
// changed since parking, so the park has naturally lifted and this cycle
// must proceed normally, not stay parked forever.
func controllerParkBlocksDispatch(p ControllerParkedState, currentMaterialFactHash string) bool {
	if p.Reason != ParkedReasonPolicyRejected && p.Reason != ParkedReasonCapabilityRejected {
		return false
	}
	return p.MaterialFactHash != "" && p.MaterialFactHash == currentMaterialFactHash
}

// fallbackOrPreserve builds the commit.Assessment/Attempt/Coverage triple
// for a cycle that ends WITHOUT a fresh accepted/contradicted L2 result:
// when in.CurrentAssessment already exists and is trustworthy (Task 5's own
// trustworthy — model-validated or deterministically complete, never a
// stale fallback), its existing semantic content is REVALIDATED against the
// CURRENT snap — via the same rebindSufficientReason +
// validateProposalContent pattern RevalidateReuse uses to revalidate a
// prior against a newer input (assessment.go), not a Reconcile-invented
// second copy of that logic — and, when accepted, the (possibly floor-
// adjusted) proposal is preserved with only its controller-owned fields
// (ActionContract/Cadence/EvidenceQuality) refreshed against state — no new
// durable row (the returned Attempt is the zero value, so CommitController
// advances no current_assessment_id). RevalidateReuse itself cannot be
// called here directly: its own AssessmentBasisHash-equality gate exists for
// a DIFFERENT purpose (deciding whether a whole cycle can skip work
// entirely) and would always reject preserve's call site, since preserve is
// reached only when RevalidateReuse has already failed (or never applied)
// for THIS cycle's changed basis.
//
// Revalidation is essential, not optional: a Situation's deterministic
// urgent floor (critical_anchor) can become newly eligible in the very
// cycle L2 fails, and a stale prior Assessment's own Attention may no
// longer reflect it (or, symmetrically, may still claim an urgent Attention
// whose grounding floor has since lifted) — see validateProposalContent's
// floor-adjustment/urgent_without_floor rules. When revalidation rejects
// the preserved proposal (the floor grounding a stale urgent Attention is
// gone, or any other current-basis policy check now fails it), preserving
// it unchanged would commit an ungrounded Assessment, so this falls through
// to the same DeterministicFallback path used when no trustworthy prior
// exists at all — spec.md's "Deterministic fallback when L2 is unavailable
// and no trustworthy prior Assessment exists" now also covers "...or the
// prior's semantic content is no longer valid against the current basis."
func (c *Controller) fallbackOrPreserve(situationID string, snap Snapshot, in SnapshotInput, state ControllerState, retryEpoch, workAttempt int, now time.Time) (model.Assessment, AssessmentAttempt, []model.IncidentCoverage) {
	if in.CurrentAssessment != nil {
		if _, ok := trustworthy(*in.CurrentAssessment); ok {
			proposal := proposalFromAssessment(in.CurrentAssessment.Assessment)
			if rebound, ok := rebindSufficientReason(proposal.SufficientReason, snap.EligibleReasons); ok {
				proposal.SufficientReason = rebound
				revalidated := validateProposalContent(proposal, snap)
				if revalidated.Outcome.accepted() {
					result := DeriveAssessment(revalidated.Proposal, snap, in, state, in.CurrentAssessment.Derivation, in.CurrentAssessment.ReusedFromAssessmentID, now)
					return result.Assessment, AssessmentAttempt{}, nil
				}
			}
		}
	}
	result := DeterministicFallback(snap, in, state, now)
	// duration=0: this derivation never calls out (callID is always nil
	// here), matching buildAuthoritativeAttempt's own "zero for every
	// derivation that never called out" contract.
	attempt := buildAuthoritativeAttempt(situationID, result, nil, retryEpoch, workAttempt, 0, now)
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
// remains due") rather than an unexpected error. commit_failed is a
// supplementary diagnostic event beyond spec.md's own named 13-event
// taxonomy ("Audit events cover AT LEAST" that list) — kept because a
// commit failure (most commonly a stale-claim race) is operationally
// worth its own audit trail distinct from any of the 13 named events, none
// of which name a whole-commit failure.
func (c *Controller) commit(ctx context.Context, claim Claim, commit ControllerCommit) error {
	err := c.store.CommitController(ctx, claim, commit)
	if err != nil {
		c.logger.Warn("situation: controller commit failed", "situation_id", claim.Situation.ID, "err", err)
		c.auditAppend(ctx, "situation.controller", "situation.controller.commit_failed", map[string]any{
			"situation_id": claim.Situation.ID, "error": err.Error(),
		})
		return err
	}
	c.auditCommitSuccess(ctx, claim, commit)
	return nil
}

// assessmentAuditKind maps a NEW authoritative attempt's own Derivation onto
// spec.md's exact named audit event for that outcome. Only a genuinely fresh
// authoritative row (commit.Attempt.ID != "") ever reaches this — a cycle
// that only refreshes the bounded current projection (commit.Attempt is the
// zero value: a still-parked cycle, or a preserve/fallback path whose result
// was preserved unchanged) emits none of these three, matching spec.md's own
// "reconciliation churn within an unchanged basis does not spend a model
// call" — and correspondingly does not spend an audit event announcing a new
// judgment that never happened. model_validated (a fresh L2-accepted
// proposal) and deterministic_controller (a non-L2 derivation that is still
// a genuine new judgment, e.g. an urgent-floor Situation's first
// Assessment) both count as "authoritative" for audit purposes: the
// distinguishing signal spec.md's taxonomy cares about is fallback
// (L2 failed/blocked, no trustworthy prior) versus reused (an unchanged
// prior's content carried forward) versus everything else that is a genuine
// fresh judgment.
func assessmentAuditKind(d model.AssessmentDerivation) (string, bool) {
	switch d {
	case model.DerivationModelValidated, model.DerivationDeterministic:
		return "situation.assessment_authoritative", true
	case model.DerivationDeterministicFallback:
		return "situation.assessment_fallback", true
	case model.DerivationRevalidatedReuse:
		return "situation.assessment_reused", true
	default:
		return "", false
	}
}

// auditCommitSuccess emits spec.md's own named audit events for a
// successfully committed cycle: at most one of situation.assessment_
// authoritative/reused/fallback (see assessmentAuditKind), plus one
// situation.triage_requested or situation.triage_skipped per Triage
// decision this same commit shares (spec.md: "Triage request/skip decisions
// produced by the claimed snapshot" commit together with the Assessment).
// Every payload carries only bounded, stable identity/digest attributes —
// Situation/Incident ID, input version, attempt ID, and the material/basis/
// membership/Incident-input digests spec.md's OTel/log-attribute
// requirement names — never a proposal, prompt, or provider body.
func (c *Controller) auditCommitSuccess(ctx context.Context, claim Claim, commit ControllerCommit) {
	situationID := claim.Situation.ID
	if commit.Attempt.ID != "" {
		if kind, ok := assessmentAuditKind(commit.Attempt.Derivation); ok {
			c.auditAppend(ctx, "situation.controller", kind, map[string]any{
				"situation_id":             situationID,
				"attempt_id":               commit.Attempt.ID,
				"input_version":            commit.Attempt.InputVersion,
				"derivation":               string(commit.Attempt.Derivation),
				"material_fact_hash":       commit.MaterialFactHash,
				"assessment_basis_hash":    commit.AssessmentBasisHash,
				"provider_request_started": string(*commit.Attempt.ProviderRequestStarted),
				"duration_ms":              commit.Attempt.CompletedAt.Sub(commit.Attempt.CreatedAt).Milliseconds(),
			})
		}
	}
	for _, d := range commit.TriageDecisions {
		kind := "situation.triage_skipped"
		if d.Decision == TriageDecisionRequest {
			kind = "situation.triage_requested"
		}
		c.auditAppend(ctx, "situation.controller", kind, map[string]any{
			"situation_id":          situationID,
			"incident_id":           d.IncidentID,
			"input_version":         d.SituationInputVersion,
			"decision_reason":       d.DecisionReason,
			"material_fact_hash":    d.MaterialFactHash,
			"membership_digest":     d.MembershipDigest,
			"incident_input_digest": d.IncidentInputDigest,
		})
	}
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
	// Finding C1 fix: workAttempt=1 (not 0) — buildAuthoritativeAttempt's own
	// doc comment names this the nominal value for a non-work-bearing commit;
	// migration 0015's CHECK requires work_attempt BETWEEN 1 AND 5, so 0
	// fails closed against a real schema (this cycle never calls
	// BeginControllerAttempt at all, so no real budget-counter value exists
	// to report — 1 is a harmless placeholder satisfying the schema's
	// identity/CHECK requirement, not a claim of real attempt consumption).
	if in.CurrentAssessment != nil {
		rr := RevalidateReuse(*in.CurrentAssessment, snap, in, state, now)
		if rr.Ok {
			// duration=0: a reuse commit never calls out (callID is always
			// nil here).
			return c.commitResult(ctx, claim, base, rr.Result, nil, 0, 1, 0, now)
		}
	}

	// Finding I1 fix: a policy/capability park recorded against the CURRENT
	// basis is permanent (spec.md: "Policy rejection, unsupported scope, and
	// unsupported capability are permanent for the unchanged basis.
	// Dependency recovery cannot re-arm them.") — unlike malformed_exhausted/
	// dependency_exhausted, which only park after genuinely spending all 5
	// BeginControllerAttempt-budgeted attempts (so BeginControllerAttempt's
	// own ceiling already blocks further dispatch on its own), a policy/
	// capability rejection parks after just ONE attempt. Without this check,
	// BeginControllerAttempt would happily keep succeeding for attempts 2-5
	// on later cycles (it only tracks the attempt COUNT vs. the 5 ceiling, not
	// "already permanently parked"), dispatching L2 again each time — costing
	// up to 5 attempts/10 L2 calls for what spec.md mandates should cost
	// exactly one. Skip work-bearing dispatch entirely (no
	// BeginControllerAttempt call, no L2 call) while parked for one of these
	// two reasons against the SAME basis; Triage decisions and the reuse/
	// bounded-projection refresh above/below still proceed normally — parking
	// only suppresses NEW semantic L2 work. If the basis has since changed,
	// controllerParkBlocksDispatch returns false and this cycle proceeds
	// exactly as if not parked, naturally lifting the park.
	if controllerParkBlocksDispatch(in.ControllerParked, snap.MaterialFactHash) {
		return c.commitBlocked(ctx, claim, base, situationID, snap, in, state, now)
	}

	// Finding I3 ruling: a deterministic urgent floor (critical_anchor) does
	// NOT short-circuit L2 dispatch. An earlier version of this cycle
	// committed DeterministicAssessment immediately and returned whenever
	// hasDeterministicFloor(snap.EligibleReasons) was true — which, combined
	// with RevalidateReuse's own trustworthiness rule (deterministic_
	// controller/deterministic_fallback both pass ValidateShape and, for
	// deterministic_controller specifically, are NOT excluded by trustworthy()
	// the way deterministic_fallback is), meant a floor Situation's
	// conservative-default semantic fields (persistence=unknown,
	// impact=none_observed, novelty=insufficient_history, causality=unknown)
	// got REUSED forever afterward — the highest-severity Situations
	// (critical_anchor) never received a real semantic L2 judgment on any
	// future cycle. That contradicts Task 5's own DeterministicAssessment doc
	// comment (which scopes the deterministic_controller derivation to "the
	// 'L2 failed' case" and a later terminal-closure Assessment, not "the
	// primary path for critical Situations"), spec.md's "A deterministic
	// urgent-floor Assessment is authoritative for its deterministic fields,
	// but its unknown semantic fields cannot justify skipping Acute Triage
	// when focused analysis still has decision value" (the floor's presence
	// does not mean semantic judgment is no longer needed), and spec.md's own
	// fallback-section example — "a reachable critical_anchor candidate still
	// produces deterministic urgent Attention... DURING THE SAME L2 FAILURE"
	// — which describes the floor applying ALONGSIDE an L2 failure (L2 was
	// still attempted), not replacing the attempt.
	//
	// The floor's Attention-raising is Task 5's own DeriveAssessment/
	// validateProposalContent adjustment mechanism, correctly wired into
	// EVERY remaining path without any Reconcile-level special case:
	// validateProposalContent forces Attention to urgent (recorded as a safe
	// "adjustment", never a rejection) whenever the floor is active,
	// regardless of what the model itself proposed, for the fresh
	// model-validated path (ValidateAssessmentProposal), reuse's own
	// revalidation step (RevalidateReuse, when the basis is UNCHANGED), and
	// fallbackOrPreserve's own preserve branch (revalidating a trustworthy
	// prior's content against the CURRENT, possibly CHANGED, basis via that
	// same validateProposalContent call — a fix to a gap this comment
	// originally left open: an earlier version of this fix preserved the
	// prior's content unrevalidated, so a floor that became newly eligible
	// in the very cycle L2 failed could commit a stale pre-floor Attention);
	// DeterministicAssessment applies the identical floor check directly
	// when it IS reached — via DeterministicFallback, i.e. when this cycle's
	// own work-bearing L2 dispatch below actually failed/was blocked AND no
	// trustworthy prior Assessment exists, or the prior one revalidation
	// rejects (fallbackOrPreserve). So a floor Situation with no prior
	// Assessment still goes through work-bearing dispatch just like any
	// other Situation: on success it becomes model_validated with Attention
	// forced urgent; on failure it falls back to DeterministicFallback,
	// which ALSO forces Attention to urgent via the same floor check. And a
	// floor Situation that DOES already carry a trustworthy prior gets the
	// identical guarantee through a different one of these same paths: an
	// unchanged basis reuses it (RevalidateReuse) with Attention forced
	// urgent if the floor is active; a changed basis with L2 down/blocked
	// preserves it (fallbackOrPreserve) with the SAME forcing, or falls
	// through to DeterministicFallback if revalidation itself rejects it
	// (e.g. a SufficientReason that no longer grounds anything). Every one
	// of these paths — fresh, reused, preserved, or fallback — therefore
	// already carries Attention=urgent whenever the floor is active this
	// cycle, satisfying "the floor's only special effect is guaranteeing
	// Attention is raised to urgent (never lowered, and never invented once
	// its own grounding is gone)" without ever needing to skip L2 to get
	// there.

	// 6. Work-bearing: consume a work attempt before any provider I/O.
	retryEpoch, workAttempt, err := c.store.BeginControllerAttempt(ctx, claim, snap.MaterialFactHash, now)
	if err != nil {
		if errors.Is(err, ErrControllerAttemptsExhausted) {
			// Already parked from a prior cycle on this unchanged input:
			// refresh the bounded projection only, touch no parked state.
			return c.commitBlocked(ctx, claim, base, situationID, snap, in, state, now)
		}
		return fmt.Errorf("situation: controller reconcile: begin attempt: %w", err)
	}
	freshEpoch := workAttempt == 1

	proposal, vr, lastCallID, lastDuration, correctionUsed, transportErr := c.dispatchWorkBearing(ctx, claim, snap, retryEpoch, workAttempt, now)
	if proposal != nil {
		result := DeriveAssessment(*proposal, snap, in, state, model.DerivationModelValidated, nil, now)
		return c.commitResult(ctx, claim, base, result, &lastCallID, retryEpoch, workAttempt, lastDuration, now)
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
// the Situation is not stuck. duration is the real measured L2 call latency
// when callID is non-nil (dispatchWorkBearing's own oneShot.Latency), or 0
// for a no-call commit (reuse) — threaded straight through to
// buildAuthoritativeAttempt.
func (c *Controller) commitResult(ctx context.Context, claim Claim, base ControllerCommit, result AssessmentResult, callID *string, retryEpoch, workAttempt int, duration time.Duration, now time.Time) error {
	base.Attempt = buildAuthoritativeAttempt(claim.Situation.ID, result, callID, retryEpoch, workAttempt, duration, now)
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
		// A late/stale completion race — a real L2 call already succeeded
		// (RequestStarted proved it), but a concurrent newer input
		// invalidated this cycle's own claim before the fenced commit — is
		// audited as stale, never as a provider failure: the model work
		// itself did not fail, it was correctly discarded (spec.md: "A
		// stale proposal/attempt is retained as `stale` but changes no
		// projection, Triage state, lifecycle, or outward effect"). Fired
		// regardless of whether the durable stale-outcome append above
		// itself succeeded — audit is best-effort and never gates or
		// repeats the already-completed model work.
		c.auditAppend(ctx, "situation.controller", "situation.assessment_stale", map[string]any{
			"situation_id": claim.Situation.ID, "call_id": *callID, "attempt_id": stale.ID,
			"input_version":            stale.InputVersion,
			"provider_request_started": string(*stale.ProviderRequestStarted),
			"duration_ms":              stale.CompletedAt.Sub(stale.CreatedAt).Milliseconds(),
		})
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

// commitBlocked commits the bounded projection refresh for a cycle that must
// not dispatch further L2 work this cycle without ever calling
// BeginControllerAttempt — either because a prior cycle already spent the
// unchanged input's full five-attempt budget (BeginControllerAttempt itself
// reports ErrControllerAttemptsExhausted), or because a still-active policy/
// capability park already covers the current basis (Finding I1,
// controllerParkBlocksDispatch). Neither case touches controller_parked_at/
// reason (base.Parked stays the zero value/untouched — whatever was
// persisted stands).
func (c *Controller) commitBlocked(ctx context.Context, claim Claim, base ControllerCommit, situationID string, snap Snapshot, in SnapshotInput, state ControllerState, now time.Time) error {
	assessment, attempt, coverage := c.fallbackOrPreserveBlocked(situationID, snap, in, state, now)
	base.Assessment, base.Attempt, base.Coverage = assessment, attempt, coverage
	c.finalizeCheckpoint(&base, now)
	return c.commit(ctx, claim, base)
}

// fallbackOrPreserveBlocked is fallbackOrPreserve's counterpart for a cycle
// that discovers it must not attempt any work this cycle before ever calling
// BeginControllerAttempt (see commitBlocked's own doc comment for the two
// cases) — it must still refresh the bounded projection (a fresh
// ActionContract timing promise), using SemanticRetryPhaseBlocked state.
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
// spent. lastDuration is the most recent dispatch's own real measured
// latency (llm.OneShotCompletion.Latency) — for the caller to thread into
// whichever attempt row it ends up building from this cycle's outcome
// (Task 9 fix round, Finding #4).
func (c *Controller) dispatchWorkBearing(ctx context.Context, claim Claim, snap Snapshot, retryEpoch, workAttempt int, now time.Time) (proposal *model.AssessmentProposal, lastVR *ValidationResult, lastCallID string, lastDuration time.Duration, correctionUsed bool, lastTransportErr error) {
	prompt, err := BuildAssessmentPrompt(snap)
	if err != nil {
		return nil, nil, "", 0, false, fmt.Errorf("situation: build assessment prompt: %w", err)
	}

	for callNumber := 1; callNumber <= c.cfg.MaxL2CallsPerAttempt; callNumber++ {
		callID := uuid.NewString()
		call := AssessmentCall{
			ID: callID, SituationID: claim.Situation.ID, MaterialFactHash: snap.MaterialFactHash,
			InputVersion: snap.InputVersion, RetryEpoch: retryEpoch, WorkAttempt: workAttempt,
			CallNumber: callNumber, DispatchedAt: now,
		}
		if err := c.store.RecordAssessmentCall(ctx, claim, call); err != nil {
			return nil, nil, callID, 0, correctionUsed, fmt.Errorf("situation: record assessment call: %w", err)
		}
		c.auditAppend(ctx, "situation.controller", "situation.assessment_call_dispatched", map[string]any{
			"situation_id": claim.Situation.ID, "call_id": callID, "call_number": callNumber,
			"input_version": snap.InputVersion, "retry_epoch": retryEpoch, "work_attempt": workAttempt,
			"material_fact_hash": snap.MaterialFactHash,
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
		lastVR, lastTransportErr, lastCallID, lastDuration = vr, transportErr, callID, oneShot.Latency

		policy := ClassifyL2Outcome(vr, transportErr, correctionUsed)
		if policy.Outcome == L2OutcomeAccepted || policy.Outcome == L2OutcomeContradicted {
			p := vr.Proposal
			return &p, nil, callID, oneShot.Latency, correctionUsed, nil
		}

		outcomeSequence := synthesizeSequence(snap.InputVersion, retryEpoch, workAttempt, callNumber)
		outcome := buildOutcomeAttempt(claim.Situation.ID, callID, snap.InputVersion, retryEpoch, workAttempt, outcomeSequence, vr, transportErr, started, oneShot.Latency, now)
		if err := c.store.AppendAssessmentOutcome(ctx, outcome); err != nil {
			c.logger.Error("situation: controller: append assessment outcome failed", "situation_id", claim.Situation.ID, "call_id", callID, "err", err)
		}
		// outcome.Status is buildOutcomeAttempt's own closed classification:
		// "rejected" for a validated-but-rejected proposal (policy/capability/
		// malformed-shape/stale-basis), "failed" for a transport-layer
		// failure (timeout/network/rate-limit) — the exact split spec.md's
		// named situation.assessment_rejected/situation.assessment_failed
		// events distinguish.
		kind := "situation.assessment_rejected"
		if outcome.Status == "failed" {
			kind = "situation.assessment_failed"
		}
		c.auditAppend(ctx, "situation.controller", kind, map[string]any{
			"situation_id": claim.Situation.ID, "call_id": callID, "outcome": string(policy.Outcome),
			"input_version":            snap.InputVersion,
			"retry_epoch":              retryEpoch,
			"work_attempt":             workAttempt,
			"provider_request_started": string(started),
			"duration_ms":              outcome.CompletedAt.Sub(outcome.CreatedAt).Milliseconds(),
		})

		if policy.ImmediateCorrection && !correctionUsed && callNumber < c.cfg.MaxL2CallsPerAttempt {
			correctionUsed = true
			continue
		}
		break
	}
	return nil, lastVR, lastCallID, lastDuration, correctionUsed, lastTransportErr
}
