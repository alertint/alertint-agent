// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/observation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// Claim carries the exact fenced aggregate state Reconcile was handed —
// mirroring store.SituationClaim without importing internal/store (which
// already imports this package). The concrete adapter that fences a real
// SQLite transaction against this Claim lives outside this package (Task
// 13 wiring).
type Claim struct {
	Situation  model.Situation
	ClaimOwner string
	ClaimToken int64
}

// AssessmentActor is the closed origin of one attempt.
type AssessmentActor string

const (
	AssessmentActorDeterministic AssessmentActor = "deterministic_controller"
	AssessmentActorLLM           AssessmentActor = "llm"
)

// AssessmentAttemptStatus is the closed attempt outcome.
type AssessmentAttemptStatus string

const (
	AttemptStatusProposed      AssessmentAttemptStatus = "proposed"
	AttemptStatusAuthoritative AssessmentAttemptStatus = "authoritative"
	AttemptStatusRejected      AssessmentAttemptStatus = "rejected"
	AttemptStatusFailed        AssessmentAttemptStatus = "failed"
	AttemptStatusStale         AssessmentAttemptStatus = "stale"
)

// AssessmentAttempt is the durable attempt record Controller appends. It
// mirrors store.AssessmentAttempt closely so a thin adapter is mechanical.
type AssessmentAttempt struct {
	ID                    string
	Sequence              int
	InputVersion          int
	FactHash              string
	Actor                 AssessmentActor
	Status                AssessmentAttemptStatus
	TriggerReasons        []string
	SnapshotDigest        string
	Proposal              json.RawMessage
	Validated             json.RawMessage
	ValidationAdjustments []model.ValidationAdjustment
	ModelUsage            json.RawMessage
	CreatedAt             time.Time
	CompletedAt           *time.Time
}

// AnalysisState mirrors incident_analysis_state: the explicit B+ gate
// persisted per Incident. An omitted finding is never ambiguous.
type AnalysisState struct {
	IncidentID      string
	Status          L1Status
	DecisionReason  string
	LatestAttemptID string
	UpdatedAt       time.Time
}

// ErrStaleInput signals the claimed input version no longer matches current
// durable state. It is not an ordinary failure: the caller stores the
// attempt as stale and reschedules the current input rather than
// propagating an error.
var ErrStaleInput = errors.New("situation: claimed input version is stale")

// Store is the narrow durable boundary Controller.Reconcile needs. It is
// deliberately situation-owned rather than *store.Store: internal/store
// already imports internal/situation, so this package cannot import it
// back. A real adapter over the existing store.Store persistence
// (situations.go, situation_assessments.go) lives in cmd/alertint wiring.
type Store interface {
	// ClaimedSituation reads the aggregate this worker already holds a lease
	// on (claimed by a prior ClaimDueSituations call); Reconcile does not
	// claim work itself.
	ClaimedSituation(ctx context.Context, situationID string) (Claim, error)
	// LoadReconciliationInput assembles everything BuildSnapshot needs except
	// semantic-profile heads (ProfileReader's job) and the L1 finding (the B+
	// gate's own async result, not yet durable evidence when this loads). It
	// also returns the Situation's primary Incident ID for the B+ gate and L1
	// dispatch.
	LoadReconciliationInput(ctx context.Context, claim Claim) (SnapshotInput, string, error)
	AnalysisState(ctx context.Context, incidentID string) (AnalysisState, error)
	SetAnalysisState(ctx context.Context, state AnalysisState) error
	// LastTrustedAssessment returns the covering decision for the B+ gate and
	// the full prior Assessment for the L2 prompt (nil on a Situation's first
	// attempt).
	LastTrustedAssessment(ctx context.Context, claim Claim) (TrustedAssessment, *model.Assessment, error)
	AppendAssessmentAttempt(ctx context.Context, claim Claim, attempt AssessmentAttempt) error
	// CommitAuthoritative appends the authoritative attempt and applies the
	// transition atomically (from the caller's perspective); it returns
	// ErrStaleInput when claim.Situation.InputVersion no longer matches
	// current durable state.
	CommitAuthoritative(ctx context.Context, claim Claim, attempt AssessmentAttempt, tr model.Transition) error
	// Reschedule moves next_assessment_at to at without mutating lifecycle or
	// Attention — used after a stale commit reschedules the current input.
	Reschedule(ctx context.Context, claim Claim, at time.Time) error
	// Park preserves the still-safe prior Assessment and marks work parked
	// for an unchanged input that exhausted its attempt budget; it never
	// derives terminality from exhaustion.
	Park(ctx context.Context, claim Claim, retryAt time.Time, decisionReason string) error
	// MarkDue unions one due reason and pulls next_assessment_at earlier —
	// used by the async L1 dispatch to make the Situation reconsider its
	// result without depending on any in-memory channel surviving a crash.
	MarkDue(ctx context.Context, situationID string, reason model.DueReason, at time.Time) error
}

// ProfileReader resolves the current advisory L0 profile head for one source
// signature. internal/semanticprofile imports internal/store (which imports
// this package), so this package cannot import it back; the interface is
// expressed in this package's own ProfileHead type instead.
type ProfileReader interface {
	ProfileHead(ctx context.Context, signature string) (ProfileHead, bool, error)
}

// Config holds Controller tunables. Zero values are normalized to the spec
// defaults by NewController.
type Config struct {
	MaxL2Calls          int
	MaxAttemptsPerInput int
	FastCadence         time.Duration
	NormalCadence       time.Duration
	SlowCadence         time.Duration
	ParkRetryAfter      time.Duration
	AllowedCapabilities []string
}

func (c Config) normalized() Config {
	if c.MaxL2Calls <= 0 {
		c.MaxL2Calls = 2
	}
	if c.MaxAttemptsPerInput <= 0 {
		c.MaxAttemptsPerInput = 5
	}
	if c.FastCadence <= 0 {
		c.FastCadence = 60 * time.Second
	}
	if c.NormalCadence <= 0 {
		c.NormalCadence = 5 * time.Minute
	}
	if c.SlowCadence <= 0 {
		c.SlowCadence = 15 * time.Minute
	}
	if c.ParkRetryAfter <= 0 {
		c.ParkRetryAfter = 24 * time.Hour
	}
	return c
}

// Controller is the sole Situation reconciler: it owns B+ gating, L2
// proposal/validation, and the conditional authoritative commit. It has no
// outward Slack authority — that is Task 10's job, consuming what this
// commits.
type Controller struct {
	store        Store
	profiles     ProfileReader
	observations *observation.Runner
	acute        AcuteInvestigator
	assessor     AssessmentClient
	clock        func() time.Time
	cfg          Config
}

// NewController constructs a Controller. profiles, observations, acute, and
// assessor may be nil (each degrades independently: no profile widening, no
// bounded reads this cycle, L1 never dispatched, L2 falls back to the
// deterministic degraded Assessment).
func NewController(store Store, profiles ProfileReader, observations *observation.Runner, acute AcuteInvestigator, assessor AssessmentClient, clock func() time.Time, cfg Config) *Controller {
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &Controller{store: store, profiles: profiles, observations: observations, acute: acute, assessor: assessor, clock: clock, cfg: cfg.normalized()}
}

// Reconcile runs one reconciliation pass for an already-claimed Situation:
// build the deterministic snapshot, publish immediately on a deterministic
// urgent floor, gate and (asynchronously) dispatch L1, and — only when the
// material fact hash is not already covered by a trustworthy Assessment —
// propose, validate, and conditionally commit an authoritative L2
// Assessment. The caller (a lease-heartbeating worker) owns claiming and
// releasing the aggregate lease around this call.
func (c *Controller) Reconcile(ctx context.Context, situationID string) error {
	if strings.TrimSpace(situationID) == "" {
		return errors.New("situation: reconcile requires a situation id")
	}
	claim, err := c.store.ClaimedSituation(ctx, situationID)
	if err != nil {
		return fmt.Errorf("situation: reconcile: claim: %w", err)
	}
	in, incidentID, err := c.store.LoadReconciliationInput(ctx, claim)
	if err != nil {
		return fmt.Errorf("situation: reconcile: load input: %w", err)
	}
	c.attachProfiles(ctx, &in)
	now := c.clock().UTC()
	in.Now = now
	snap, err := BuildSnapshot(in)
	if err != nil {
		return fmt.Errorf("situation: reconcile: build snapshot: %w", err)
	}

	trusted, prior, err := c.store.LastTrustedAssessment(ctx, claim)
	if err != nil {
		return fmt.Errorf("situation: reconcile: trusted assessment: %w", err)
	}

	decision := c.decideL1(claim, snap, trusted)
	if decision.Status == L1StatusPlanned {
		if err := c.beginAcuteInvestigation(ctx, claim, incidentID, decision, now); err != nil {
			return fmt.Errorf("situation: reconcile: begin l1: %w", err)
		}
	} else if err := c.store.SetAnalysisState(ctx, AnalysisState{
		IncidentID: incidentID, Status: decision.Status, DecisionReason: decision.DecisionReason, UpdatedAt: now,
	}); err != nil {
		return fmt.Errorf("situation: reconcile: set analysis state: %w", err)
	}

	if trusted.Trustworthy && trusted.FactHash == snap.MaterialHash {
		// Nothing material changed since the last authoritative commit; a
		// wasted L1 re-run alone never forces L2 (its normalization would
		// have to change the hash first).
		return nil
	}

	if floor := ApplyAttentionFloors(model.AttentionObserve, snap, snap.EligibleReasons); floor == model.AttentionUrgent {
		// Publish immediately on sufficient deterministic facts — never
		// waits on L1 or an L2 model call.
		return c.commitDeterministicFloor(ctx, claim, snap, trusted.Sequence, now)
	}

	return c.runL2(ctx, claim, snap, prior, trusted.Sequence, now)
}

// decideL1 applies the B+ gate and, when the claimed Situation carries a
// manual-reassessment due reason, forces a planned decision even over an
// otherwise-covered hash (manual reassessment authorizes one bypass).
func (c *Controller) decideL1(claim Claim, snap Snapshot, trusted TrustedAssessment) L1Decision {
	decision := DecideL1(snap, trusted)
	if decision.Status == L1StatusNotRequested {
		for _, reason := range claim.Situation.DueReasons {
			if reason == model.DueManualReassessment {
				return L1Decision{Status: L1StatusPlanned, DecisionReason: L1ReasonManualReassessment, CoveredSequence: trusted.Sequence}
			}
		}
	}
	return decision
}

// attachProfiles resolves one advisory profile head per distinct delivery
// signature. A resolution failure is best-effort: profiles only ever widen
// evidence consideration, so their absence never blocks reconciliation.
func (c *Controller) attachProfiles(ctx context.Context, in *SnapshotInput) {
	if c.profiles == nil {
		return
	}
	seen := make(map[string]struct{})
	for _, delivery := range in.Deliveries {
		if delivery.ProfileSignature == "" {
			continue
		}
		if _, ok := seen[delivery.ProfileSignature]; ok {
			continue
		}
		seen[delivery.ProfileSignature] = struct{}{}
		head, ok, err := c.profiles.ProfileHead(ctx, delivery.ProfileSignature)
		if err != nil || !ok {
			continue
		}
		in.ProfileHeads = append(in.ProfileHeads, head)
	}
}

// beginAcuteInvestigation applies the B+ "planned" decision: it guards
// against dispatching a second concurrent Investigate() for the same
// Incident (the async goroutine deliberately outlives this lease-scoped
// Reconcile call, so a later reconciliation pass before the first completes
// must observe "running" and skip re-dispatch rather than firing a
// duplicate call), tracks L1's own attempt budget against the same
// per-input attempt count L2 parks on, and only then dispatches.
func (c *Controller) beginAcuteInvestigation(ctx context.Context, claim Claim, incidentID string, decision L1Decision, now time.Time) error {
	if claim.Situation.AttemptCount >= c.cfg.MaxAttemptsPerInput {
		// This Situation's own reconciliation attempt budget for the
		// current unchanged input is exhausted — the same gate runL2 parks
		// on. Repeatedly re-dispatching L1 against the same unchanged facts
		// would not help either; mark it exhausted rather than leaving the
		// gate stuck at "planned" forever.
		return c.store.SetAnalysisState(ctx, AnalysisState{
			IncidentID: incidentID, Status: L1StatusExhausted, DecisionReason: "l1_attempt_budget_exhausted", UpdatedAt: now,
		})
	}
	if c.acute == nil {
		// No investigator wired: the decision stands as planned — nothing
		// to dispatch, and nothing to guard against duplicating.
		return c.store.SetAnalysisState(ctx, AnalysisState{
			IncidentID: incidentID, Status: decision.Status, DecisionReason: decision.DecisionReason, UpdatedAt: now,
		})
	}
	current, err := c.store.AnalysisState(ctx, incidentID)
	if err != nil {
		return err
	}
	if current.Status == L1StatusRunning {
		// An investigation is already in flight for this Incident; do not
		// dispatch a duplicate.
		return nil
	}
	if err := c.store.SetAnalysisState(ctx, AnalysisState{
		IncidentID: incidentID, Status: L1StatusRunning, DecisionReason: decision.DecisionReason, UpdatedAt: now,
	}); err != nil {
		return err
	}
	c.dispatchAcuteInvestigation(ctx, claim.Situation.ID, incidentID)
	return nil
}

// dispatchAcuteInvestigation runs L1 asynchronously: Reconcile has already
// (or is about to) commit whatever deterministic/L2 result the current
// facts support, and L1's own finding only matters for a LATER
// reconciliation once its normalization is durable. It uses a
// cancellation-detached context so the lease-scoped ctx ending when
// Reconcile returns cannot cut the investigation off mid-flight. The caller
// (beginAcuteInvestigation) has already persisted "running" and confirmed no
// other investigation is in flight, so this only ever transitions running ->
// complete/blocked.
func (c *Controller) dispatchAcuteInvestigation(ctx context.Context, situationID, incidentID string) {
	if c.acute == nil {
		return
	}
	bg := context.WithoutCancel(ctx)
	go func() {
		result, err := c.acute.Investigate(bg, incidentID)
		now := c.clock().UTC()
		status := L1StatusComplete
		if err != nil {
			status = L1StatusBlocked
		}
		_ = c.store.SetAnalysisState(bg, AnalysisState{IncidentID: incidentID, Status: status, DecisionReason: "l1_attempt_completed", UpdatedAt: now})
		if err != nil {
			return
		}
		_ = NormalizeL1(result) // persisting the normalized finding into a snapshot-loadable fact is Task 9+ store wiring
		_ = c.store.MarkDue(bg, situationID, model.DueRetry, now)
	}()
}

// commitDeterministicFloor builds and commits the one Assessment shape a
// deterministic urgent floor authorizes without any model call: Attention is
// forced urgent, the cited reason is the eligible floor candidate itself,
// and the limitation says interpretation is unavailable — never invented.
func (c *Controller) commitDeterministicFloor(ctx context.Context, claim Claim, snap Snapshot, priorSequence int, now time.Time) error {
	floor, ok := selectUrgentFloorReason(snap)
	if !ok {
		return errors.New("situation: floor attention computed without an eligible floor candidate")
	}
	nextUpdate := now.Add(c.cfg.FastCadence)
	action := "confirm bounded evidence"
	proposal := model.Assessment{
		SchemaVersion: AssessmentSchemaVersion, Persistence: model.PersistenceUnknown, Impact: model.ImpactUnknown,
		Novelty: model.NoveltyInsufficientHistory, Causality: model.CausalityUnknown, Attention: model.AttentionUrgent,
		Lifecycle: snap.Lifecycle, EvidenceQuality: model.EvidenceQualityDegraded,
		SufficientReason: sufficientReasonFromCandidate(floor, nil),
		ActionContract: model.ActionContract{
			NextActor: model.NextActorAlertint, ActionStatus: model.ActionStatusPlanned,
			AlertintAction: &action, NextUpdateAt: &nextUpdate, NextUpdateOn: []string{"recovery_observed", "availability_impact"},
		},
		Limitations:     []model.Limitation{{Code: "model_interpretation_unavailable", Detail: "published from a deterministic urgent floor ahead of L1/L2 interpretation"}},
		ProposedCadence: model.CadenceFast,
	}
	validated, adjustments, err := ValidateAssessment(snap, proposal, now)
	if err != nil {
		return fmt.Errorf("situation: reconcile: deterministic floor validation: %w", err)
	}
	return c.commitAssessment(ctx, claim, snap, validated, adjustments, AssessmentActorDeterministic, priorSequence, now, nil)
}

// commitDeterministicDegraded is the safe default when L2 cannot produce a
// validated proposal this attempt (no assessor wired, the call failed, or
// the budget was exhausted) and no deterministic urgent floor applies
// (floors already short-circuited Reconcile before runL2 otherwise). It
// never self-selects an admissible-but-not-automatically-publishable
// reason — only L2 may decide those — so it stays quiet (observe).
func (c *Controller) commitDeterministicDegraded(ctx context.Context, claim Claim, snap Snapshot, priorSequence int, now time.Time) error {
	nextUpdate := now.Add(c.cfg.NormalCadence)
	proposal := model.Assessment{
		SchemaVersion: AssessmentSchemaVersion, Persistence: model.PersistenceUnknown, Impact: model.ImpactUnknown,
		Novelty: model.NoveltyInsufficientHistory, Causality: model.CausalityUnknown, Attention: model.AttentionObserve,
		Lifecycle: snap.Lifecycle, EvidenceQuality: model.EvidenceQualityInsufficient,
		ActionContract:  model.ActionContract{NextActor: model.NextActorNone, ActionStatus: model.ActionStatusWaiting, NextUpdateAt: &nextUpdate},
		Limitations:     []model.Limitation{{Code: "model_interpretation_unavailable", Detail: "L2 produced no validated proposal this attempt"}},
		ProposedCadence: model.CadenceNormal,
	}
	validated, adjustments, err := ValidateAssessment(snap, proposal, now)
	if err != nil {
		return fmt.Errorf("situation: reconcile: degraded assessment validation: %w", err)
	}
	return c.commitAssessment(ctx, claim, snap, validated, adjustments, AssessmentActorDeterministic, priorSequence, now, nil)
}

// runL2 requests a validated L2 proposal within the two-call budget. A
// syntactically invalid response earns one corrective retry (never a policy
// rejection, which is rejected outright with no prompt-around retry); a
// valid first proposal that still leaves a material contradiction unresolved
// (Causality: contradicted — the schema's own name for exactly this state)
// earns exactly one optional finalize pass against the same immutable
// snapshot, spending whatever budget remains. Every discarded call (a
// transport/API error, a malformed response, or a policy rejection) is
// audited. After five exhausted attempts for this unchanged input it parks
// rather than converting exhaustion into terminality; otherwise a call that
// never yields a committable proposal still ends in a safe deterministic
// degraded commit so the Situation is never left without a current
// Assessment.
func (c *Controller) runL2(ctx context.Context, claim Claim, snap Snapshot, prior *model.Assessment, priorSequence int, now time.Time) error {
	if claim.Situation.AttemptCount >= c.cfg.MaxAttemptsPerInput {
		return c.store.Park(ctx, claim, now.Add(c.cfg.ParkRetryAfter), "l2_budget_exhausted_unchanged_input")
	}
	if c.assessor == nil {
		return c.commitDeterministicDegraded(ctx, claim, snap, priorSequence, now)
	}

	prompt := BuildAssessmentPrompt(snap, prior, c.cfg.AllowedCapabilities)
	sequence := priorSequence
	var (
		haveValid  bool
		validValid model.Assessment
		validAdj   []model.ValidationAdjustment
		validUsage json.RawMessage
		validSeq   int
	)
	for call := 0; call < c.cfg.MaxL2Calls; call++ {
		completion, err := c.assessor.Complete(ctx, AssessmentSystemPrompt, prompt, AssessmentRequiredKeys)
		sequence++
		if err != nil {
			// The call itself failed (network/provider): audited as failed
			// with no proposal (there is none), then stop — a transport/API
			// error is not a schema-correction case and is never retried
			// within this attempt cycle.
			c.recordDiscardedAttempt(ctx, claim, snap, AttemptStatusFailed, nil, sequence, now)
			break
		}
		var proposal model.Assessment
		if jsonErr := json.Unmarshal(completion.Raw, &proposal); jsonErr != nil {
			c.recordDiscardedAttempt(ctx, claim, snap, AttemptStatusFailed, completion.Raw, sequence, now)
			if !haveValid && call+1 < c.cfg.MaxL2Calls {
				// One corrective retry, only before any valid proposal
				// exists to fall back on.
				continue
			}
			break
		}
		validated, adjustments, valErr := ValidateAssessment(snap, proposal, now)
		if valErr != nil {
			// Policy rejection: audited as rejected, then reject outright —
			// no prompt-around retry, valid or not.
			c.recordDiscardedAttempt(ctx, claim, snap, AttemptStatusRejected, completion.Raw, sequence, now)
			break
		}
		if !haveValid && validated.Causality == model.CausalityContradicted && call+1 < c.cfg.MaxL2Calls {
			// The first valid proposal still leaves a material contradiction
			// unresolved: spend exactly one remaining call finalizing it
			// against the same snapshot rather than committing it as-is.
			haveValid, validValid, validAdj, validUsage, validSeq = true, validated, adjustments, modelUsageJSON(completion), sequence
			continue
		}
		return c.commitAssessment(ctx, claim, snap, validated, adjustments, AssessmentActorLLM, sequence-1, now, modelUsageJSON(completion))
	}
	if haveValid {
		// The finalize pass was not reached, failed, or was rejected: the
		// first valid (if still contradicted) proposal stands rather than
		// being discarded outright. validSeq — not the loop's now-advanced
		// sequence — is this proposal's own attempt sequence number.
		return c.commitAssessment(ctx, claim, snap, validValid, validAdj, AssessmentActorLLM, validSeq-1, now, validUsage)
	}
	return c.commitDeterministicDegraded(ctx, claim, snap, sequence, now)
}

// recordDiscardedAttempt audits one L2 call this attempt cycle rejected or
// failed to parse. It is best-effort: a failure to record the discard must
// never itself fail reconciliation, which already has a safe deterministic
// fallback ahead of it.
func (c *Controller) recordDiscardedAttempt(ctx context.Context, claim Claim, snap Snapshot, status AssessmentAttemptStatus, raw json.RawMessage, sequence int, now time.Time) {
	var proposal json.RawMessage
	if json.Valid(raw) {
		proposal = raw
	}
	attempt := AssessmentAttempt{
		ID: uuid.NewString(), Sequence: sequence, InputVersion: snap.InputVersion, FactHash: snap.MaterialHash,
		Actor: AssessmentActorLLM, Status: status, TriggerReasons: dueReasonStrings(claim.Situation.DueReasons),
		SnapshotDigest: snap.MaterialHash, Proposal: proposal, CreatedAt: now, CompletedAt: &now,
	}
	_ = c.store.AppendAssessmentAttempt(ctx, claim, attempt)
}

// commitAssessment appends and commits the authoritative attempt. A stale
// commit (the claimed input version no longer matches current durable
// state) is stored as `stale`, produces no outward effect, and reschedules
// the current input rather than failing the reconciliation.
func (c *Controller) commitAssessment(ctx context.Context, claim Claim, snap Snapshot, validated model.Assessment, adjustments []model.ValidationAdjustment, actor AssessmentActor, priorSequence int, now time.Time, usage json.RawMessage) error {
	validatedJSON, err := json.Marshal(validated)
	if err != nil {
		return fmt.Errorf("situation: reconcile: marshal validated assessment: %w", err)
	}
	attempt := AssessmentAttempt{
		ID: uuid.NewString(), Sequence: priorSequence + 1, InputVersion: snap.InputVersion, FactHash: snap.MaterialHash,
		Actor: actor, Status: AttemptStatusAuthoritative, TriggerReasons: dueReasonStrings(claim.Situation.DueReasons),
		SnapshotDigest: snap.MaterialHash, Validated: validatedJSON, ValidationAdjustments: adjustments,
		ModelUsage: usage, CreatedAt: now, CompletedAt: &now,
	}
	tr := model.Transition{
		ID: uuid.NewString(), SituationID: claim.Situation.ID, InputVersion: snap.InputVersion,
		Lifecycle: validated.Lifecycle, Attention: validated.Attention, Assessment: &validated,
		ActionContract: validated.ActionContract, Reason: strings.Join(attempt.TriggerReasons, ","), CreatedAt: now,
	}
	err = c.store.CommitAuthoritative(ctx, claim, attempt, tr)
	if errors.Is(err, ErrStaleInput) {
		stale := attempt
		stale.Status = AttemptStatusStale
		if appendErr := c.store.AppendAssessmentAttempt(ctx, claim, stale); appendErr != nil {
			return fmt.Errorf("situation: reconcile: store stale attempt: %w", appendErr)
		}
		return c.store.Reschedule(ctx, claim, now)
	}
	if err != nil {
		return fmt.Errorf("situation: reconcile: commit assessment: %w", err)
	}
	return nil
}

// modelUsageJSON captures only the audit-safe usage figures the client
// already computes — never the raw model response (excluded from audit by
// contract).
func modelUsageJSON(completion llm.Completion) json.RawMessage {
	usage, err := json.Marshal(struct {
		Model        string `json:"model"`
		InputTokens  int    `json:"input_tokens"`
		OutputTokens int    `json:"output_tokens"`
		LatencyMS    int64  `json:"latency_ms"`
	}{completion.Model, completion.InputTokens, completion.OutputTokens, completion.Latency.Milliseconds()})
	if err != nil {
		return nil
	}
	return usage
}

func dueReasonStrings(reasons []model.DueReason) []string {
	out := make([]string, len(reasons))
	for i, reason := range reasons {
		out[i] = string(reason)
	}
	return out
}
