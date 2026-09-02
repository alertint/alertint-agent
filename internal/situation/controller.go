// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"encoding/json"
	"time"

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
	InputVersion                         int
	Assessment                           model.Assessment
	Coverage                             []model.IncidentCoverage
	Derivation                           model.AssessmentDerivation
	ReusedFromAssessmentID               *string
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
type ControllerCommit struct {
	Attempt            AssessmentAttempt
	Assessment         model.Assessment
	TriageDecisions    []TriageDecision
	Lifecycle          model.Lifecycle
	Attention          model.Attention
	RecoveryObservedAt *time.Time
	GraceUntil         *time.Time
	TerminalAt         *time.Time
	TerminalReason     *model.TerminalReason
	NextAssessmentAt   time.Time
	ConsumedDueReasons []model.DueReason
	RetryAt            *time.Time
	LastErrorClass     *string
}
