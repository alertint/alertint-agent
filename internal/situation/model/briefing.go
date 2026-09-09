// SPDX-License-Identifier: FSL-1.1-ALv2

package model

import (
	"strings"
	"time"
	"unicode/utf8"
)

// IncidentAnalysis is selected completed output, never a prompt or raw evidence
// envelope. Missing provenance remains missing; verification is not causality.
type IncidentAnalysis struct {
	IncidentID        string     `json:"incident_id"`
	Title             string     `json:"title,omitempty"`
	Summary           string     `json:"summary,omitempty"`
	Findings          []string   `json:"findings,omitempty"`
	Verification      string     `json:"verification,omitempty"`
	VerificationLimit string     `json:"verification_limit,omitempty"`
	VerificationGaps  int        `json:"verification_gaps,omitempty"`
	AnalyzedAt        *time.Time `json:"analyzed_at,omitempty"`
	Stale             bool       `json:"stale,omitempty"`
}

// BoundIncidentAnalysis owns the byte bounds at both snapshot and publication
// boundaries. Copy slices/instants so the immutable selection cannot alias input.
func BoundIncidentAnalysis(a IncidentAnalysis) IncidentAnalysis {
	a.IncidentID = briefingBound(a.IncidentID, 200)
	a.Title = briefingBound(a.Title, 180)
	a.Summary = briefingBound(a.Summary, 500)
	a.Verification = briefingBound(a.Verification, 40)
	a.VerificationLimit = briefingBound(a.VerificationLimit, 100)
	findings := a.Findings
	a.Findings = nil
	for i, f := range findings {
		if i == 3 {
			break
		}
		if strings.TrimSpace(f) != "" {
			a.Findings = append(a.Findings, briefingBound(f, 400))
		}
	}
	if a.AnalyzedAt != nil {
		at := a.AnalyzedAt.UTC()
		a.AnalyzedAt = &at
	}
	return a
}

func briefingBound(s string, limit int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= limit {
		return s
	}
	cut := s[:limit-3]
	for !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut + "…"
}

// BriefingAlert keeps stable internal identity separate from bounded readable
// names. State is firing, resolved or unknown, from the source lifecycle fold.
type BriefingAlert struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"`
}

// OperatorBriefing travels only through the immutable publication projection.
// A nil briefing on old projections preserves their legacy replay behavior.
type OperatorBriefing struct {
	Scope         string             `json:"scope"`
	DisplayScope  string             `json:"display_scope,omitempty"`
	Alerts        []BriefingAlert    `json:"alerts,omitempty"`
	AlertsOmitted int                `json:"alerts_omitted,omitempty"`
	RetryAt       *time.Time         `json:"retry_at,omitempty"`
	Symptoms      []string           `json:"symptoms,omitempty"`
	Firing        int                `json:"firing"`
	Resolved      int                `json:"resolved"`
	Unknown       int                `json:"unknown"`
	Total         int                `json:"total"`
	Critical      int                `json:"critical"`
	AnalysisCount int                `json:"analysis_count"`
	Failed        int                `json:"failed"`
	Pending       int                `json:"pending"`
	Unavailable   int                `json:"unavailable,omitempty"`
	Analyses      []IncidentAnalysis `json:"analyses,omitempty"`
	Historical    bool               `json:"historical,omitempty"`

	// Work is the aggregate, per-Situation acute-triage work disposition
	// (B0 integration contract §3, accepted 2026-09-08): a coherent
	// projection of durable IncidentState/TriageState facts B3/B4/B5
	// consume instead of re-deriving their own reading of raw Triage
	// phases. Zero value (Work.Phase == "") means this Transition predates
	// the field (legacy replay) — never a real "no work" disposition,
	// which is WorkPhaseNone.
	Work WorkProjection `json:"work"`
}

// WorkPhase is one closed-vocabulary Acute Triage work disposition, richer
// than the older 4-value TriagePhase enum DeriveActionContract still reads:
// it tells apart "not yet reached ready" from "decided but not yet
// executing" from "actually executing" from "settled with no further
// automatic work" — the distinctions slide 2 (MINIMAL 2.2) requires and the
// ported presentation collapsed (S2-01/S2-02/S2-03/S2-07).
type WorkPhase string

const (
	// WorkPhaseCollecting is an Incident that has not yet reached "ready" —
	// no incident_triage row exists yet (TriageState.Phase == "").
	WorkPhaseCollecting WorkPhase = "collecting"
	// WorkPhaseAwaitingDecision is a ready Incident whose Triage schedule
	// has never received a controller decision.
	WorkPhaseAwaitingDecision WorkPhase = "awaiting_decision"
	// WorkPhaseQueued is a durable request with no attempt claimed yet —
	// never evidence that execution has actually begun.
	WorkPhaseQueued WorkPhase = "queued"
	// WorkPhaseExecuting is a fenced attempt actually running.
	WorkPhaseExecuting WorkPhase = "executing"
	// WorkPhaseRetryWait is a failed attempt with a persisted, bounded
	// retry time — distinct from a generic status checkpoint.
	WorkPhaseRetryWait WorkPhase = "retry_wait"
	// WorkPhaseSettled is a clean skip (coverage reuse or an eligibility
	// policy) — no further automatic work on this schedule, and never a
	// fabricated analysis success.
	WorkPhaseSettled WorkPhase = "settled"
	// WorkPhaseExhausted is a schedule that spent its final failure/attempt
	// budget — the investigation's own end, independent of source
	// lifecycle/monitoring.
	WorkPhaseExhausted WorkPhase = "exhausted"
	// WorkPhaseNone means no member Incident carries any Triage work at
	// all — a genuine "nothing outstanding", not a legacy zero value.
	WorkPhaseNone WorkPhase = "none"
)

// WorkProjection is the aggregate, per-Situation acute-triage work
// disposition B2 derives from durable IncidentState/TriageState facts —
// never guessed from display text and never inferred from a request or
// decision alone (B0 integration contract §3).
type WorkProjection struct {
	// Phase is the aggregate disposition across every member Incident's
	// Triage schedule. Precedence: executing > queued (once some Incident
	// has actually executed) > retry_wait > awaiting_decision/queued
	// (before any execution) > exhausted > settled > collecting > none.
	Phase WorkPhase `json:"phase"`
	// ExecutionStarted is true only when some member Incident's Triage
	// schedule has actually claimed an attempt: TriageState.Attempts > 0,
	// or equivalently ActiveAttempt/LastExecution, both sourced from the
	// immutable incident_triage_attempts ledger (BuildWorkProjection) —
	// NEVER inferred from a request or decision alone, and NEVER from a
	// PRE-claim clean skip (CleanSkipIncidentTriageBelowMinimumMembers
	// consumes no attempt, so a skip decision alone is not execution). A
	// POST-claim clean skip (CompleteIncidentTriageAttemptAsCleanSkip) DOES
	// still read as execution having started: an attempt was claimed and
	// consumed before the coverage-reuse decision closed it (repair, lead
	// review round 3, 2026-09-09 — this field was already wired, not
	// pending a future chunk).
	ExecutionStarted bool `json:"execution_started"`
	// InvestigatedAlertIDs/InvestigatedNames are the recorded investigation
	// input this Situation's actual execution(s) used — the union of each
	// member Incident's current execution's frozen claim-time member
	// deliveries, resolved to Alert identity/name (never Situation.Total;
	// never current membership, which may have changed since the claim).
	// Bounded, deterministically ordered by Alert ID. Populated by
	// committedOperatorBriefing's investigatedAlertIdentities from
	// TriageState.ActiveAttempt/LastExecution (R1 repair, lead review
	// 2026-09-09).
	InvestigatedAlertIDs []string `json:"investigated_alert_ids,omitempty"`
	InvestigatedNames    []string `json:"investigated_names,omitempty"`
	// RemainingIncidents counts member Incidents whose Triage schedule
	// still has outstanding automatic work (awaiting_decision, queued,
	// executing, or retry_wait) — not the Situation's total member count.
	RemainingIncidents int `json:"remaining_incidents"`
	// SkipReason is the dominant settled Incident's recorded disposition:
	// "" (none settled), "prior_coverage" (exact trustworthy coverage
	// reuse), or "eligibility_policy" (a policy such as minimum members
	// excluded the work) — mapped from the durable decision_reason /
	// clean-skip code, never guessed from display text.
	SkipReason string `json:"skip_reason,omitempty"`
	// RetryEligibleAt is the earliest of the persisted retry_wait next_at
	// across member Incidents' Triage schedules and the committed
	// Assessment-level retry (situations.retry_at, ControllerCommit.RetryAt
	// — R3 repair, lead review 2026-09-09), or nil when neither exists
	// (including every exhausted schedule, which never has one).
	RetryEligibleAt *time.Time `json:"retry_eligible_at,omitempty"`
	// SourceGraceUntil is the committed recovery-grace deadline, carried
	// here so a renderer never needs a second read to tell a retry-due time
	// apart from the recovery deadline.
	SourceGraceUntil *time.Time `json:"source_grace_until,omitempty"`
	// StatusCheckpointAt is ActionContract.NextUpdateAt — a status check,
	// never a reply promise (spec.md's status-checkpoint fallback).
	StatusCheckpointAt *time.Time `json:"status_checkpoint_at,omitempty"`
}

// OperatorDelta captures what changed relative to the prior committed state.
// A delayed renderer never needs to consult mutable history to explain it.
type OperatorDelta struct {
	StateChanged        bool               `json:"state_changed,omitempty"`
	PreviousFiring      int                `json:"previous_firing"`
	PreviousTotal       int                `json:"previous_total"`
	ScopeChanged        bool               `json:"scope_changed,omitempty"`
	PreviousScope       string             `json:"previous_scope,omitempty"`
	SymptomsChanged     bool               `json:"symptoms_changed,omitempty"`
	PreviousSymptoms    []string           `json:"previous_symptoms,omitempty"`
	ClearedAlerts       []string           `json:"cleared_alerts,omitempty"`
	NewFiringAlerts     []string           `json:"new_firing_alerts,omitempty"`
	Analyses            []IncidentAnalysis `json:"analyses,omitempty"`
	AnalysisFailed      bool               `json:"analysis_failed,omitempty"`
	AttentionIncreased  bool               `json:"attention_increased,omitempty"`
	HumanRequestChanged bool               `json:"human_request_changed,omitempty"`
	AbilityLost         bool               `json:"ability_lost,omitempty"`

	// Candidates are the structured material-evidence facts B3 derives from
	// (prior, current) (B0 integration contract §4), immutable and legacy-
	// compatible: every field above stays populated exactly as before for
	// old readers/replay. B5 filters Candidates against DeliveredHistory
	// (ReplyEligible) to decide what actually posts; B4 renders only
	// Summary.Briefing(+Work) and this slice, never re-deriving materiality.
	Candidates []MaterialCandidate `json:"candidates,omitempty"`
}

// CandidateKind is the closed set of structured material-evidence facts a
// committed Transition can carry (B0 integration contract §4). A candidate
// existing here is a materiality FACT, never a delivery decision — B5's
// ReplyEligible (DeliveredHistory-aware) and B4's renderer are the only
// consumers that decide whether/how it reaches Slack.
type CandidateKind string

const (
	// CandidateFirstExecutionAssurance marks Work.ExecutionStarted's false
	// -> true edge for this Situation — never a request/decision alone, and
	// never re-emitted on a later commit once execution has started.
	CandidateFirstExecutionAssurance CandidateKind = "first_execution_assurance"
	// CandidateUsefulFinding marks a structured-fact change in a member
	// Incident's analysis: Observations, Unknowns or Hypothesis differ from
	// the prior committed analysis for that Incident — never a Verification
	// enum flip or a paraphrase alone.
	CandidateUsefulFinding CandidateKind = "useful_finding"
	// CandidateInconclusiveCompletion marks a member Incident's Triage
	// schedule newly settling (exhausted or a clean skip) with no useful
	// finding to report — the investigation's own honest end.
	CandidateInconclusiveCompletion CandidateKind = "inconclusive_completion"
	// CandidateMembersChanged marks a source scope/urgency/membership
	// change while the Situation stays Active — distinct from AllClear/
	// Refire, which already carry their own lifecycle-edge member facts.
	CandidateMembersChanged CandidateKind = "members_changed"
	// CandidateAbilityChanged marks a new or newly-cleared investigation
	// limitation (e.g. an evidence source becoming unavailable or recovering)
	// — never a repeated, already-communicated limitation.
	CandidateAbilityChanged CandidateKind = "ability_changed"
	// CandidateActionChanged marks ActionContract.OperatorActionRequired
	// newly appearing, changing or clearing.
	CandidateActionChanged CandidateKind = "action_changed"
	// CandidateAllClear marks every member alert reaching authoritative
	// clearance (Lifecycle -> RecoveryPending).
	CandidateAllClear CandidateKind = "all_clear"
	// CandidateRefire marks a source refire interrupting recovery
	// confirmation (Lifecycle RecoveryPending -> Active) — distinct from a
	// recurrence-count milestone rung, which is not a candidate (E2).
	CandidateRefire CandidateKind = "refire"
	// CandidateTerminalEnd marks the Situation's lifecycle newly reaching a
	// terminal outcome (Recovered or ClosedUnknown).
	CandidateTerminalEnd CandidateKind = "terminal_end"
)

// NextStepKind names what a candidate's actual next step actually is —
// never a fabricated retry or execution ETA.
type NextStepKind string

const (
	NextStepStatusCheck   NextStepKind = "status_check"
	NextStepRetryEligible NextStepKind = "retry_eligible"
	NextStepGraceDeadline NextStepKind = "grace_deadline"
	NextStepWorkEnded     NextStepKind = "work_ended"
	NextStepTrackingEnded NextStepKind = "tracking_ended"
)

// FindingFacts are the structured pieces of one member Incident's analysis
// that materiality compares by structural inequality, never prose equality
// (B0 integration contract §4): a changed Verification enum or wording-only
// Hypothesis rewrite alone is NOT a candidate; a changed Observations or
// Unknowns set IS.
type FindingFacts struct {
	IncidentID   string     `json:"incident_id,omitempty"`
	Hypothesis   string     `json:"hypothesis,omitempty"`
	Observations []string   `json:"observations,omitempty"`
	Unknowns     []string   `json:"unknowns,omitempty"`
	AnalyzedAt   *time.Time `json:"analyzed_at,omitempty"`
}

// MemberFacts are actual recorded member-alert names and counts — never a
// common-cause inference from grouping, and never Situation.Total standing
// in for the investigation's own recorded input count.
type MemberFacts struct {
	Cleared     []string `json:"cleared,omitempty"`
	NowFiring   []string `json:"now_firing,omitempty"`
	StillFiring []string `json:"still_firing,omitempty"`
	FiringCount int      `json:"firing_count"`
	Total       int      `json:"total"`
}

// LimitationFacts names one recorded investigation-ability limitation code
// (never free prose) and whether this candidate reports it appearing or
// clearing.
type LimitationFacts struct {
	Code    string `json:"code,omitempty"`
	Cleared bool   `json:"cleared,omitempty"`
}

// ActionFacts distinguishes a recorded operator Action newly introduced,
// revised, or withdrawn. A withdrawal only corrects an earlier DELIVERED
// request (B5's DeliveredHistory.CommunicatedAction, §5) — B3 emits the raw
// structural fact; B5 decides delivery-aware eligibility.
type ActionFacts struct {
	Introduced bool           `json:"introduced,omitempty"`
	Revised    bool           `json:"revised,omitempty"`
	Withdrawn  bool           `json:"withdrawn,omitempty"`
	Action     OperatorAction `json:"action,omitempty"`
}

// NextStepFacts is the actual recorded next step a candidate's reply may
// state — a status checkpoint, a real retry/grace time, or an explicit end.
// Never an invented retry or execution ETA.
type NextStepFacts struct {
	Kind NextStepKind `json:"kind,omitempty"`
	At   *time.Time   `json:"at,omitempty"`
}

// MaterialCandidate is one structured material-evidence fact B3's
// MaterialCandidates derives from (prior, current) committed Transitions
// (B0 integration contract §4). Exactly one of Finding/Members/Limitation/
// Action is populated, matching Kind; Next is always the actual recorded
// next step, never fabricated.
type MaterialCandidate struct {
	Kind       CandidateKind    `json:"kind"`
	Finding    *FindingFacts    `json:"finding,omitempty"`
	Members    *MemberFacts     `json:"members,omitempty"`
	Limitation *LimitationFacts `json:"limitation,omitempty"`
	Action     *ActionFacts     `json:"action,omitempty"`
	Next       NextStepFacts    `json:"next,omitempty"`
}
