// SPDX-License-Identifier: FSL-1.1-ALv2

package model

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
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
	// EvidenceFingerprint is EvidenceFingerprint() over this analysis's
	// recorded observations and verification limitation as they stood
	// BEFORE the display bounds above cut them (lead authorization, round 4,
	// 2026-09-09) — presentation-only comparison provenance, so materiality
	// never mistakes a shorter display for different evidence. "" means the
	// projection recorded none (a legacy snapshot, or a shape built outside
	// the loader): unknown, never an empty result.
	EvidenceFingerprint string `json:"evidence_fingerprint,omitempty"`
}

// AnalysisFindingsBound and CompletionObservationsBound are the two DISPLAY
// bounds one Incident's recorded observations pass through: the analysis
// overview keeps three (BoundIncidentAnalysis below), an EndedWork
// completion keeps six. Named because materiality has to know a list may be
// cut at exactly these lengths and at no other — a shorter list is complete
// as recorded.
const (
	AnalysisFindingsBound       = 3
	CompletionObservationsBound = 6
)

// EvidenceFingerprint is the one shared, presentation-only structural
// fingerprint of one Incident's evidence: its recorded observations and its
// decision-relevant verification limitation/gap count, normalized the same
// way on every path and hashed BEFORE any display truncation. Hypothesis and
// title prose, judgment/completion times, attempt identity and the outcome
// enum are deliberately excluded — canonical slide 4 row 577, "Neither
// paraphrasing nor an evidence enum change earns a reply". An absent list
// and an empty one produce the same fingerprint, so a persistence round trip
// is never a change; an evidence set that is genuinely empty still has a
// fingerprint, so "" can only ever mean unknown provenance.
//
// It is comparison provenance only: it never enters an assessment or reuse
// digest, delivery history, dispatch authority or any schema.
func EvidenceFingerprint(observations []string, verificationLimit string, verificationGaps int) string {
	var b strings.Builder
	for _, o := range observations {
		o = normalizeEvidenceText(o)
		if o == "" {
			continue
		}
		// Length-prefixed so no observation's content can imitate the
		// framing of a different list.
		b.WriteString("o")
		b.WriteString(strconv.Itoa(len(o)))
		b.WriteString(":")
		b.WriteString(o)
		b.WriteString("\x1e")
	}
	limit := normalizeEvidenceText(verificationLimit)
	b.WriteString("l")
	b.WriteString(strconv.Itoa(len(limit)))
	b.WriteString(":")
	b.WriteString(limit)
	b.WriteString("\x1eg:")
	b.WriteString(strconv.Itoa(verificationGaps))
	sum := sha256.Sum256([]byte(b.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// normalizeEvidenceText is the whitespace normalization briefingBound
// already applies to displayed text, hoisted so a fingerprint taken before
// truncation and a comparison of the bounded text after it agree.
func normalizeEvidenceText(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// BoundIncidentAnalysis owns the byte bounds at both snapshot and publication
// boundaries. Copy slices/instants so the immutable selection cannot alias input.
func BoundIncidentAnalysis(a IncidentAnalysis) IncidentAnalysis {
	a.IncidentID = briefingBound(a.IncidentID, 200)
	a.Title = briefingBound(a.Title, 180)
	a.Summary = briefingBound(a.Summary, 500)
	a.Verification = briefingBound(a.Verification, 40)
	a.VerificationLimit = briefingBound(a.VerificationLimit, 100)
	a.EvidenceFingerprint = briefingBound(a.EvidenceFingerprint, 80)
	findings := a.Findings
	a.Findings = nil
	for i, f := range findings {
		if i == AnalysisFindingsBound {
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
	s = normalizeEvidenceText(s)
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
	// InvestigatedAlertIDs carries the identities themselves, bounded only
	// by investigatedIdentityLimit, so it is count provenance rather than a
	// display list; InvestigatedNames is separately truncated to the eight
	// names a reply shows. Never read one as the other.
	InvestigatedAlertIDs []string `json:"investigated_alert_ids,omitempty"`
	InvestigatedNames    []string `json:"investigated_names,omitempty"`
	// InvestigatedCount is the EXACT number of distinct frozen claim-time
	// investigation inputs, counted before either bound above is applied —
	// the only truthful number a reply may state as "investigating N alerts"
	// (R3 repair, lead review 2026-09-09). Meaningful ONLY when
	// InvestigatedCountKnown is true.
	InvestigatedCount int `json:"investigated_count,omitempty"`
	// InvestigatedCountKnown is true only when the COMPLETE frozen input
	// union was resolved to Alert identity and counted before truncation
	// (lead decision B, round 2, 2026-09-09). False — "unknown" — on a
	// transition that predates the field (legacy replay carried at most
	// eight bounded IDs, which could mean eight or ninety), and whenever any
	// frozen member delivery id could not be resolved through this
	// Situation's own deliveries (a legacy/moved row), so the count is never
	// silently under-reported. Unknown is neither zero inputs nor the bounded
	// list length: B4/B5 omit an unqualified numeric assurance when unknown.
	InvestigatedCountKnown bool `json:"investigated_count_known,omitempty"`
	// EndedWork lists every member Incident whose Triage schedule has ended
	// (settled or exhausted), each with the actual attempt identity and
	// durable completion facts that ended it (lead decision D, round 2,
	// 2026-09-09) — the per-incident completion provenance B3's
	// inconclusive-completion candidate compares by stable incident/attempt/
	// outcome identity, never by aggregate phase alone. Presentation facts
	// only: nothing here is a new stored outcome, an LLM authority, or a
	// dispatch trigger. Never truncated to a display bound — text is bounded
	// within each record instead.
	EndedWork []IncidentWorkOutcome `json:"ended_work,omitempty"`
	// EndedWorkKnown is true on every projection built with per-incident
	// completion provenance. False means a transition that predates
	// EndedWork (legacy replay): its ended work is UNKNOWN, not empty, so a
	// later projection must never manufacture retrospective phantom
	// completions against it.
	EndedWorkKnown bool `json:"ended_work_known,omitempty"`
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
	// QueuedEligibleAt is the earliest recorded eligibility across member
	// Incidents whose Triage schedule is QUEUED: incident_triage.next_at,
	// the moment the worker may claim the durable request
	// (applyRequestFromAwaitingDecisionTx stamps it, and a request refresh
	// preserves an existing back-off time rather than restarting it). It
	// answers slide 2's "queued analysis, with a known readiness/due time
	// or actual waiting reason" — an eligibility time only, never a promise
	// that execution begins then and never evidence that anything started
	// (G1 repair, lead final review 2026-09-10). nil means no queued
	// schedule records one.
	QueuedEligibleAt *time.Time `json:"queued_eligible_at,omitempty"`
	// QueuedEligibilityKnown is true on every projection built with the
	// field above. False means a transition that predates it (legacy
	// replay): its queued eligibility is UNKNOWN rather than absent, so a
	// renderer must never read the missing time as "eligible now". Same
	// unknown-is-not-empty rule as EndedWorkKnown.
	QueuedEligibilityKnown bool `json:"queued_eligibility_known,omitempty"`
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

// IncidentWorkOutcome is one member Incident's ended Triage work with the
// completion provenance that ended it (lead decision D, round 2,
// 2026-09-09). It is a projection of existing durable facts — the
// incident_triage row's phase/decision_reason, the incident_triage_attempts
// ledger's result_code/completed_at/output_digest, and the accepted Incident
// output matched to that attempt — never a new stored outcome.
type IncidentWorkOutcome struct {
	IncidentID string `json:"incident_id"`
	// AttemptID is the actual execution that ended this schedule, "" when no
	// attempt was ever claimed (a pre-claim clean skip, or an Incident
	// analyzed before the attempt ledger existed). Identity for comparison:
	// a second completion for the same Incident is a different attempt.
	AttemptID string `json:"attempt_id,omitempty"`
	// Phase is WorkPhaseSettled or WorkPhaseExhausted — the only two ended
	// dispositions.
	Phase WorkPhase `json:"phase"`
	// SkipReason is this Incident's own mapped clean-skip disposition
	// (WorkProjection.SkipReason vocabulary), "" when the schedule did not
	// end by a skip.
	SkipReason string `json:"skip_reason,omitempty"`
	// ResultCode/CompletedAt are the attempt ledger's durable completion
	// columns for AttemptID — "success", a stale/owner-terminal outcome, a
	// typed failure class, or the clean-skip code; empty/nil without an
	// attempt.
	ResultCode  string     `json:"result_code,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	// EvidenceKnown is true only when the accepted success output was
	// positively matched to THIS attempt through the recorded output digest
	// (never joined on incident id alone), so Finding below is that
	// attempt's own recorded result — including a positively loaded EMPTY
	// hypothesis. False means evidence unavailable/unmatched: an absent
	// Finding then establishes nothing, neither a hypothesis nor its
	// absence.
	EvidenceKnown bool `json:"evidence_known,omitempty"`
	// Finding is the matched attempt's recorded result: Hypothesis is the
	// recorded root cause only (an analysis title is not a causal
	// hypothesis), Observations the recorded findings, Unknowns the recorded
	// verification limitations, AnalyzedAt the actual judgment time. Nil
	// when EvidenceKnown is false.
	Finding *FindingFacts `json:"finding,omitempty"`
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
	// EvidenceFingerprint is the same pre-truncation comparison provenance
	// IncidentAnalysis carries, for evidence that reaches materiality as a
	// completion instead of an overview entry. Projections carry it; the
	// MaterialCandidate handed to B4/B5 never does.
	EvidenceFingerprint string `json:"evidence_fingerprint,omitempty"`
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
	// CountKnown qualifies FiringCount on a first_execution_assurance
	// candidate only (lead decision B, round 2, 2026-09-09): true when
	// FiringCount is the exact, completely resolved frozen input count
	// (WorkProjection.InvestigatedCountKnown); false means the count is
	// UNKNOWN — FiringCount is then 0 and must not be rendered as a number.
	// Total stays the Situation total and is never the analyzed count or a
	// denominator. Every other candidate kind keeps FiringCount/Total's
	// existing source semantics and leaves this false.
	CountKnown bool `json:"count_known,omitempty"`
	// PreviousScope/Scope and PreviousUrgency/Urgency carry a material
	// scope or attention change that moved no member at all (R2 repair,
	// lead review 2026-09-09: S4-06's "scope-expanded" reply must not
	// vanish at B5's candidate-only eligibility interface just because the
	// same alerts are still firing). Both sides of a pair are populated
	// together, and only for a POSITIVE recorded change — an unchanged
	// scope, or a de-escalation, leaves them empty.
	PreviousScope   string `json:"previous_scope,omitempty"`
	Scope           string `json:"scope,omitempty"`
	PreviousUrgency string `json:"previous_urgency,omitempty"`
	Urgency         string `json:"urgency,omitempty"`
}

// LimitationFacts names one recorded investigation-ability limitation code
// (never free prose) and whether this candidate reports it appearing or
// clearing.
type LimitationFacts struct {
	Code    string `json:"code,omitempty"`
	Cleared bool   `json:"cleared,omitempty"`
}

// LimitationInvestigationUnavailable is the stable code for the one recorded
// limitation that has no WaitReason of its own: a member Incident's
// investigation became unavailable (OperatorBriefing.Unavailable rose), so
// the Situation's evidence coverage shrank without the contract itself
// blocking. It is a LimitationFacts.Code so B5's CommunicatedLimitationCodes
// can recognize and later clear it; borrowing an unrelated current WaitReason
// here would report the wrong obstacle (R4 repair, lead review 2026-09-09).
const LimitationInvestigationUnavailable = "investigation_unavailable"

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
	// Outcome is the per-incident completion provenance behind an
	// inconclusive_completion (or an EndedWork-sourced useful_finding)
	// candidate (lead decision D, round 2, 2026-09-09): the actual
	// incident/attempt identity, durable result code and completion time,
	// and whether the attempt's evidence was positively matched. B5 keys
	// repeat suppression on this identity, never on aggregate phase; B4
	// states the "checks not retained" limit when EvidenceKnown is false
	// instead of inventing checked sources. Its Finding is carried in the
	// candidate's own Finding field, not duplicated here. Nil on every
	// other candidate kind and on a legacy aggregate-only exhaustion edge.
	Outcome *IncidentWorkOutcome `json:"outcome,omitempty"`
}
