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
	// schedule has actually claimed an attempt (TriageState.Attempts > 0,
	// equivalently ActiveAttempt/LastExecution once a future chunk wires
	// their durable read) — NEVER inferred from a request or decision
	// alone, and NEVER from a clean skip (a skip is a decision, not an
	// attempt).
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
}
