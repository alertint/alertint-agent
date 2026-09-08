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
