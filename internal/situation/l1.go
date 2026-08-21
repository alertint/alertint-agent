// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

// AcuteResult is the bounded acute-triage finding an L1 investigation
// produces. It mirrors acutetriage.Result field-for-field; this package
// cannot import skills/acutetriage (that package's Investigate takes a
// store.Incident, and internal/store already imports internal/situation —
// importing it back would cycle), so the concrete adapter that turns a
// store.Incident into an incidentID call and an acutetriage.Result into this
// type lives outside this package.
type AcuteResult struct {
	IncidentID     string
	OutputJSON     json.RawMessage
	Summary        string
	RootCause      string
	Confidence     float64
	EnrichmentJSON string
	CompletedAt    time.Time
}

// AcuteInvestigator is the interface the B+ gate dispatches through. Its
// result is durable evidence only: L1 findings carry no Attention or
// notification authority (D2) — only a validated L2 Assessment does.
type AcuteInvestigator interface {
	Investigate(ctx context.Context, incidentID string) (AcuteResult, error)
}

// L1Status is the closed acute-analysis gate state persisted per Incident
// (incident_analysis_state.status). An omitted finding is never ambiguous.
type L1Status string

const (
	L1StatusNotRequested L1Status = "not_requested"
	L1StatusPlanned      L1Status = "planned"
	L1StatusRunning      L1Status = "running"
	L1StatusComplete     L1Status = "complete"
	L1StatusBlocked      L1Status = "blocked"
	L1StatusExhausted    L1Status = "exhausted"
)

// Closed B+ decision-reason codes. They name why focused acute analysis
// could have decision value (or, for the one skip reason, why it could not).
const (
	L1ReasonCoveredUnchanged      = "covered_unchanged_fact_hash"
	L1ReasonNovelOrChangedSymptom = "novel_or_changed_symptom"
	L1ReasonEnvelopeViolation     = "envelope_violation_mechanism"
	L1ReasonOperatorOwnership     = "operator_ownership_value"
	L1ReasonManualReassessment    = "manual_reassessment"
	L1ReasonMaterialChange        = "material_fact_hash_changed"
)

// TrustedAssessment is the prior authoritative Assessment the B+ gate
// consults. Only its covered material hash, Assessment sequence, and
// trustworthiness matter — an untrustworthy (e.g. deterministic-floor
// degraded, or a prior attempt that itself exhausted) prior Assessment can
// never justify a skip.
type TrustedAssessment struct {
	Sequence    int
	FactHash    string
	Trustworthy bool
}

// L1Decision is the persisted B+ gate outcome.
type L1Decision struct {
	Status          L1Status
	DecisionReason  string
	CoveredSequence int
}

// DecideL1 implements the B+ gate (D2): L1 is requested for any material
// causality/explanation/ownership value, novel or changed symptom,
// conflicting facts, envelope-violation mechanism, new semantic signature,
// useful bounded observation, or manual reassessment; it skips only when a
// trustworthy Assessment already covers an unchanged material fact hash. New
// Incident identity or an unchanged alert name alone never proves an
// unchanged fact set — MaterialFactHash already excludes both by
// construction, so hash equality against a trustworthy prior Assessment is
// the only skip test. Manual reassessment (a due reason on the claimed
// Situation, not the Snapshot itself) is applied by the caller: it forces a
// planned decision even over an otherwise-covered hash.
func DecideL1(snapshot Snapshot, trusted TrustedAssessment) L1Decision {
	if trusted.Trustworthy && trusted.FactHash != "" && trusted.FactHash == snapshot.MaterialHash {
		return L1Decision{Status: L1StatusNotRequested, DecisionReason: L1ReasonCoveredUnchanged, CoveredSequence: trusted.Sequence}
	}
	return L1Decision{Status: L1StatusPlanned, DecisionReason: l1TriggerReason(snapshot), CoveredSequence: trusted.Sequence}
}

// l1TriggerReason names the most specific eligible-reason category the
// current snapshot already surfaces, falling back to a generic material
// change when no closed category applies (e.g. the very first assessment).
func l1TriggerReason(snapshot Snapshot) string {
	for _, reason := range snapshot.EligibleReasons {
		switch reason.Code {
		case "novel_symptom":
			return L1ReasonNovelOrChangedSymptom
		case "envelope_violation":
			return L1ReasonEnvelopeViolation
		case "operator_judgment_needed":
			return L1ReasonOperatorOwnership
		}
	}
	return L1ReasonMaterialChange
}

// NormalizeL1 reduces a raw AcuteResult into the material L1Output
// BuildSnapshot consumes. Prose (Summary, the full OutputJSON) and raw model
// confidence never enter the material fact hash — Snapshot.L1 keeps them only
// as closed classes (status/root-cause class), and MaterialFactHash's L1
// subset (L1Finding) drops even the confidence class. This is what makes a
// "wasted" L1 run — one whose classified conclusion did not change — produce
// an unchanged material hash and therefore never force L2 reassessment.
func NormalizeL1(result AcuteResult) L1Output {
	status := "conclusive"
	rootClass := "identified"
	if strings.TrimSpace(result.RootCause) == "" {
		status = "inconclusive"
		rootClass = "unknown"
	}
	return L1Output{
		Status:          status,
		Summary:         result.Summary,
		RootCauseClass:  rootClass,
		ConfidenceClass: classifyL1Confidence(result.Confidence),
	}
}

func classifyL1Confidence(confidence float64) string {
	switch {
	case confidence >= 0.8:
		return "high"
	case confidence >= 0.5:
		return "medium"
	default:
		return "low"
	}
}
