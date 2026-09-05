// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Task 5: L2 Assessment prompt construction. Prompts only from the bounded
// Snapshot DTO — no raw delivery payloads, Slack content, SQL, secrets, or
// historical rejected-proposal prose reach this function's signature, so
// none of it can leak into the prompt by construction.
// ----------------------------------------------------------------------

// assessmentPromptSchemaVersion tracks this file's own prompt shape/wording.
// A future task bumps it (never silently) when the instructions or the
// snapshot projection change in a way that should invalidate any cached
// prompt-hash comparison.
const assessmentPromptSchemaVersion = 1

// assessmentPromptMaxOutputTokens bounds the semantic-proposal JSON reply.
// The proposal schema is small and fixed; this is a Task 5 default, not a
// spec-mandated number.
const assessmentPromptMaxOutputTokens = 800

// assessmentPromptDTO is the ONLY content BuildAssessmentPrompt ever
// marshals into the prompt body — a deliberately narrower projection than
// Snapshot itself: it excludes MaterialFactHash/AssessmentBasisHash (Task 5's
// own internal reuse-guard bookkeeping, meaningless to the model and not
// needed for its judgment). Every field here is already one of Task 4's
// bounded, closed-shape reductions (facts, symptoms, eligible reason
// candidates, Incident/Triage summaries) — none of them carry raw delivery
// payloads, Slack content, SQL, or secrets.
type assessmentPromptDTO struct {
	SchemaVersion   int                     `json:"schema_version"`
	SituationID     string                  `json:"situation_id"`
	InputVersion    int                     `json:"input_version"`
	Lifecycle       model.Lifecycle         `json:"lifecycle"`
	ElapsedSeconds  int64                   `json:"elapsed_seconds"`
	DurationClass   string                  `json:"duration_class"`
	Facts           []model.Fact            `json:"facts"`
	Symptoms        []Symptom               `json:"symptoms"`
	Incidents       []IncidentState         `json:"incidents"`
	EligibleReasons []model.ReasonCandidate `json:"eligible_reasons"`
}

func newAssessmentPromptDTO(snap Snapshot) assessmentPromptDTO {
	return assessmentPromptDTO{
		SchemaVersion:   assessmentPromptSchemaVersion,
		SituationID:     snap.SituationID,
		InputVersion:    snap.InputVersion,
		Lifecycle:       snap.Lifecycle,
		ElapsedSeconds:  snap.ElapsedSeconds,
		DurationClass:   snap.DurationClass,
		Facts:           snap.Facts,
		Symptoms:        snap.Symptoms,
		Incidents:       snap.Incidents,
		EligibleReasons: snap.EligibleReasons,
	}
}

// assessmentPromptPreamble introduces the bounded snapshot body below.
const assessmentPromptPreamble = `You are AlertINT's Situation Assessment judge.

You are given one Situation's bounded, deterministic snapshot as JSON below —
its immutable material facts, active symptoms, member Incidents, and the
closed set of eligible Sufficient-reason candidates the controller has
already deterministically proven admissible for this exact snapshot. This is
the entire evidentiary basis; nothing outside it exists for this judgment.

Situation snapshot:
`

// assessmentSchemaInstructions states the exact response schema and the
// controller-exclusive fields the model must never author. It spells out the
// nested shapes of sufficient_reason and limitations explicitly: the first
// live lab run (2026-09-04) showed a model reading the bare "null" / "[]"
// placeholders as "a candidate ID string" and "free-text strings", which
// ValidateAssessmentProposal rejects as invalid_shape on every call — a
// prompt-contract gap, not a model fault, so the contract is stated in full.
// The allowed limitation codes are rendered from the same list the
// validator checks (knownLimitationCode), so the two can never drift.
const assessmentSchemaInstructions = `
Respond with exactly one JSON object matching this schema and nothing else —
no markdown fence, no commentary. Every value must have exactly the JSON type
shown; there are no other fields:

{
  "schema_version": 1,
  "persistence": "transient | sustained | unknown",
  "impact": "none_observed | suspected | confirmed | unknown",
  "novelty": "familiar | changed | new | insufficient_history",
  "causality": "supported | correlated | contradicted | unknown | operator_confirmed",
  "attention": "observe | investigate | urgent",
  "sufficient_reason": null,
  "limitations": []
}

sufficient_reason is either JSON null or exactly ONE object of this shape —
never a bare string, never an array:

  {"code": "<candidate code>", "candidate_id": "<candidate id, verbatim>",
   "summary": "<one bounded sentence>", "evidence_refs": ["<fact id>", ...]}

It must name exactly one candidate already listed in this snapshot's
eligible_reasons above — copy both that candidate's "code" and its "id"
verbatim; you may select and explain only an eligible candidate. evidence_refs
may be empty and may contain only "id" values of entries in this snapshot's
facts. You may never invent a reason ID or evidence reference not present in
this snapshot.

limitations is an array (possibly empty) of objects of this shape — never bare
strings:

  {"code": "<one of the allowed codes>", "detail": "<one bounded sentence>"}

The only allowed limitation codes are:
%s
A limitation with any other code is rejected. Use [] when none applies; do not
restate a capability_limitation fact that is already in the snapshot unless it
bears on your judgment.

Every "summary" and "detail" must be at most %d characters.

The following fields are FORBIDDEN in your response and will be rejected if
present: "lifecycle", "action_contract", and "cadence". The controller
derives these exclusively; do not propose them under any name or nesting.

Ground every claim stronger than "unknown" in the snapshot's own evidence.
Never claim urgent attention unless the snapshot proves a deterministic
urgent anchor. Never present mere temporal overlap as a supported cause.`

// promptLimitationCodes lists the limitation codes the schema instructions
// offer the model: every capability limitation this build knows
// (plan2UnsupportedCapabilities) — the same set knownLimitationCode accepts,
// minus semantic_assessment_unavailable, which is the controller's own
// fallback marker and never a model claim.
func promptLimitationCodes() []string {
	codes := make([]string, 0, len(plan2UnsupportedCapabilities))
	for _, l := range plan2UnsupportedCapabilities {
		codes = append(codes, l.Code)
	}
	return codes
}

func renderAssessmentSchemaInstructions() string {
	var b strings.Builder
	for _, code := range promptLimitationCodes() {
		b.WriteString("  ")
		b.WriteString(code)
		b.WriteString("\n")
	}
	return fmt.Sprintf(assessmentSchemaInstructions, b.String(), maxBoundedTextLength)
}

// BuildAssessmentPrompt renders the L2 Assessment prompt from snap alone.
// CachePrefix is set: the snapshot body is stable across a controller
// attempt's calls (draft, and — for a non-contradicted proposal — a
// verification call), so it is the natural client-side cache breakpoint.
func BuildAssessmentPrompt(snap Snapshot) (llm.Prompt, error) {
	body, err := json.MarshalIndent(newAssessmentPromptDTO(snap), "", "  ") //nolint:musttag // Symptom/IncidentState (snapshot.go, Task 3/4) have no json tags yet; encoding/json's default capitalized-field marshaling is already exercised and asserted by this file's tests
	if err != nil {
		return llm.Prompt{}, fmt.Errorf("situation: marshal assessment prompt snapshot: %w", err)
	}
	prefix := assessmentPromptPreamble + string(body) + "\n" + renderAssessmentSchemaInstructions()
	return llm.Prompt{
		Prefix:          prefix,
		CachePrefix:     true,
		MaxOutputTokens: assessmentPromptMaxOutputTokens,
	}, nil
}
