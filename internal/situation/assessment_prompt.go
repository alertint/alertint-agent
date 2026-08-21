// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"encoding/json"

	"github.com/alertint/alertint-agent/internal/llm"
	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// AssessmentSystemPrompt is the fixed L2 system prompt. It names the strict
// output schema and the boundary the validator enforces, so a compliant
// model minimizes rejected proposals rather than relying on the validator as
// a silent filter.
const AssessmentSystemPrompt = `You are the Situation controller's L2 judgment step for one AlertINT Situation.
You receive only typed, already-reduced evidence — never raw connector payloads or free-form alert text.

You MUST respond with ONLY a valid JSON object — no prose, no markdown fences — conforming exactly to the
authoritative Assessment schema (schema_version, persistence, impact, novelty, causality, attention, lifecycle,
evidence_quality, sufficient_reason, action_contract, limitations, proposed_cadence).

Hard rules the validator enforces and will reject or deterministically correct a violation of:
- lifecycle must exactly echo the input's current controller lifecycle; you cannot change it.
- sufficient_reason.candidate_id, when the publication is not "observe", MUST be copied verbatim from one entry
  in eligible_reasons. You cannot invent a reason, combine codes into a new one, or cite evidence outside a
  listed candidate.
- attention "urgent" requires a deterministic floor candidate (deterministic_floor=true) among eligible_reasons;
  you can explain a floor, you cannot mint one. Conversely, if a deterministic floor is eligible, attention will
  be forced to "urgent" regardless of what you propose — propose it explicitly.
- causality "supported" requires an eligible sufficient_reason; temporal co-occurrence alone is "correlated".
- action_contract.action_status "running" requires next_actor "alertint" and a non-empty alertint_action.
- next_actor "none" carries no alertint_action/operator_action_required/operator_judgment_requested;
  next_actor "alertint" carries no operator fields; next_actor "operator" carries no alertint_action.
- a nonterminal lifecycle (active, recovery_pending) requires a future next_update_at; a terminal lifecycle
  (recovered, closed_unknown) carries neither next_update_at nor next_update_on.
- only capability names listed in allowed_capabilities may be named as a next useful bounded observation.`

// AssessmentRequiredKeys are the top-level JSON keys a proposal must include.
// sufficient_reason is intentionally absent: an "observe" publication needs
// none.
var AssessmentRequiredKeys = []string{
	"schema_version", "persistence", "impact", "novelty", "causality", "attention",
	"lifecycle", "evidence_quality", "action_contract", "limitations", "proposed_cadence",
}

// AssessmentPromptPayload is the strict, closed input the L2 prompt renders
// as JSON. It carries exactly what the spec allows: typed facts, eligible
// reason candidates, the current controller lifecycle, the prior trusted
// Assessment (nil on the first attempt), and the allowed capability names —
// nothing else. Raw payloads, prose, and Slack presentation never appear
// here because Snapshot itself already excludes them.
type AssessmentPromptPayload struct {
	Facts                  []observationmodel.Fact `json:"facts"`
	EligibleReasons        []model.ReasonCandidate `json:"eligible_reasons"`
	Lifecycle              model.Lifecycle         `json:"lifecycle"`
	PriorTrustedAssessment *model.Assessment       `json:"prior_trusted_assessment,omitempty"`
	AllowedCapabilities    []string                `json:"allowed_capabilities"`
}

// BuildAssessmentPrompt renders the strict L2 prompt for one immutable
// snapshot. prior is the last authoritative, trustworthy Assessment (nil on
// the first attempt for this Situation); allowedCapabilities names the
// bounded observation capabilities this install has configured.
func BuildAssessmentPrompt(snapshot Snapshot, prior *model.Assessment, allowedCapabilities []string) llm.Prompt {
	payload := AssessmentPromptPayload{
		Facts:                  snapshot.Facts,
		EligibleReasons:        snapshot.EligibleReasons,
		Lifecycle:              snapshot.Lifecycle,
		PriorTrustedAssessment: prior,
		AllowedCapabilities:    canonicalStrings(allowedCapabilities),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		// Marshal of a closed, already-canonicalized struct cannot fail in
		// practice; an empty object keeps the caller's contract total rather
		// than panicking on an unreachable path.
		body = []byte(`{}`)
	}
	return llm.Prompt{Prefix: string(body)}
}
