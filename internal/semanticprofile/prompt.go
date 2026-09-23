// SPDX-License-Identifier: FSL-1.1-ALv2

package semanticprofile

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/alertint/alertint-agent/internal/llm"
	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
)

// ----------------------------------------------------------------------
// Plan 4 Task 8: L0 semantic-profile inference prompt construction. Prompts
// only from the frozen semantic input (source, alert name, proven signal
// identity, sorted label/annotation key schema — never concrete label
// values, arrival clocks, fingerprints, or run IDs; see
// profilemodel.SignatureInput's own doc comment) — the same bounded input
// every job freezes once at creation. No tools, no recursive calls, no
// model-authored queries are ever offered.
// ----------------------------------------------------------------------

// inferencePromptMaxOutputTokens bounds the profile JSON reply — the
// closed eight-field schema is small and fixed, well under this ceiling.
const inferencePromptMaxOutputTokens = 600

const inferencePromptPreamble = `You are AlertINT's advisory semantic-profile analyst.

You are given the bounded, immutable identity of ONE alert-generating source
below — its source adapter, rule/alert name, proven signal identity when the
adapter could prove one, and the SORTED KEY NAMES (never the values) of its
labels and annotations. This is the entire evidentiary basis; nothing outside
it exists for this judgment. Your output is purely ADVISORY interpretation
guidance for a later evidence-preparation stage — it can never assert that any
particular alert is currently firing or resolved, grant investigative
authority, or take any action.

Source identity:
`

const inferenceSchemaInstructions = `
Respond with exactly one JSON object matching this schema and nothing else —
no markdown fence, no commentary. Every value must have exactly the JSON type
shown; there are no other fields, no tools, no recursive calls, and no
model-authored queries of any kind:

{
  "subject_kind": "<bounded phrase, e.g. \"service\" or \"host\">",
  "event_kind": "<bounded phrase, e.g. \"availability\" or \"latency\">",
  "possible_role": "<bounded phrase, e.g. \"symptom\" or \"cause\">",
  "candidate_scope": ["<existing configured label-key name>", ...],
  "companion_signal_kinds": ["<bounded phrase>", ...],
  "horizon_tier": "%s",
  "useful_capabilities": ["<capability name>", ...],
  "uncertainty": ["<bounded sentence>", ...]
}

subject_kind, event_kind, and possible_role are required, non-empty, bounded
advisory strings (at most %d characters each). candidate_scope and
companion_signal_kinds are arrays of at most %d bounded strings each (%d
characters max per entry) — candidate_scope names only EXISTING configured
label keys, never a new resource value. horizon_tier must be exactly one of:
%s
useful_capabilities is an array of at most %d entries, each exactly one of
these closed capability names:
%s
uncertainty is an array of at most %d bounded sentences (%d characters max
each) — use [] when you have none.

This is advisory interpretation only: it can widen how long a later stage
waits for lifecycle evidence, never shorten it, assert a firing/resolved
observation, renew an observation timestamp, or erase a source failure. It
carries no policy, action, or envelope authority of any kind.`

// horizonTiersInOrder is the fixed, human-readable rendering order for the
// four closed horizon values.
var horizonTiersInOrder = []string{
	profilemodel.HorizonUnknown, profilemodel.HorizonMinutes, profilemodel.HorizonHours, profilemodel.HorizonDays,
}

// capabilityNamesInOrder is the fixed rendering order for the seven closed
// capability names — mirrors internal/observation/model's own catalog order.
var capabilityNamesInOrder = []string{
	profilemodel.CapabilityStoreRead, profilemodel.CapabilityPrometheusQuery, profilemodel.CapabilityZabbixMetricRange,
	profilemodel.CapabilityZabbixProblemHist, profilemodel.CapabilityLokiQuery, profilemodel.CapabilitySentryIssues,
	profilemodel.CapabilityChangeEvents,
}

func renderInferenceSchemaInstructions() string {
	return fmt.Sprintf(inferenceSchemaInstructions,
		strings.Join(horizonTiersInOrder, "|"),
		profilemodel.MaxMeaningFieldChars, profilemodel.MaxArrayValues, profilemodel.MaxMeaningFieldChars,
		indentedList(horizonTiersInOrder),
		profilemodel.MaxArrayValues, indentedList(capabilityNamesInOrder),
		profilemodel.MaxArrayValues, profilemodel.MaxUncertaintyChars,
	)
}

func indentedList(values []string) string {
	var b strings.Builder
	for _, v := range values {
		b.WriteString("  ")
		b.WriteString(v)
		b.WriteString("\n")
	}
	return b.String()
}

// BuildInferencePrompt renders the L0 semantic-profile inference prompt
// from frozenInputJSON alone — the exact frozen semantic input a job's
// FrozenInputJSON carries (profilemodel.SignatureInput, marshaled).
// CachePrefix is set: the source-identity body is fixed for every attempt
// this job ever makes, so it is the natural client-side cache breakpoint.
func BuildInferencePrompt(frozenInputJSON json.RawMessage) (llm.Prompt, error) {
	var in profilemodel.SignatureInput
	if err := json.Unmarshal(frozenInputJSON, &in); err != nil {
		return llm.Prompt{}, fmt.Errorf("semanticprofile: unmarshal frozen input for prompt: %w", err)
	}
	body, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return llm.Prompt{}, fmt.Errorf("semanticprofile: marshal frozen input for prompt: %w", err)
	}
	prefix := inferencePromptPreamble + string(body) + "\n" + renderInferenceSchemaInstructions()
	return llm.Prompt{
		Prefix:          prefix,
		CachePrefix:     true,
		MaxOutputTokens: inferencePromptMaxOutputTokens,
	}, nil
}
