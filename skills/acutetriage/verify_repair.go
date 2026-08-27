// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/alertint/alertint-agent/internal/llm"
	promclient "github.com/alertint/alertint-agent/internal/prometheus"
)

// verificationRepairMaxOutputTokens bounds the repair call's output on the
// wire (llm.Prompt.MaxOutputTokens may only LOWER the operator's configured
// ceiling). The reply is a handful of expressions and nothing else, so a tight
// cap is both sufficient and the thing that keeps a mis-behaving model from
// turning one syntax slip into an expensive generation.
const verificationRepairMaxOutputTokens = 512

// verificationRepairSystem is the repair call's whole job description: syntax
// only, JSON only, one object per input index. The semantic-preservation ask
// here is a courtesy to the model — it is NOT what enforces preservation;
// promclient.ValidateSyntaxRepair is (a model that ignores this instruction
// gets its "repair" rejected below, never executed).
const verificationRepairSystem = "You repair PromQL syntax. Return JSON only. Preserve each query's intent, metric names, label matchers, and time window unless syntax requires moving them. Return exactly one object per repaired input index; do not add queries."

// verificationRepairInstruction prefixes the marshalled issue list. It names
// the response shape inline so a model that ignores the system turn still has
// the contract in front of it.
const verificationRepairInstruction = "Repair only the listed invalid PromQL expressions. Keep every index unchanged. " +
	`Respond as {"queries":[{"index":0,"expr":"..."}]}.` + "\n\nInvalid queries:\n"

// promQLIssue is one invalid model-proposed query as the repair call sees it:
// its index in the round's model-query slice (the join key the reply must echo
// back), the expression, the model's own stated intent, and the parser's
// verdict on why it will not run.
type promQLIssue struct {
	Index int    `json:"index"`
	Expr  string `json:"expr"`
	Why   string `json:"why,omitempty"`
	Error string `json:"error"`
}

// repairEnvelope is the documented reply shape. Anything else it contains is
// ignored; anything missing simply leaves that index unrepaired.
type repairEnvelope struct {
	Queries []struct {
		Index int    `json:"index"`
		Expr  string `json:"expr"`
	} `json:"queries"`
}

// verificationRepairStats is the count-only record of one repair attempt:
// Attempted is how many locally invalid model PromQL queries went into the
// single batch call, Repaired how many came back genuinely fixed, Invalid how
// many were still unusable afterwards. Attempted == Repaired + Invalid always.
type verificationRepairStats struct {
	Attempted int
	Repaired  int
	Invalid   int
}

// repairPrompt renders the user turn: the fixed instruction plus the issue
// list as JSON.
func repairPrompt(issues []promQLIssue) string {
	body, err := json.Marshal(struct {
		Queries []promQLIssue `json:"queries"`
	}{Queries: issues})
	if err != nil {
		// Unreachable: every field of promQLIssue is a string or an int.
		return verificationRepairInstruction
	}
	return verificationRepairInstruction + string(body)
}

// repairModelPromQL gives every locally invalid model-proposed PromQL query in
// queries exactly ONE chance to be fixed, in a single batched LLM call, and
// returns the effective plan plus the counts of what happened.
//
// The one-call bound is the whole design (ADR-0043): a model that emits
// invalid PromQL will often emit invalid PromQL again, and a retry loop turns
// one bad draft into an unbounded spend on a query that is, by construction,
// optional evidence. So there is exactly one call and no second chance — not
// on a failed call, not on a malformed or truncated reply, not on a reply
// whose "repair" is still invalid. Whatever is not fixed by that one call is
// marked OutcomeInvalid (markInvalid) and never reaches the backend:
// runVerificationWith skips an already-invalid query outright, so it costs
// neither a request nor a slice of the round's timeout budget.
//
// A replacement must clear TWO gates, not one: promclient.ValidateExpr (it
// parses) AND promclient.ValidateSyntaxRepair (it is the same query). The
// second gate is what stops the failure mode that makes silent repair
// dangerous — a model "fixing" a query it cannot parse by substituting a
// metric it can, producing a perfectly valid query that answers a different
// question and then feeding that answer to the re-judge as if it were the
// evidence the draft asked for.
//
// Nothing outside an attempted index is touched: valid queries, every query's
// Kind/Source/Why/Params, the slice order, and the query count all survive
// verbatim (the returned slice is a copy, so the caller's input is left
// pristine either way). Never returns an error — a repair that cannot happen
// is a query that does not run, never a failed triage.
func (s *Skill) repairModelPromQL(ctx context.Context, incidentID string, queries []VerificationQuery) ([]VerificationQuery, verificationRepairStats) {
	var stats verificationRepairStats

	logger := s.logger
	if logger == nil {
		logger = slog.Default()
	}

	// Only model-proposed PromQL can be repaired: an incidents_in_window entry
	// carries no expression at all, and parseVerificationPlan already dropped
	// empty-expr promql entries and every kind outside the closed set.
	issues := make([]promQLIssue, 0, len(queries))
	parseErr := make(map[int]error, len(queries)) // doubles as the "was asked about" set
	for i := range queries {
		if queries[i].Kind != kindPromQL || queries[i].Expr == "" {
			continue
		}
		err := promclient.ValidateExpr(queries[i].Expr)
		if err == nil {
			continue
		}
		parseErr[i] = err
		issues = append(issues, promQLIssue{
			Index: i, Expr: queries[i].Expr, Why: queries[i].Why, Error: err.Error(),
		})
	}
	if len(issues) == 0 {
		// The overwhelmingly common case: no call, no audit row, no cost.
		return queries, stats
	}
	stats.Attempted = len(issues)
	out := slices.Clone(queries)

	comp, callErr := s.llm.Complete(ctx, verificationRepairSystem, llm.Prompt{
		Prefix:          repairPrompt(issues),
		MaxOutputTokens: verificationRepairMaxOutputTokens,
	}, []string{"queries"})

	// First nonblank entry wins per requested index: a duplicate for an index
	// already answered, a blank expression, and an index that was never asked
	// about (out of range, or pointing at a query that parsed fine) are all
	// ignored rather than trusted. A reply that cannot be decoded at all is
	// treated exactly like a failed call — no replacements, one call spent.
	replacements := make(map[int]string, len(issues))
	if callErr == nil {
		var env repairEnvelope
		if err := json.Unmarshal(comp.Raw, &env); err != nil {
			callErr = fmt.Errorf("malformed repair response: %w", err)
		} else {
			for _, r := range env.Queries {
				expr := strings.TrimSpace(r.Expr)
				if expr == "" {
					continue
				}
				if _, asked := parseErr[r.Index]; !asked {
					continue
				}
				if _, done := replacements[r.Index]; done {
					continue
				}
				replacements[r.Index] = expr
			}
		}
	}

	// Revalidate every attempted index once, after application. A replacement
	// is applied to Expr before it is judged, so the persisted query and the
	// WARN below both show the last expression actually tried rather than a
	// draft the repair already superseded — a rejected replacement is still
	// what the operator needs to see when asking why this check did not run.
	// It is never executed either way: markInvalid excludes it from the round.
	for _, iss := range issues {
		i := iss.Index
		original := out[i].Expr
		err := parseErr[i] // the standing verdict when no replacement was offered
		if repaired, ok := replacements[i]; ok {
			out[i].Expr = repaired
			if err = promclient.ValidateExpr(repaired); err == nil {
				err = promclient.ValidateSyntaxRepair(original, repaired)
			}
		}
		if err == nil {
			stats.Repaired++
			continue
		}
		markInvalid(&out[i])
		stats.Invalid++
		logger.Warn("acutetriage: verify: model promql invalid after one repair; not executed",
			"incident", incidentID, "expr", out[i].Expr, "err", err, "repair_err", callErr)
	}

	// Counts only — never an expression, a parser string, or model output
	// (R4/KTD6, same rule the planned/executed rows follow).
	if s.auditor != nil {
		_ = s.auditor.Append(ctx, "skill:acute-triage", "incident.verification_repair", map[string]any{
			"incident_id":          incidentID,
			"attempted":            stats.Attempted,
			"repaired":             stats.Repaired,
			"invalid_after_repair": stats.Invalid,
		})
	}
	return out, stats
}
