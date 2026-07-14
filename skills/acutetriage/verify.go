// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"encoding/json"
	"log/slog"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

// VerificationParams carries the skill-side tunables (from config Task 1).
type VerificationParams struct {
	Enabled             bool
	MaxQueries          int
	QueryTimeoutSeconds int
}

// Query kinds. The floor uses up_ratio + incidents_in_window; the model may
// propose promql and incidents_in_window ONLY (closed set, R4).
const (
	kindPromQL            = "promql"
	kindUpRatio           = "up_ratio"
	kindIncidentsInWindow = "incidents_in_window"
)

// VerificationQuery is one planned/executed query, persisted verbatim (R8/R10).
type VerificationQuery struct {
	Kind    string         `json:"kind"`
	Source  string         `json:"source"` // "model" | "floor"
	Expr    string         `json:"expr,omitempty"`
	Params  map[string]any `json:"params,omitempty"`
	Why     string         `json:"why,omitempty"`
	Outcome Outcome        `json:"outcome,omitempty"` // fetched|empty|degraded|failed (evidence.go)
	Result  string         `json:"result,omitempty"`  // rendered text, byte-identical to prompt (R8)
}

// VerificationRound is one executed round (R8).
type VerificationRound struct {
	At      time.Time           `json:"at"`
	Draft   DraftRef            `json:"draft"`
	Queries []VerificationQuery `json:"queries"`
}

type DraftRef struct {
	RootCause  string  `json:"root_cause"`
	Confidence float64 `json:"confidence"`
}

// VerificationEnrichment is the envelope key "verification" (R8).
type VerificationEnrichment struct {
	Outcome string              `json:"outcome"` // supported | revised | degraded
	Rounds  []VerificationRound `json:"rounds"`
}

// broadScopeKeys are the shared-label keys wide enough to define a peer scope
// (grill 2026-07-14): the floor drops narrow identity (pod/container/instance)
// so the ratio covers peers, not just the incident's own targets.
var broadScopeKeys = []string{"namespace", "service", "job"}

// parentScope derives a Prometheus matcher over the incident's shared
// broad-scope labels (namespace/service/job) — the peer scope the floor's
// up_ratio query runs against. Narrow identity labels (pod/container/instance)
// are dropped even when shared, so a host-only alert yields "" (unscoped —
// the caller falls back to a global ratio) rather than a matcher that is
// really just the incident's own target.
func parentScope(alerts []store.Alert) string {
	shared := sharedLabelValues(alerts)
	scope := map[string][]string{}
	for _, k := range broadScopeKeys {
		if vs, ok := shared[k]; ok && len(vs) > 0 {
			scope[k] = vs
		}
	}
	return renderPromMatcher(scope)
}

// floorPlan returns the two queries that ALWAYS run in a verification round,
// regardless of what the model proposes: peer-scope up_ratio and
// incidents_in_window. Both are Source: "floor" — never subject to the
// model's query cap or the closed-kind-set filter in parseVerificationPlan.
func floorPlan(alerts []store.Alert) []VerificationQuery {
	return []VerificationQuery{
		{Kind: kindUpRatio, Source: "floor", Expr: parentScope(alerts),
			Why: "peer-scope health: is the wider world up?"},
		{Kind: kindIncidentsInWindow, Source: "floor",
			Params: map[string]any{"window_minutes": float64(60)},
			Why:    "is anything else firing?"},
	}
}

// verificationPlanEnvelope is the shape parseVerificationPlan extracts out of
// the model's draft JSON response — just the "verification.queries" slice;
// every other draft key is ignored here.
type verificationPlanEnvelope struct {
	Verification *struct {
		Queries []VerificationQuery `json:"queries"`
	} `json:"verification"`
}

// parseVerificationPlan parses and sanitizes the model's own proposed
// verification queries out of its draft JSON response. A malformed
// verification block (bad JSON, "queries" not a list) degrades to nil
// (floor-only) rather than erroring — the floor queries always run
// regardless (R1). Kinds are filtered to the closed set the model may
// propose (promql, incidents_in_window — R4; up_ratio is floor-only and
// never model-proposable); empty-expr promql entries are dropped; every
// surviving query is force-labeled Source: "model"; the list is capped at
// maxQueries with the drop count logged (no silent caps, R3).
func parseVerificationPlan(raw json.RawMessage, maxQueries int, logger *slog.Logger, incidentID string) []VerificationQuery {
	if logger == nil {
		logger = slog.Default()
	}

	var env verificationPlanEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		logger.Warn("acutetriage: verify: malformed verification block, falling back to floor-only",
			"err", err, "incident", incidentID)
		return nil
	}
	if env.Verification == nil {
		return nil
	}

	filtered := make([]VerificationQuery, 0, len(env.Verification.Queries))
	for _, q := range env.Verification.Queries {
		switch q.Kind {
		case kindPromQL:
			if q.Expr == "" {
				continue
			}
		case kindIncidentsInWindow:
			// no expr required
		default:
			continue
		}
		q.Source = "model"
		filtered = append(filtered, q)
	}

	if len(filtered) > maxQueries {
		dropped := len(filtered) - maxQueries
		logger.Warn("acutetriage: verify: capping model-proposed verification queries",
			"proposed", len(filtered), "kept", maxQueries, "dropped", dropped, "incident", incidentID)
		filtered = filtered[:maxQueries]
	}

	return filtered
}
