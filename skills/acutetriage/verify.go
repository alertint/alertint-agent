// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

// VerificationParams carries the skill-side tunables (from config Task 1).
//
// MaxSeries decision (Task 4): threaded as its own field here rather than
// reusing MetricParams, because runVerification never receives a MetricParams
// value (its signature only takes VerificationParams — see the plan's
// Interfaces block) and this package's Prometheus concerns should stay
// confined to the struct that already carries every other verification tunable
// rather than reaching into an unrelated call's param type. At wiring time
// (Task 6) this is fed from the SAME config field FetchMetrics uses:
// prometheus.max_series — model-proposed promql shares the identical
// server-side series bound as metric enrichment.
type VerificationParams struct {
	Enabled             bool
	MaxQueries          int
	QueryTimeoutSeconds int
	MaxSeries           int
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

// Verification-round outcomes (VerificationEnrichment.Outcome). degraded flags a
// finding that shipped without a full falsification pass — the floor could not
// fetch, or the re-judge call was lost — and drives Finding.Unverified.
const (
	verifyOutcomeSupported = "supported"
	verifyOutcomeRevised   = "revised"
	verifyOutcomeDegraded  = "degraded"
)

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
	Verification *verificationPlan `json:"verification"`
}

// verificationPlan accepts both shapes models emit for the "verification"
// value: the documented envelope {"queries":[...]} and a bare [...] list
// (seen in production under v0.8.0 — a strict object-only unmarshal degraded
// every such plan to floor-only).
type verificationPlan struct {
	Queries []VerificationQuery `json:"queries"`
}

func (p *verificationPlan) UnmarshalJSON(data []byte) error {
	if trimmed := bytes.TrimSpace(data); len(trimmed) > 0 && trimmed[0] == '[' {
		return json.Unmarshal(trimmed, &p.Queries)
	}
	type plain verificationPlan // drop the method, avoid recursion
	return json.Unmarshal(data, (*plain)(p))
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

// verifyStateReader is the narrow store surface the incidents_in_window query
// needs. *store.Store satisfies it; tests inject a fake (mirrors MemoryReader
// / SentryReader).
type verifyStateReader interface {
	IncidentsInWindow(ctx context.Context, since time.Time,
		excludeIncidentID, excludeGroupKey string, excludeDrills bool, limit int,
	) (int, []store.WindowIncident, error)
}

// defaultWindowMinutes is the incidents_in_window lookback when a query's
// Params carries no valid window_minutes (R4 default).
const defaultWindowMinutes = 60

// runVerification executes the floor queries (always: peer up-ratio +
// cross-incident scan) plus every model-proposed query, each under its own
// slice of the shared query-phase budget, filling Outcome and Result on every
// query (R2/R3). Never returns an error — a query's own failure lands in its
// Outcome/Result, it never aborts the round or the ones after it.
//
// The pipeline (verifyAndRejudge) passes the real skill logger; the runner tests
// pass nil (defaulted to slog.Default below).
func runVerification(ctx context.Context, prom metricQuerier, state verifyStateReader,
	params VerificationParams, inc store.Incident, alerts []store.Alert,
	draft DraftRef, modelQueries []VerificationQuery, now time.Time, logger *slog.Logger,
) *VerificationRound {
	if logger == nil {
		logger = slog.Default()
	}

	queries := make([]VerificationQuery, 0, 2+len(modelQueries))
	queries = append(queries, floorPlan(alerts)...)
	queries = append(queries, modelQueries...)

	// Two-layer budget, mirroring FetchMetrics exactly (metrics.go:361-374):
	// an outer queryPhaseCtx caps the WHOLE query phase at QueryTimeoutSeconds
	// regardless of how the caller's ctx is scoped, and each query additionally
	// gets its own slice of that budget so one slow or hung query times out on
	// its own share instead of starving the rest of the round. A purely
	// sequential loop dividing the budget N ways would already sum to at most
	// the total (integer division only trims remainder nanoseconds, never
	// grows it), but the outer ctx is kept anyway as the same hard ceiling
	// FetchMetrics relies on — belt-and-braces against a future refactor (e.g.
	// concurrent queries) silently breaking that invariant. len(queries) is
	// never 0 — floorPlan always contributes its two entries.
	budget := time.Duration(params.QueryTimeoutSeconds) * time.Second
	queryPhaseCtx, phaseCancel := context.WithTimeout(ctx, budget)
	defer phaseCancel()
	perQuery := budget / time.Duration(len(queries))

	for i := range queries {
		qCtx, cancel := context.WithTimeout(queryPhaseCtx, perQuery)
		runOneQuery(qCtx, prom, state, &queries[i], inc, now, params.MaxSeries, logger)
		cancel()
	}

	return &VerificationRound{At: now, Draft: draft, Queries: queries}
}

// runOneQuery dispatches one query to its kind-specific executor, filling its
// Outcome and Result in place. The closed kind set (kindUpRatio,
// kindIncidentsInWindow, kindPromQL) is enforced upstream — floorPlan only
// ever emits the first two, parseVerificationPlan only ever lets the latter
// two through — so the default branch below is unreachable in practice; it
// exists as a fail-safe rather than a silent no-op if that ever changes.
func runOneQuery(ctx context.Context, prom metricQuerier, state verifyStateReader,
	q *VerificationQuery, inc store.Incident, now time.Time, maxSeries int, logger *slog.Logger,
) {
	switch q.Kind {
	case kindUpRatio:
		runUpRatio(ctx, prom, q, now, logger, inc.ID)
	case kindIncidentsInWindow:
		runIncidentsInWindow(ctx, state, q, inc, now, logger)
	case kindPromQL:
		runPromQL(ctx, prom, q, maxSeries, now, logger, inc.ID)
	default:
		q.Outcome = OutcomeFailed
		q.Result = renderUnavailable("unsupported query kind")
		logger.Warn("acutetriage: verify: unsupported query kind", "kind", q.Kind, "incident", inc.ID)
	}
}

// runUpRatio executes the floor's peer-scope health check: sum(up{scope}) and
// count(up{scope}) as two instant queries sharing this query's one budget
// slice (never a series dump — always an aggregate pair, D7). scope is the
// query's Expr, set by floorPlan to parentScope(alerts); "" renders an
// unscoped global ratio rather than a matcher that is really just the
// incident's own target.
func runUpRatio(ctx context.Context, prom metricQuerier, q *VerificationQuery, now time.Time, logger *slog.Logger, incidentID string) {
	if prom == nil {
		q.Outcome = OutcomeFailed
		q.Result = renderUnavailable("prometheus not configured")
		return
	}
	scope := q.Expr
	sumData, sumErr := prom.QueryInstant(ctx, "sum(up"+scope+")", now, 0)
	countData, countErr := prom.QueryInstant(ctx, "count(up"+scope+")", now, 0)
	if sumErr != nil || countErr != nil {
		logger.Warn("acutetriage: verify: up_ratio query failed", "scope", scope, "sum_err", sumErr, "count_err", countErr, "incident", incidentID)
		classifyPairErrs(q, sumErr, countErr)
		return
	}

	sumVal, sumOK := firstInstantValue(sumData)
	countVal, countOK := firstInstantValue(countData)
	if !sumOK || !countOK {
		q.Outcome = OutcomeEmpty
		q.Result = "(no data)"
		return
	}
	q.Outcome = OutcomeFetched
	if scope == "" {
		q.Result = capText(flattenRecalled(fmt.Sprintf("up %s/%s (all targets)", sumVal, countVal)), 400)
	} else {
		q.Result = capText(flattenRecalled(fmt.Sprintf("up %s/%s in %s", sumVal, countVal, scope)), 400)
	}
}

// runIncidentsInWindow executes the floor's own-state contrast check (also
// the model's only permitted named state query): is anything else firing on a
// different group key right now? Render per spec R4 — the count, then up to 5
// group keys with severity and status, folded into a "+N more" line; never
// another incident's finding text.
func runIncidentsInWindow(ctx context.Context, state verifyStateReader, q *VerificationQuery, inc store.Incident, now time.Time, logger *slog.Logger) {
	if state == nil {
		q.Outcome = OutcomeFailed
		q.Result = renderUnavailable("state store not configured")
		return
	}
	windowMinutes := windowMinutesFromParams(q.Params)
	since := now.Add(-time.Duration(windowMinutes) * time.Minute)
	total, top, err := state.IncidentsInWindow(ctx, since, inc.ID, inc.GroupKey, true, 5)
	if err != nil {
		logger.Warn("acutetriage: verify: incidents_in_window query failed", "err", err, "incident", inc.ID)
		classifyErr(q, err)
		return
	}
	if total == 0 {
		q.Outcome = OutcomeEmpty
	} else {
		q.Outcome = OutcomeFetched
	}
	q.Result = capText(flattenRecalled(renderIncidentsInWindowResult(total, top, windowMinutes)), 400)
}

// runPromQL executes one model-proposed promql query, server-side bounded by
// maxSeries (prometheus.max_series — R3). Rendered as series-identity/value
// pairs, capped at maxSnapshotsPerScope lines (mirrors the metric-enrichment
// render cap).
func runPromQL(ctx context.Context, prom metricQuerier, q *VerificationQuery, maxSeries int, now time.Time, logger *slog.Logger, incidentID string) {
	if prom == nil {
		q.Outcome = OutcomeFailed
		q.Result = renderUnavailable("prometheus not configured")
		return
	}
	data, err := prom.QueryInstant(ctx, q.Expr, now, maxSeries)
	if err != nil {
		logger.Warn("acutetriage: verify: model promql query failed", "expr", q.Expr, "err", err, "incident", incidentID)
		classifyErr(q, err)
		return
	}
	results := decodeInstantResults(data)
	if len(results) == 0 {
		q.Outcome = OutcomeEmpty
		q.Result = "(no data)"
		return
	}
	if len(results) > maxSnapshotsPerScope {
		results = results[:maxSnapshotsPerScope]
	}
	lines := make([]string, 0, len(results))
	for _, r := range results {
		lines = append(lines, fmt.Sprintf("%s %s", r.Series, r.Value))
	}
	q.Outcome = OutcomeFetched
	q.Result = capText(flattenRecalled(strings.Join(lines, "; ")), 400)
}

// classifyErr maps a single query error to its Outcome/Result: a
// context.DeadlineExceeded is this query's own per-slice timeout (backend
// reachable but too slow to answer within its share of the budget) —
// OutcomeDegraded, distinct from a genuine failure, mirroring the 0.7.3
// slow-is-not-down distinction in FetchMetrics/classify. Any other error is a
// hard failure — OutcomeFailed.
func classifyErr(q *VerificationQuery, err error) {
	if errors.Is(err, context.DeadlineExceeded) {
		q.Outcome = OutcomeDegraded
		q.Result = renderUnavailable("timed out")
		return
	}
	q.Outcome = OutcomeFailed
	q.Result = renderUnavailable("failed")
}

// classifyPairErrs is classifyErr for up_ratio's two sub-queries sharing one
// outcome: a hard error on either sum or count wins over a mere timeout on
// the other (the more actionable outage — same precedent as FetchMetrics'
// anyHardErr/anyTimeout: "hard error beats timeout").
func classifyPairErrs(q *VerificationQuery, sumErr, countErr error) {
	hardErr := (sumErr != nil && !errors.Is(sumErr, context.DeadlineExceeded)) ||
		(countErr != nil && !errors.Is(countErr, context.DeadlineExceeded))
	if hardErr {
		q.Outcome = OutcomeFailed
		q.Result = renderUnavailable("failed")
		return
	}
	q.Outcome = OutcomeDegraded
	q.Result = renderUnavailable("timed out")
}

// renderUnavailable renders the R5 explicit-unavailable note call 2 sees for a
// failed or degraded query, passed through the same flatten+cap path every
// other Result takes (R13).
func renderUnavailable(reason string) string {
	return capText(flattenRecalled(fmt.Sprintf("unavailable (%s)", reason)), 400)
}

// windowMinutesFromParams reads a query's "window_minutes" param — a float64,
// since it round-trips through the model's JSON — defaulting to
// defaultWindowMinutes when absent, the wrong type, or non-positive (R4).
func windowMinutesFromParams(params map[string]any) int {
	if v, ok := params["window_minutes"]; ok {
		if f, ok := v.(float64); ok && f > 0 {
			return int(f)
		}
	}
	return defaultWindowMinutes
}

// renderIncidentsInWindowResult renders the R4 contrast-check text: the total
// count, then up to len(top) "group_key (severity, status)" entries — top is
// already store-side limited to 5 — folded into a trailing "+N more" when
// total exceeds what top carries. A member alert with no severity label
// renders "unknown" rather than a blank field.
func renderIncidentsInWindowResult(total int, top []store.WindowIncident, windowMinutes int) string {
	windowLabel := fmt.Sprintf("%dm", windowMinutes)
	if total == 0 {
		return fmt.Sprintf("0 incidents on other group keys (%s)", windowLabel)
	}
	parts := make([]string, 0, len(top))
	for _, wi := range top {
		sev := wi.Severity
		if sev == "" {
			sev = "unknown"
		}
		parts = append(parts, fmt.Sprintf("%s (%s, %s)", wi.GroupKey, sev, wi.Status))
	}
	line := strings.Join(parts, "; ")
	if more := total - len(top); more > 0 {
		line += fmt.Sprintf("; +%d more", more)
	}
	return fmt.Sprintf("%d incidents on other group keys (%s): %s", total, windowLabel, line)
}

// decodeInstantResults parses the same instant-vector envelope rankSeries
// consumes (the Prometheus API's "data" field: {"result":[{"metric":{...},
// "value":[ts,"val"]}]}) WITHOUT rankSeries's system-metric/named-series
// filtering: up_ratio's aggregate scalar carries no metric name at all, and a
// model's raw promql result needs every returned value rendered, not just the
// ones bearing a __name__ label.
func decodeInstantResults(raw json.RawMessage) []MetricSnapshot {
	var d struct {
		Result []struct {
			Metric map[string]string `json:"metric"`
			Value  [2]any            `json:"value"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil
	}
	out := make([]MetricSnapshot, 0, len(d.Result))
	for _, r := range d.Result {
		val, ok := r.Value[1].(string)
		if !ok {
			continue
		}
		out = append(out, MetricSnapshot{Series: formatSeriesIdentity(r.Metric), Value: val})
	}
	return out
}

// firstInstantValue returns the value of the first result decodeInstantResults
// finds, for up_ratio's single-series sum(...)/count(...) aggregates.
func firstInstantValue(raw json.RawMessage) (string, bool) {
	results := decodeInstantResults(raw)
	if len(results) == 0 {
		return "", false
	}
	return results[0].Value, true
}

// floorFetched is the first of the two R15 rails: every floor query
// (Source=="floor") fetched or found nothing. A failed or degraded
// MODEL-targeted query alone must never flip this — the floor is the promised
// minimum, targeted queries are bonus precision on top (R15).
func floorFetched(r *VerificationRound) bool {
	if r == nil {
		return false
	}
	for _, q := range r.Queries {
		if q.Source != "floor" {
			continue
		}
		if q.Outcome != OutcomeFetched && q.Outcome != OutcomeEmpty {
			return false
		}
	}
	return true
}

// anyUnfetched is the second R15 rail, backing the confidence clamp: any
// query — floor OR model — that failed or degraded. An empty result still
// counts as fetched here ("asked, nothing there" is itself an answer), so
// only OutcomeFailed/OutcomeDegraded trip it.
func anyUnfetched(r *VerificationRound) bool {
	if r == nil {
		return false
	}
	for _, q := range r.Queries {
		if q.Outcome == OutcomeFailed || q.Outcome == OutcomeDegraded {
			return true
		}
	}
	return false
}

// verificationLive is the R17 cap-interaction predicate: whether any up_ratio
// or promql query across every round actually fetched. A fetched PromQL
// observation (whether the floor's aggregate ratio or a model-targeted query)
// is a real observation of the infrastructure and counts as live evidence for
// hasLiveEvidence; incidents_in_window never does — it is this install's own
// SQLite bookkeeping, not an external observation. An install without
// Prometheus configured therefore never trips this, leaving today's 0.6-cap
// behavior untouched.
func verificationLive(v *VerificationEnrichment) bool {
	if v == nil {
		return false
	}
	for _, round := range v.Rounds {
		for _, q := range round.Queries {
			if (q.Kind == kindUpRatio || q.Kind == kindPromQL) && q.Outcome == OutcomeFetched {
				return true
			}
		}
	}
	return false
}

// renderVerificationResults appends the round's computed-facts section for
// call 2 (callTwoContinuation is the sole caller): the full "## Verification
// results (computed, read-only)" header, then one entry per query (floor
// first, in Queries order) naming its source/kind and why, followed by the
// SAME Result string runVerification already rendered, flattened, and capped
// (persist-as-rendered, R8/R13) — this function invents no new text beyond
// the header, it only assembles what each VerificationQuery already carries.
// The caller owns no header of its own — writing one there too would
// duplicate this one. A nil round (verification disabled, or never ran)
// renders nothing, so the prompt stays byte-identical to a non-verification
// triage.
func renderVerificationResults(b *strings.Builder, r *VerificationRound) {
	if r == nil || len(r.Queries) == 0 {
		return
	}
	b.WriteString("\n\n## Verification results (computed, read-only)")
	for _, q := range r.Queries {
		fmt.Fprintf(b, "\n\n- [%s/%s]", q.Source, q.Kind)
		if q.Why != "" {
			fmt.Fprintf(b, " %s", q.Why)
		}
		fmt.Fprintf(b, "\n  %s", q.Result)
	}
}
