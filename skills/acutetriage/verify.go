// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/internal/zabbix"
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
	// HasPromQL / HasZabbix are presence flags stamped by the skill
	// (verifyParams()), never parsed from config: they select which floor
	// sources contribute (ADR-0034) and which query kinds the model may be
	// offered (prompts.go).
	HasPromQL bool
	HasZabbix bool
}

// Query kinds. The floor uses up_ratio + incidents_in_window; the model may
// propose promql and incidents_in_window ONLY (closed set, R4).
const (
	kindPromQL            = "promql"
	kindUpRatio           = "up_ratio"
	kindIncidentsInWindow = "incidents_in_window"
	// sourceCapture marks a query widened live-once at verdict capture (D10) and
	// frozen into a verdict's widened_json — distinct from "model" (a live
	// triage's own proposed query) and "floor" (always-run).
	sourceCapture = "capture"
)

// VerificationQuery is one planned/executed query, persisted verbatim (R8/R10).
type VerificationQuery struct {
	Kind    string         `json:"kind"`
	Source  string         `json:"source"` // "model" | "floor" | "capture" | "operator"
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
	// OperatorRuling records call 2's judgment on the governing correction
	// (ADR-0029) when one is steering; nil when no correction governs this
	// triage at all.
	OperatorRuling *OperatorRulingRecord `json:"operator_ruling,omitempty"`
}

// OperatorRulingRecord is the deterministic record of what call 2 ruled on
// the governing correction's fetched operator-sourced evidence — or the
// default when it didn't rule at all. Ruling is one of:
//   - "supported" / "contradicted" / "unverifiable": the model's own valid
//     ruling (soft-parsed from resp2.OperatorRuling).
//   - "absent": call 2 answered but omitted or mangled the operator_ruling key.
//   - "unruled": call 2 never completed (the degraded-draft path).
//
// Backed reports whether at least one operator-sourced query actually fetched
// data (operatorEvidenceFetched), independent of what the model claims — the
// Task 8 backstop treats an unbacked "contradicted" as unproven.
type OperatorRulingRecord struct {
	Ruling         string `json:"ruling"`
	Basis          string `json:"basis,omitempty"`
	Backed         bool   `json:"backed"`
	VerdictID      int64  `json:"verdict_id"`
	VerdictVersion int    `json:"verdict_version"`
	VerdictDate    string `json:"verdict_date"`
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

// composeFloor assembles the deterministic floor from the applicable floor
// sources (ADR-0034) plus the universal own-state check. Every configured
// source that can address the incident contributes; there is no either/or
// branch and no activation config. Never returns an empty slice — the
// own-state check always runs.
func composeFloor(p VerificationParams, hostLabel string, alerts []store.Alert) []VerificationQuery {
	var qs []VerificationQuery
	if p.HasPromQL {
		qs = append(qs, VerificationQuery{Kind: kindUpRatio, Source: "floor", Expr: parentScope(alerts),
			Why: "peer-scope health: is the wider world up?"})
	}
	if p.HasZabbix {
		qs = append(qs, zabbixFloorQueries(alerts, hostLabel)...)
	}
	return append(qs, VerificationQuery{Kind: kindIncidentsInWindow, Source: "floor",
		Params: map[string]any{"window_minutes": float64(60)},
		Why:    "is anything else firing?"})
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
// never model-proposable); empty-expr promql entries are dropped; a
// promql entry is also dropped when params.HasPromQL is false — a
// Prometheus-less install can't run it, and an always-failing query would
// trigger the R15 clamp every re-judge (belt-and-suspenders on top of the
// prompt no longer offering the kind, ADR-0034); every surviving query is
// force-labeled Source: "model"; the list is capped at params.MaxQueries
// with the drop count logged (no silent caps, R3).
func parseVerificationPlan(raw json.RawMessage, params VerificationParams, logger *slog.Logger, incidentID string) []VerificationQuery {
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

	var droppedPromQL int
	filtered := make([]VerificationQuery, 0, len(env.Verification.Queries))
	for _, q := range env.Verification.Queries {
		switch q.Kind {
		case kindPromQL:
			if q.Expr == "" {
				continue
			}
			if !params.HasPromQL {
				droppedPromQL++
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

	if droppedPromQL > 0 {
		logger.Warn("acutetriage: verify: dropping model-proposed promql queries (prometheus not configured)",
			"dropped", droppedPromQL, "incident", incidentID)
	}

	if len(filtered) > params.MaxQueries {
		dropped := len(filtered) - params.MaxQueries
		logger.Warn("acutetriage: verify: capping model-proposed verification queries",
			"proposed", len(filtered), "kept", params.MaxQueries, "dropped", dropped, "incident", incidentID)
		filtered = filtered[:params.MaxQueries]
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

// minPerQueryTimeout floors each query's slice of the shared QueryTimeoutSeconds
// budget (D10 deviation, user-approved). Steering can add up to
// maxSteeringQueries operator queries on top of the floor and the model's own
// proposals — up to 11 queries sharing one round today — so a naive equal
// split (budget / len(queries)) can shrink well below what even a healthy
// backend needs to answer, including the floor's own essential up_ratio
// check. A slow backend then becomes indistinguishable from a genuinely
// untested correction: a timed-out probe doesn't count as fetched, doesn't
// count as backed, and confidence gets clamped anyway. This floor does not
// grow the outer budget: when flooring every slice would sum past it, the
// outer queryPhaseCtx deadline (still the hard ceiling below) simply cuts off
// the trailing queries' contexts early — the same accepted degradation mode
// FetchMetrics already relies on — rather than adding rebalancing logic here.
const minPerQueryTimeout = 2 * time.Second

// zabbixMultiRPCWeight is the budget-slice weight for the two Zabbix floor
// kinds: on a cache miss they can issue up to 3 sequential Zabbix RPCs
// (HostContext + HostGroups + GroupOpenProblems), unlike every other query
// kind's single RPC or RPC pair, which gets weight 1.
const zabbixMultiRPCWeight = 3

// queryWeight is runVerificationWith's per-query share of the round's
// timeout budget, relative to every other query in the round — see
// zabbixMultiRPCWeight.
func queryWeight(kind string) int {
	switch kind {
	case kindZabbixReachability, kindZabbixNeighborProblems:
		return zabbixMultiRPCWeight
	default:
		return 1
	}
}

// queryExecutor abstracts "run one verification query, fill Outcome/Result in
// place". liveExecutor is production; snapshotExecutor is the hermetic replay
// seam (ADR-0021 pipeline, frozen data).
type queryExecutor interface {
	execute(ctx context.Context, q *VerificationQuery)
}

// liveExecutor runs queries against the real backends: the pre-existing
// runOneQuery behavior for the legacy kinds, plus the Zabbix floor kinds
// routed through zv (Tasks 4/5).
type liveExecutor struct {
	prom      metricQuerier
	state     verifyStateReader
	inc       store.Incident
	now       time.Time
	maxSeries int
	logger    *slog.Logger
	zv        *zabbixVerifier
}

func (e *liveExecutor) execute(ctx context.Context, q *VerificationQuery) {
	switch q.Kind {
	case kindZabbixReachability:
		e.zv.runReachability(ctx, q)
	case kindZabbixNeighborProblems:
		e.zv.runNeighborProblems(ctx, q)
	default:
		runOneQuery(ctx, e.prom, e.state, q, e.inc, e.now, e.maxSeries, e.logger)
	}
}

// runVerification executes the pre-composed floor (composeFloor — whichever
// of peer up-ratio, the Zabbix reachability/neighbor-problems pair, and the
// universal cross-incident scan apply, ADR-0034), the governing verdict's
// operator-sourced steering queries (buildSteeringQueries, ADR-0029), and
// every model-proposed query against the live backends, each under its own
// slice of the shared query-phase budget, filling Outcome and Result on every
// query (R2/R3). Never returns an error — a query's own failure lands in its
// Outcome/Result, it never aborts the round or the ones after it.
//
// The pipeline (verifyAndRejudge) passes the real skill logger; the runner tests
// pass nil (defaulted to slog.Default below). zabbixSeed pre-populates the
// round's zabbixVerifier cache from chunk-02's FetchZabbixContext fetch
// (analysisResult.zabbixSeed) — the pipeline's only caller; runner tests pass
// nil and pay the normal live-fetch cost.
func runVerification(ctx context.Context, prom metricQuerier, zbx ZabbixReader, state verifyStateReader,
	params VerificationParams, inc store.Incident, floor []VerificationQuery,
	draft DraftRef, operatorQueries, modelQueries []VerificationQuery, now time.Time, logger *slog.Logger,
	zabbixSeed map[string]zabbix.Topology,
) *VerificationRound {
	if logger == nil {
		logger = slog.Default()
	}
	zv := newZabbixVerifier(zbx, logger, inc.ID)
	zv.seedHostContext(zabbixSeed)
	exec := &liveExecutor{prom: prom, state: state, inc: inc, now: now, maxSeries: params.MaxSeries,
		logger: logger, zv: zv}
	return runVerificationWith(ctx, exec, params, floor, draft, operatorQueries, modelQueries, now)
}

// runVerificationWith is runVerification's executor-parameterized core: every
// floor + operator + model query is dispatched through exec instead of always
// hitting the live backends, so replay can serve queries from a frozen
// snapshot (Task 11) while production runs unchanged through runVerification's
// liveExecutor wrapper. operatorQueries (buildSteeringQueries — the governing
// verdict's deterministic query set, ADR-0029) ride between the floor and the
// model's own proposals; like the floor they are exempt from MaxQueries —
// they are deterministic and separately capped at maxSteeringQueries (D10).
func runVerificationWith(ctx context.Context, exec queryExecutor, params VerificationParams,
	floor []VerificationQuery, draft DraftRef, operatorQueries, modelQueries []VerificationQuery, now time.Time,
) *VerificationRound {
	queries := make([]VerificationQuery, 0, len(floor)+len(operatorQueries)+len(modelQueries))
	queries = append(queries, floor...)
	queries = append(queries, operatorQueries...)
	queries = append(queries, modelQueries...)

	// Two-layer budget, mirroring FetchMetrics exactly (metrics.go:361-374):
	// an outer queryPhaseCtx caps the WHOLE query phase at QueryTimeoutSeconds
	// regardless of how the caller's ctx is scoped, and each query additionally
	// gets its own slice of that budget so one slow or hung query times out on
	// its own share instead of starving the rest of the round. Without the
	// minPerQueryTimeout floor below, a purely sequential loop dividing the
	// budget N ways would always sum to at most the total (integer division
	// only trims remainder nanoseconds, never grows it) — but once N is large
	// enough that the floor kicks in, per-query slices can sum past the
	// budget. The outer ctx is what makes that safe: a child context's
	// effective deadline can never exceed its parent's, so once
	// queryPhaseCtx's own deadline passes, every further query's context is
	// already expired and fails fast — trailing queries are simply cut off
	// rather than the round running long. len(queries) is never 0 — composeFloor
	// always contributes at least the incidents_in_window entry.
	budget := time.Duration(params.QueryTimeoutSeconds) * time.Second
	queryPhaseCtx, phaseCancel := context.WithTimeout(ctx, budget)
	defer phaseCancel()

	// Slices are weighted, not split evenly: the Zabbix floor kinds can issue
	// up to 3 sequential RPCs on a cache miss (HostContext + HostGroups +
	// GroupOpenProblems) versus one RPC pair for everything else, so an equal
	// split would squeeze a legitimately slower query into the same share as
	// a single aggregate query and misreport it as degraded/timed-out under
	// load that Zabbix itself, not the query shape, caused.
	totalWeight := 0
	for i := range queries {
		totalWeight += queryWeight(queries[i].Kind)
	}

	for i := range queries {
		slice := budget * time.Duration(queryWeight(queries[i].Kind)) / time.Duration(totalWeight)
		if slice < minPerQueryTimeout {
			slice = minPerQueryTimeout
		}
		qCtx, cancel := context.WithTimeout(queryPhaseCtx, slice)
		exec.execute(qCtx, &queries[i])
		cancel()
	}

	return &VerificationRound{At: now, Draft: draft, Queries: queries}
}

// runOneQuery dispatches one query to its kind-specific executor, filling its
// Outcome and Result in place. The closed kind set here (kindUpRatio,
// kindIncidentsInWindow, kindPromQL) is enforced upstream — composeFloor only
// ever emits up_ratio/incidents_in_window (the Zabbix floor kinds are routed
// away by liveExecutor.execute before reaching here), parseVerificationPlan
// only ever lets promql/incidents_in_window through — so the default branch
// below is unreachable in practice; it exists as a fail-safe rather than a
// silent no-op if that ever changes.
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
// query's Expr, set by composeFloor to parentScope(alerts); "" renders an
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

// isHardErr reports whether err is more than a mere timeout — the shared
// "hard error beats timeout" classification every partial-failure path in
// this package uses (classifyErr, classifyPairErrs, zabbixVerifier's
// runReachability): a context.DeadlineExceeded is this query's own per-slice
// timeout (backend reachable but too slow to answer within its share of the
// budget), distinct from a genuine failure.
func isHardErr(err error) bool {
	return err != nil && !errors.Is(err, context.DeadlineExceeded)
}

// classifyErr maps a single query error to its Outcome/Result: a timeout is
// OutcomeDegraded (mirroring the 0.7.3 slow-is-not-down distinction in
// FetchMetrics/classify); any other error is OutcomeFailed.
func classifyErr(q *VerificationQuery, err error) {
	if isHardErr(err) {
		q.Outcome = OutcomeFailed
		q.Result = renderUnavailable("failed")
		return
	}
	q.Outcome = OutcomeDegraded
	q.Result = renderUnavailable("timed out")
}

// classifyPairErrs is classifyErr for up_ratio's two sub-queries sharing one
// outcome: a hard error on either sum or count wins over a mere timeout on
// the other (the more actionable outage — same precedent as FetchMetrics'
// anyHardErr/anyTimeout: "hard error beats timeout").
func classifyPairErrs(q *VerificationQuery, sumErr, countErr error) {
	if isHardErr(sumErr) || isHardErr(countErr) {
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

// windowMinutesFromParams reads a query's "window_minutes" param — normally a
// float64 since it round-trips through the model's JSON, but also accepted as
// a plain int (a live Go-constructed query, e.g. the snapshot-executor match
// in replay, never passes through JSON) — defaulting to defaultWindowMinutes
// when absent, the wrong type, or non-positive (R4).
func windowMinutesFromParams(params map[string]any) int {
	switch v := params["window_minutes"].(type) {
	case float64:
		if v > 0 {
			return int(v)
		}
	case int:
		if v > 0 {
			return v
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
// (Source=="floor") fetched or found nothing, AND at least one of them came
// from a real backend. A failed or degraded MODEL-targeted query alone must
// never flip this — the floor is the promised minimum, targeted queries are
// bonus precision on top (R15).
//
// The real-backend requirement matters because composeFloor (ADR-0034) is
// presence-based: an install with no Prometheus and no Zabbix configured — or
// Zabbix configured but the incident lacking host identity — composes a floor
// of ONLY kindIncidentsInWindow, this install's own SQLite bookkeeping, which
// almost always fetches. Without excluding it, such an install would silently
// clear the caveat on the strength of nothing but its own query, on every
// triage. Requiring at least one non-incidents_in_window floor member
// restores the pre-Task-6 behavior for a zero-real-backend install: back then
// the floor always included up_ratio, which unconditionally failed
// "prometheus not configured" absent Prometheus, so floorFetched was reliably
// false and the 0.6 metadata-only confidence cap's caveat never cleared.
func floorFetched(r *VerificationRound) bool {
	if r == nil {
		return false
	}
	sawRealSource := false
	for _, q := range r.Queries {
		if q.Source != "floor" {
			continue
		}
		if isRealFloorSource(q) {
			sawRealSource = true
		}
		if q.Outcome != OutcomeFetched && q.Outcome != OutcomeEmpty {
			return false
		}
	}
	return sawRealSource
}

// isRealFloorSource reports whether q is a floor query backed by a real
// external observation rather than kindIncidentsInWindow (this install's own
// SQLite bookkeeping) — the one predicate floorFetched and anyUnfetched both
// need and must agree on, shared here so a future floor source only needs
// this single definition updated to stay in sync across both R15 rails.
func isRealFloorSource(q VerificationQuery) bool {
	return q.Source == "floor" && q.Kind != kindIncidentsInWindow
}

// anyUnfetched is the second R15 rail, backing the confidence clamp: any
// query — floor OR model — that failed or degraded. An empty result still
// counts as fetched here ("asked, nothing there" is itself an answer), so
// only OutcomeFailed/OutcomeDegraded trip it directly.
//
// It also trips symmetrically with floorFetched's zero-real-backend fix: a
// round whose only floor member is kindIncidentsInWindow (this install's own
// SQLite bookkeeping, never a real observation) never fails or degrades — it
// unconditionally fetches — so without this second condition, a zero-backend
// install (no Prometheus, no Zabbix — or Zabbix configured but the incident
// lacking host identity) would report anyUnfetched == false even though
// nothing external was ever checked. That would silently disable the R15
// clamp on exactly the installs where it matters most: those with OTHER live
// evidence sources configured (e.g. Sentry, GitHub) where the 0.6
// metadata-only cap does not apply, leaving the clamp as the only thing
// stopping a re-judge from inflating confidence on zero verification.
func anyUnfetched(r *VerificationRound) bool {
	if r == nil {
		return false
	}
	sawRealFloorSource := false
	for _, q := range r.Queries {
		if q.Outcome == OutcomeFailed || q.Outcome == OutcomeDegraded {
			return true
		}
		if isRealFloorSource(q) {
			sawRealFloorSource = true
		}
	}
	return !sawRealFloorSource
}

// verificationLive is the R17 cap-interaction predicate: whether any
// floor-source or promql query across every round actually fetched. A
// fetched observation from any floor source — Prometheus's aggregate ratio,
// a model promql, or the Zabbix floor's polling verdict / live problem
// evaluation — is a real observation of the infrastructure and counts as
// live evidence (ADR-0034 phase symmetry); incidents_in_window never does —
// it is this install's own SQLite bookkeeping. An install with no floor
// source configured therefore never trips this, leaving the 0.6-cap
// behavior untouched.
//
// The check is Kind != kindIncidentsInWindow rather than an explicit
// allowlist of the other kinds by name, so a future floor source's new kind
// counts automatically instead of requiring this switch to be remembered and
// extended — the same generalization floorFetched/anyUnfetched already use
// via isRealFloorSource (this predicate also covers a model-proposed
// kindPromQL query, which isRealFloorSource's Source=="floor" check would
// exclude, so it stays its own definition rather than reusing that one).
func verificationLive(v *VerificationEnrichment) bool {
	if v == nil {
		return false
	}
	for _, round := range v.Rounds {
		for _, q := range round.Queries {
			if q.Kind != kindIncidentsInWindow && q.Outcome == OutcomeFetched {
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

// snapshotExecutor serves verification queries from the frozen snapshot:
// original round results + widened entries (source "capture"). Floor queries
// regenerate byte-identical (composeFloor is deterministic) and hit; model
// queries exact-match; a miss returns "no data (replay)" — OutcomeEmpty, the
// same "asked, nothing there" class the 0.8.3 empty-result calibration
// already teaches the model to weigh. Not safe for concurrent use (the round
// loop is sequential).
type snapshotExecutor struct {
	byKey   map[string]VerificationQuery
	matched int
	missed  int
}

func newSnapshotExecutor(frozen []VerificationQuery) *snapshotExecutor {
	m := make(map[string]VerificationQuery, len(frozen))
	for _, q := range frozen {
		m[snapshotKey(q)] = q
	}
	return &snapshotExecutor{byKey: m}
}

// snapshotKey normalizes a query to its match identity: kind+expr for
// promql/up_ratio, kind+window for incidents_in_window (numbers arrive as
// float64 from frozen JSON and as int from live params — normalize both),
// kind+checked-hosts for the two Zabbix floor kinds (hostsFromParams already
// tolerates the []any-vs-[]string shape difference between a frozen envelope
// and a live-composed query, Task 3).
func snapshotKey(q VerificationQuery) string {
	switch q.Kind {
	case kindIncidentsInWindow:
		return q.Kind + "\x1f" + strconv.Itoa(windowMinutesFromParams(q.Params))
	case kindZabbixReachability, kindZabbixNeighborProblems:
		return q.Kind + "\x1f" + strings.Join(hostsFromParams(q.Params), ",")
	}
	return q.Kind + "\x1f" + q.Expr
}

func (e *snapshotExecutor) execute(_ context.Context, q *VerificationQuery) {
	if f, ok := e.byKey[snapshotKey(*q)]; ok {
		q.Outcome = f.Outcome
		q.Result = f.Result
		e.matched++
		return
	}
	q.Outcome = OutcomeEmpty
	q.Result = "no data (replay)"
	e.missed++
}

// fidelity is the replay_fidelity report: full when every executed query was
// served from the snapshot, else partial with the unmatched count.
func (e *snapshotExecutor) fidelity() string {
	if e.missed == 0 {
		return "full"
	}
	return fmt.Sprintf("partial (%d/%d verification queries unmatched)", e.missed, e.missed+e.matched)
}
