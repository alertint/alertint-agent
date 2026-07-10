// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/logs"
	"github.com/alertint/alertint-agent/internal/store"
)

// metricPhysicalKeys are the physical-identity allowlist keys — the ones that
// name a real Prometheus series. The logical keys (service, job) are attached by
// alerting rules and commonly exist on no series, so the R9 retry drops them.
var metricPhysicalKeys = map[string]bool{
	"namespace": true, "pod": true, "container": true, "instance": true,
}

// buildMetricSelector builds the incident's generic metric selector: for each
// allowlisted label key present with a value on EVERY member alert, the distinct
// values that key takes across members, unioned. This is exactly the log-selector
// rule (ADR-0002/0016) — reusing sharedLabelValues — but with no provider
// translation layer: for Prometheus, alert labels usually ARE series labels.
func buildMetricSelector(alerts []store.Alert) map[string][]string {
	shared := sharedLabelValues(alerts)
	out := make(map[string][]string)
	for _, k := range logs.AllowedSelectorKeys {
		if vs, ok := shared[k]; ok && len(vs) > 0 {
			out[k] = vs
		}
	}
	return out
}

// renderPromMatcher renders a selector map into a PromQL stream matcher
// {k="v",k=~"v1|v2"} with keys sorted for a deterministic query string. Returns
// "" when no key survives (no usable selector).
func renderPromMatcher(sel map[string][]string) string {
	keys := make([]string, 0, len(sel))
	for k := range sel {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		if term := promMatcherTerm(k, sel[k]); term != "" {
			parts = append(parts, term)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// promMatcherTerm renders one PromQL label matcher for key k over its value set:
// an exact matcher k="v" for a single value, or an anchored regex alternation
// k=~"v1|v2" for several. Values are regexp-escaped (so a value's own regex
// metacharacters stay literal) and %q-quoted (so the PromQL string literal is
// valid). Prometheus anchors =~ matchers (^(?:…)$), so the alternation matches
// each value exactly — mirrors internal/logs/loki matcherTerm (R3/AE2).
func promMatcherTerm(k string, values []string) string {
	uniq := dedupeSortedValues(values)
	switch len(uniq) {
	case 0:
		return ""
	case 1:
		return fmt.Sprintf("%s=%q", k, uniq[0])
	default:
		escaped := make([]string, len(uniq))
		for i, v := range uniq {
			escaped[i] = regexp.QuoteMeta(v)
		}
		return fmt.Sprintf("%s=~%q", k, strings.Join(escaped, "|"))
	}
}

// dedupeSortedValues returns the distinct non-empty values of in, sorted.
func dedupeSortedValues(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// instanceSupplements builds one bare {instance="X"} matcher per unique member
// instance value — the per-instance supplement (R2). It guarantees an alert
// carrying instance keeps at least its old broad per-instance scope even when
// the shared intersection drops instance (a label-sparse co-member) or narrows
// it (instance AND'd with pod would filter out node-level series). No-regression
// guard: correlation must never remove evidence an uncorrelated alert would have.
func instanceSupplements(alerts []store.Alert) []string {
	out := make([]string, 0)
	for _, inst := range uniqueInstances(alerts) {
		out = append(out, "{"+promMatcherTerm("instance", []string{inst})+"}")
	}
	return out
}

// renderPhysicalCore renders the R9 retry selector: the shared selector with only
// physical-identity keys (namespace, pod, container, instance), dropping the
// logical keys (service, job) that alerting rules attach but that exist on no
// series. Returns "" when the shared selector has no logical key — a retry would
// then equal the primary, so there is nothing to rescue.
func renderPhysicalCore(shared map[string][]string) string {
	core := make(map[string][]string)
	hasLogical := false
	for k, vs := range shared {
		if metricPhysicalKeys[k] {
			core[k] = vs
		} else {
			hasLogical = true
		}
	}
	if !hasLogical {
		return ""
	}
	return renderPromMatcher(core)
}

// memberLabelPairs collects every non-empty (key,value) label pair across all
// member alerts into a set keyed "k\x00v", for the R11 overlap score.
func memberLabelPairs(alerts []store.Alert) map[string]bool {
	out := make(map[string]bool)
	for _, a := range alerts {
		for k, v := range a.Labels {
			if v != "" {
				out[k+"\x00"+v] = true
			}
		}
	}
	return out
}

// MetricSnapshot is a single Prometheus metric value at a point in time. Series
// is the series' identifying label set rendered as {k="v",…} (excluding
// __name__) — renamed from the old instance-only Instance field, since scope is
// no longer instance-only (Outstanding Q3).
type MetricSnapshot struct {
	Series string `json:"series"`
	Metric string `json:"metric"`
	Value  string `json:"value"`
}

// rankSeries parses a Prometheus instant-vector data blob (the "data" field of
// the API envelope), filters system metrics, and returns at most limit snapshots
// ranked by (overlap desc, metric asc, series-identity asc) — a total,
// response-order-independent order (R11). overlap counts a series' (k,v) label
// pairs (excluding __name__) that a member alert also carries.
func rankSeries(raw json.RawMessage, memberPairs map[string]bool, limit int) []MetricSnapshot {
	var d struct {
		Result []struct {
			Metric map[string]string `json:"metric"`
			Value  [2]any            `json:"value"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil
	}
	type cand struct {
		snap    MetricSnapshot
		overlap int
	}
	cands := make([]cand, 0, len(d.Result))
	for _, r := range d.Result {
		name := r.Metric["__name__"]
		if name == "" || isSystemMetric(name) {
			continue
		}
		val, ok := r.Value[1].(string)
		if !ok {
			continue
		}
		overlap := 0
		for k, v := range r.Metric {
			if k == "__name__" {
				continue
			}
			if memberPairs[k+"\x00"+v] {
				overlap++
			}
		}
		cands = append(cands, cand{
			snap:    MetricSnapshot{Series: formatSeriesIdentity(r.Metric), Metric: name, Value: val},
			overlap: overlap,
		})
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].overlap != cands[j].overlap {
			return cands[i].overlap > cands[j].overlap
		}
		if cands[i].snap.Metric != cands[j].snap.Metric {
			return cands[i].snap.Metric < cands[j].snap.Metric
		}
		return cands[i].snap.Series < cands[j].snap.Series
	})
	if len(cands) > limit {
		cands = cands[:limit]
	}
	out := make([]MetricSnapshot, len(cands))
	for i, c := range cands {
		out[i] = c.snap
	}
	return out
}

// formatSeriesIdentity renders a series' identifying labels (all but __name__) as
// a deterministic {k="v",…} string, doubling as the snapshot's display identity
// and the ranking tiebreak key.
func formatSeriesIdentity(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		if k == "__name__" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%q", k, m[k]))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// uniqueInstances returns unique non-empty instance label values from the alerts.
func uniqueInstances(alerts []store.Alert) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range alerts {
		if inst := a.Labels["instance"]; inst != "" && !seen[inst] {
			seen[inst] = true
			out = append(out, inst)
		}
	}
	return out
}

const maxSnapshotsPerScope = 10

// MetricParams carries the metric-enrichment tunables from config. Passed in
// rather than read off the client so the fetch owns the single-deadline budget.
type MetricParams struct {
	TimeoutSeconds int
}

// metricQuerier is the narrow read surface FetchMetrics needs. *prometheus.Client
// satisfies it; tests inject a fake with no HTTP (mirrors SentryReader). The
// caller passes a TRUE nil interface when Prometheus is unconfigured, so the
// nil check below is not defeated by a typed-nil *prometheus.Client.
type metricQuerier interface {
	QueryInstant(ctx context.Context, expr string, t time.Time) (json.RawMessage, error)
}

// MetricEnrichment is the live-metric context attached to a triage prompt and
// persisted under the "metrics" envelope key. Mirrors LogEnrichment: the same
// value feeds both the prompt and persistence (one fetch, two uses), and its
// Outcome makes fetched / queried-empty / no-selector / backend-failed
// distinguishable in logs, the audit trail, and the notification card (R4/R8).
type MetricEnrichment struct {
	At        time.Time        `json:"at"`
	Selector  string           `json:"selector,omitempty"`  // rendered matcher(s) that ran (breadcrumb/replay)
	Snapshots []MetricSnapshot `json:"snapshots,omitempty"` // ranked, capped
	Note      string           `json:"note,omitempty"`      // why Snapshots is empty
	Outcome   Outcome          `json:"outcome,omitempty"`
}

// FetchMetrics queries Prometheus for the incident's series at time t using the
// generic selector (shared allowlisted labels ∩ union values) plus a per-instance
// supplement, with a physical-core retry on the primary scope (R1/R2/R9). Every
// scope's series are ranked by member-label overlap and capped (R11); snapshots
// are deduped across scopes. Best-effort: never blocks or fails triage. Returns
// nil ONLY when Prometheus is unconfigured (prom == nil) — "we never looked";
// otherwise a non-nil enrichment carrying an Outcome, so the operator and the LLM
// can tell fetched / empty / no-selector / backend-failed apart (R4). The whole
// multi-query fetch shares ONE TimeoutSeconds deadline, so worst-case added
// latency is one timeout, not N×.
func FetchMetrics(ctx context.Context, prom metricQuerier, params MetricParams, alerts []store.Alert, t time.Time, incidentID string, logger *slog.Logger) *MetricEnrichment {
	if prom == nil {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}

	shared := buildMetricSelector(alerts)
	primary := renderPromMatcher(shared)
	physicalFallback := renderPhysicalCore(shared)

	// Ordered, deduped scope list: primary first (it alone gets the retry), then
	// the per-instance supplements not already equal to the primary.
	scopes := make([]string, 0)
	seen := map[string]bool{}
	if primary != "" {
		scopes = append(scopes, primary)
		seen[primary] = true
	}
	for _, sup := range instanceSupplements(alerts) {
		if !seen[sup] {
			scopes = append(scopes, sup)
			seen[sup] = true
		}
	}

	if len(scopes) == 0 {
		logger.Info("acutetriage: metrics: no usable selector for this incident",
			"shared_labels", formatLabels(sharedLabels(alerts)), "incident", incidentID)
		return &MetricEnrichment{At: t, Note: "no usable metric selector for this incident", Outcome: OutcomeNoSelector}
	}

	ctx, cancel := context.WithTimeout(ctx, time.Duration(params.TimeoutSeconds)*time.Second)
	defer cancel()

	memberPairs := memberLabelPairs(alerts)
	var snapshots []MetricSnapshot
	anyErr, anyOK := false, false
	for i, scope := range scopes {
		data, err := prom.QueryInstant(ctx, scope, t)
		if err != nil {
			anyErr = true
			logger.Warn("acutetriage: metrics: backend query failed",
				"selector", scope, "err", err, "incident", incidentID)
			continue
		}
		anyOK = true
		ranked := rankSeries(data, memberPairs, maxSnapshotsPerScope)
		// R9 physical-core rescue — primary scope only, when it matched nothing and
		// dropping the logical keys yields a distinct selector.
		if i == 0 && scope == primary && len(ranked) == 0 && physicalFallback != "" && physicalFallback != primary {
			data2, err2 := prom.QueryInstant(ctx, physicalFallback, t)
			if err2 != nil {
				anyErr = true
				logger.Warn("acutetriage: metrics: physical-core retry failed",
					"selector", physicalFallback, "err", err2, "incident", incidentID)
			} else {
				ranked = rankSeries(data2, memberPairs, maxSnapshotsPerScope)
			}
		}
		snapshots = append(snapshots, ranked...)
	}
	snapshots = dedupeSnapshots(snapshots)

	enr := &MetricEnrichment{At: t, Selector: strings.Join(scopes, ", ")}
	switch {
	case len(snapshots) > 0:
		enr.Snapshots = snapshots
		enr.Outcome = OutcomeFetched
		logger.Info("metrics fetched", "snapshots", len(snapshots), "selector", enr.Selector, "incident", incidentID)
	case anyErr && !anyOK:
		enr.Note = "metric backend query failed"
		enr.Outcome = OutcomeFailed
	default:
		enr.Note = "no metric series matched the incident selector"
		enr.Outcome = OutcomeEmpty
		logger.Info("acutetriage: metrics: queried, no series matched", "selector", enr.Selector, "incident", incidentID)
	}
	return enr
}

// dedupeSnapshots drops duplicate (Series, Metric) snapshots — the supplement
// scopes overlap the primary, so the same value can surface twice. First wins
// (primary-scoped snapshots are appended first).
func dedupeSnapshots(in []MetricSnapshot) []MetricSnapshot {
	if len(in) == 0 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, s := range in {
		key := s.Series + "\x00" + s.Metric
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, s)
	}
	return out
}

// isSystemMetric returns true for Go runtime, process, scrape, and pushgateway
// bookkeeping metrics that are not meaningful for incident triage.
func isSystemMetric(name string) bool {
	for _, prefix := range []string{
		"go_", "process_", "scrape_", "promhttp_", "net_conntrack_", "push_",
	} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
