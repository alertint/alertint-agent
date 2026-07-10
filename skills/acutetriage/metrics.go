// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/logs"
	promclient "github.com/alertint/alertint-agent/internal/prometheus"
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

// MetricSnapshot is a single Prometheus metric value at a point in time.
type MetricSnapshot struct {
	Instance string `json:"instance"`
	Metric   string `json:"metric"`
	Value    string `json:"value"`
}

// FetchMetrics queries Prometheus for all non-system metrics on the instances
// involved in the incident at time t. At most 10 snapshots are returned per
// instance. Safe to call with a nil prom — returns nil immediately.
func FetchMetrics(ctx context.Context, prom *promclient.Client, alerts []store.Alert, t time.Time) []MetricSnapshot {
	if prom == nil {
		return nil
	}
	instances := uniqueInstances(alerts)
	if len(instances) == 0 {
		return nil
	}

	const maxPerInstance = 10
	var out []MetricSnapshot
	for _, inst := range instances {
		// Query all series for this instance at the incident time.
		data, err := prom.QueryInstant(ctx, `{instance="`+inst+`"}`, t)
		if err != nil {
			continue
		}
		out = append(out, parseInstantVector(data, inst, maxPerInstance)...)
	}
	return out
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

// parseInstantVector extracts MetricSnapshots from a Prometheus instant query
// data blob (the "data" field of the API envelope). Filters system metrics and
// returns at most limit results.
func parseInstantVector(raw json.RawMessage, instance string, limit int) []MetricSnapshot {
	var d struct {
		Result []struct {
			Metric map[string]string `json:"metric"`
			Value  [2]any            `json:"value"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil
	}

	var out []MetricSnapshot
	for _, r := range d.Result {
		if len(out) >= limit {
			break
		}
		name := r.Metric["__name__"]
		if name == "" || isSystemMetric(name) {
			continue
		}
		val, ok := r.Value[1].(string)
		if !ok {
			continue
		}
		out = append(out, MetricSnapshot{Instance: instance, Metric: name, Value: val})
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
