package acutetriage

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	promclient "github.com/alertint/alertint-agent/internal/prometheus"
	"github.com/alertint/alertint-agent/internal/store"
)

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
