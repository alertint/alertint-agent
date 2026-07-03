// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/ingress"
	"github.com/alertint/alertint-agent/internal/store"
)

// maxDrillAlerts is the structural max-fire cap (ADR-0014): scenarios are
// built-in, so the cap is enforced at materialization, not per-request.
const maxDrillAlerts = 25

// drillScenario is a built-in Drill definition. Scenarios are deliberately
// boring private structs — no embed, no rule-QA schema unification.
type drillScenario struct {
	key         string
	description string
	change      *drillChange // nil: no planted change event (storm)
	alerts      []drillAlertTemplate
}

// drillChange is the planted change event fired before the burst. Its labels
// are the adapted group labels (plus the drill marker), so change-enrichment
// ranking sees the overlap and the finding can name the deploy.
type drillChange struct {
	source      string
	kind        string
	title       string
	version     string
	occurredAgo time.Duration
}

// drillAlertTemplate is one Drill alert before label adaptation. All label
// values are obviously fictional (distillation privacy boundary: synthetic
// payloads persist across prompt, SQLite, and MCP).
type drillAlertTemplate struct {
	alertname string
	severity  string
	// labels are per-alert extras (never group labels). Alertmanager's v2
	// API identifies alerts by their full label set, so alerts that would
	// otherwise be label-identical (the storm burst) need one distinguishing
	// label or --via-alertmanager collapses them into a single alert.
	labels      map[string]string
	annotations map[string]string
}

// changePayload mirrors the change webhook body (internal/ingress
// changeRequest is unexported).
type changePayload struct {
	Source     string            `json:"source"`
	Kind       string            `json:"kind"`
	Title      string            `json:"title"`
	Labels     map[string]string `json:"labels"`
	Version    string            `json:"version,omitempty"`
	OccurredAt time.Time         `json:"occurred_at"`
}

// drillScenarios returns the v1 catalog: the change-planted flagship and a
// storm burst. Nothing else (cut table: full catalog is YAGNI).
func drillScenarios() map[string]drillScenario {
	return map[string]drillScenario{
		"flagship": {
			key:         "flagship",
			description: "planted deploy + error burst — causal, uncapped finding",
			change: &drillChange{
				source:      "alertint-drill",
				kind:        "deploy",
				title:       "deploy checkout v2.3.1",
				version:     "v2.3.1",
				occurredAgo: 5 * time.Minute,
			},
			alerts: []drillAlertTemplate{
				{
					alertname: "DrillCheckoutHighErrorRate",
					severity:  "critical",
					annotations: map[string]string{
						"summary":     "[drill] 5xx rate on drill-checkout jumped from 0.2% to 14%",
						"description": "[drill] Error rate breached the 5% SLO threshold minutes after a deploy.",
					},
				},
				{
					alertname: "DrillCheckoutLatencyP99",
					severity:  "warning",
					annotations: map[string]string{
						"summary":     "[drill] p99 latency on drill-checkout is 4.8s (SLO 1.2s)",
						"description": "[drill] Latency degradation correlates with the error-rate spike.",
					},
				},
				{
					alertname: "DrillCheckoutPodCrashLooping",
					severity:  "critical",
					annotations: map[string]string{
						"summary":     "[drill] pod drill-checkout-7d4b9 is CrashLoopBackOff (4 restarts)",
						"description": "[drill] Container exits with a nil-pointer panic in the payment handler.",
					},
				},
				{
					alertname: "DrillCheckoutQueueBacklog",
					severity:  "warning",
					annotations: map[string]string{
						"summary":     "[drill] order queue depth for drill-checkout is growing (12k msgs)",
						"description": "[drill] Consumers restart before draining; backlog doubles every 3 minutes.",
					},
				},
			},
		},
		"storm": {
			key:         "storm",
			description: "storm-sized burst on one service — one incident from many near-identical alerts",
			alerts:      stormTemplates(),
		},
	}
}

// stormTemplates builds a homogeneous burst large enough to read as a storm.
func stormTemplates() []drillAlertTemplate {
	out := make([]drillAlertTemplate, 0, 14)
	for i := 0; i < 14; i++ {
		out = append(out, drillAlertTemplate{
			alertname: "DrillNodeDiskPressure",
			severity:  "warning",
			labels:    map[string]string{"node": fmt.Sprintf("drill-node-%02d", i)},
			annotations: map[string]string{
				"summary":     fmt.Sprintf("[drill] node drill-node-%02d under disk pressure (92%% used)", i),
				"description": "[drill] Synthetic storm: many near-identical alerts from one failure domain.",
			},
		})
	}
	return out
}

// drillRun is a materialized scenario: concrete payloads bound to one run id
// and the target's group labels.
type drillRun struct {
	runID string
	// groupLabelValues holds the adapted value for every configured group
	// label key; identical on every burst alert so the whole Drill lands in
	// one incident.
	groupLabelValues map[string]string
	// expectedGroupKey mirrors the correlator's sorted k=v join for the
	// adapted labels — the drill finds its incident by exact match on it.
	expectedGroupKey string
	alerts           ingress.AlertmanagerPayload
	change           *changePayload // nil when the scenario has no change event
}

// cannedGroupValues maps well-known group-label keys to fictional values.
// Unknown keys fall back to "drill-<key>".
var cannedGroupValues = map[string]string{
	"cluster":   "drill-cluster",
	"namespace": "drill-shop",
	"service":   "drill-checkout",
	"app":       "drill-checkout",
	"alertname": "DrillCheckoutIncident",
	"host":      "drill-node-01",
	"instance":  "drill-node-01:9100",
	// severity is meaning-bearing: a "drill-severity" value would contradict
	// the alert annotations, so grouping by severity gets a real level.
	"severity": "warning",
}

// materializeScenario binds a scenario to the target's group labels and a run
// id: every configured group label gets the same obviously-fictional value on
// every alert (label adaptation), the first configured key's value is salted
// with the run id (run-unique group key: reruns inside an open window cannot
// merge into the previous Drill, and discovery matches exactly), fingerprints
// are run-scoped deterministic hashes, and every alert carries the reserved
// drill marker (ADR-0013).
func materializeScenario(sc drillScenario, groupLabelKeys []string, runID string, now time.Time) (drillRun, error) {
	if len(sc.alerts) == 0 || len(sc.alerts) > maxDrillAlerts {
		return drillRun{}, fmt.Errorf("drill: scenario %s has %d alerts, want 1..%d (max-fire cap)", sc.key, len(sc.alerts), maxDrillAlerts)
	}
	if len(groupLabelKeys) == 0 {
		return drillRun{}, fmt.Errorf("drill: target config has no correlator.group_labels")
	}

	adapted := make(map[string]string, len(groupLabelKeys))
	for i, key := range groupLabelKeys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		v, ok := cannedGroupValues[key]
		if !ok {
			v = "drill-" + key
		}
		if i == 0 {
			v = v + "-" + runID
		}
		adapted[key] = v
	}

	alerts := make([]ingress.AlertmanagerAlert, 0, len(sc.alerts))
	for i, tpl := range sc.alerts {
		labels := map[string]string{
			"alertname":            tpl.alertname,
			"severity":             tpl.severity,
			store.DrillMarkerLabel: store.DrillMarkerValue,
		}
		for k, v := range tpl.labels {
			labels[k] = v
		}
		// Group labels win over template labels: if the target groups by a
		// key the template also sets (e.g. alertname), the adapted value
		// keeps the whole burst in one incident.
		for k, v := range adapted {
			labels[k] = v
		}
		alerts = append(alerts, ingress.AlertmanagerAlert{
			Status:      "firing",
			Labels:      labels,
			Annotations: tpl.annotations,
			StartsAt:    now,
			Fingerprint: drillFingerprint(runID, tpl.alertname, i),
		})
	}

	run := drillRun{
		runID:            runID,
		groupLabelValues: adapted,
		expectedGroupKey: drillGroupKey(adapted),
		alerts: ingress.AlertmanagerPayload{
			Version:      "4",
			GroupKey:     "alertint-drill/" + runID,
			Status:       "firing",
			Receiver:     "alertint-drill",
			CommonLabels: adapted,
			Alerts:       alerts,
		},
	}

	if sc.change != nil {
		changeLabels := make(map[string]string, len(adapted)+1)
		for k, v := range adapted {
			changeLabels[k] = v
		}
		changeLabels[store.DrillMarkerLabel] = store.DrillMarkerValue
		run.change = &changePayload{
			Source:     sc.change.source,
			Kind:       sc.change.kind,
			Title:      sc.change.title,
			Labels:     changeLabels,
			Version:    sc.change.version,
			OccurredAt: now.Add(-sc.change.occurredAgo),
		}
	}
	return run, nil
}

// drillGroupKey mirrors internal/correlator groupKey for alerts that carry
// every configured group label: sorted k=v parts joined with ",".
func drillGroupKey(labels map[string]string) string {
	parts := make([]string, 0, len(labels))
	for k, v := range labels {
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// drillFingerprint is the run-scoped deterministic fingerprint: distinct
// across runs (fresh incidents), stable within one (same-fingerprint POSTs
// overwrite, so a within-run resolve would match its firing row).
func drillFingerprint(runID, alertname string, idx int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("alertint-drill:%s:%s:%d", runID, alertname, idx)))
	return hex.EncodeToString(sum[:8])
}
