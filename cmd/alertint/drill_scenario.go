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

// drillScenarios returns the built-in catalog: the change-planted flagship, a
// storm burst, and a database-outage cascade. The v1 "full catalog is YAGNI"
// cut was deliberately reversed for db-outage (2026-08): a no-deploy cascade
// is the best first-touch contrast to flagship's causal finding.
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
			description: "storm burst — debug logging left on fleet-wide floods every node's disk; many near-identical alerts, one incident",
			alerts:      stormTemplates(),
		},
		"db-outage": {
			key:         "db-outage",
			description: "database outage cascade — no deploy; the database is the root cause, the rest is downstream",
			alerts: []drillAlertTemplate{
				{
					alertname: "DrillPostgresDown",
					severity:  "critical",
					annotations: map[string]string{
						"summary":     "[drill] postgres on drill-orders-db is down — connection refused",
						"description": "[drill] The drill-shop primary database stopped accepting connections; no automatic failover is configured.",
					},
				},
				{
					alertname: "DrillCheckoutDBPoolExhausted",
					severity:  "critical",
					annotations: map[string]string{
						"summary":     "[drill] drill-checkout connection pool exhausted (0/50 available)",
						"description": "[drill] Every pooled connection to drill-orders-db is dead; new requests block until the pool timeout fires.",
					},
				},
				{
					alertname: "DrillCheckoutHTTP5xx",
					severity:  "warning",
					annotations: map[string]string{
						"summary":     "[drill] 5xx rate on drill-checkout is 31% — requests fail after the db timeout",
						"description": "[drill] Checkout returns 500s once the database timeout expires; the error rate tracks the outage exactly.",
					},
				},
				{
					alertname: "DrillOrderQueueStalled",
					severity:  "warning",
					annotations: map[string]string{
						"summary":     "[drill] order queue consumer for drill-checkout stalled (8k msgs, zero throughput)",
						"description": "[drill] Consumers cannot commit orders without the database; the queue grows and drains nothing.",
					},
				},
			},
		},
	}
}

// stormTemplates builds the storm burst: one real-world mistake — debug
// logging left enabled fleet-wide — filling every node's disk at once.
func stormTemplates() []drillAlertTemplate {
	out := make([]drillAlertTemplate, 0, 14)
	for i := 0; i < 14; i++ {
		out = append(out, drillAlertTemplate{
			alertname: "DrillNodeDiskPressure",
			severity:  "warning",
			labels:    map[string]string{"node": fmt.Sprintf("drill-node-%02d", i)},
			annotations: map[string]string{
				"summary":     fmt.Sprintf("[drill] node drill-node-%02d under disk pressure (92%% used, /var/log growing fast)", i),
				"description": "[drill] Debug logging was left enabled fleet-wide after last night's incident; every node's /var/log is filling at once.",
			},
		})
	}
	return out
}

// drillRun is a materialized scenario: concrete payloads bound to one run id
// and either the target's explicit override or the drill's Receiver grouping.
type drillRun struct {
	runID string
	// groupLabelValues holds the adapted value for every effective group label
	// key; identical on every burst alert so the whole Drill lands in one
	// Incident.
	groupLabelValues map[string]string
	// expectedGroupKey mirrors the correlator's sorted k=v join for the
	// adapted labels — the drill finds its incident by exact match on it.
	expectedGroupKey string
	alerts           ingress.AlertmanagerPayload
	change           *changePayload // nil when the scenario has no change event
}

// receiverModeDrillGroupLabels are emitted in the synthetic Alertmanager
// envelope when no explicit override exists. They belong only to the Drill's
// payload; they are not correlator defaults.
var receiverModeDrillGroupLabels = []string{"cluster", "namespace", "service", "host"}

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

// materializeScenario binds a scenario to its effective grouping labels and a
// run id: every group label gets the same obviously-fictional value on
// every alert (label adaptation), the first effective key's value is salted
// with the scenario key plus the run id (run-unique group key: reruns inside
// an open window cannot merge into the previous Drill, discovery matches
// exactly, and the rerun-collapse matcher can tell scenarios apart — a storm
// rerun must never land on a flagship incident), fingerprints are run-scoped
// deterministic hashes, and every alert carries the reserved drill marker
// (ADR-0013).
func materializeScenario(sc drillScenario, groupLabelKeys []string, groupSalt, fpSeed string, now time.Time) (drillRun, error) {
	if len(sc.alerts) == 0 || len(sc.alerts) > maxDrillAlerts {
		return drillRun{}, fmt.Errorf("drill: scenario %s has %d alerts, want 1..%d (max-fire cap)", sc.key, len(sc.alerts), maxDrillAlerts)
	}
	groupLabelKeys = effectiveDrillGroupLabels(groupLabelKeys)

	// groupSalt sets the run-unique group key (the correlator's collapse key);
	// fpSeed sets the alert fingerprints. A fresh run passes the same value for
	// both. A recurrence-collapse rerun reuses groupSalt (so it lands on the
	// prior incident's key) but takes a FRESH fpSeed, so its alerts are a new
	// firing episode — a distinct-fingerprint attach, not an unchanged repeat.
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
			v = v + "-" + sc.key + "-" + groupSalt
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
			Fingerprint: drillFingerprint(fpSeed, tpl.alertname, i),
		})
	}

	run := drillRun{
		runID:            groupSalt,
		groupLabelValues: adapted,
		expectedGroupKey: drillGroupKey(adapted),
		alerts: ingress.AlertmanagerPayload{
			Version:      "4",
			GroupKey:     "alertint-drill/" + fpSeed,
			Status:       "firing",
			Receiver:     "alertint-drill",
			GroupLabels:  adapted,
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

// resolvedPayload re-stamps the run's burst as resolved: identical labels and
// run-scoped fingerprints (they overwrite the firing rows), endsAt set, both
// alert and payload status resolved. Fired through the same production door
// as the burst, it closes the Drill via the normal resolution path.
func resolvedPayload(run drillRun, now time.Time) ingress.AlertmanagerPayload {
	p := run.alerts
	alerts := make([]ingress.AlertmanagerAlert, len(p.Alerts))
	for i, a := range p.Alerts {
		a.Status = "resolved"
		a.EndsAt = now
		alerts[i] = a
	}
	p.Status = "resolved"
	p.Alerts = alerts
	return p
}

func effectiveDrillGroupLabels(configured []string) []string {
	if len(configured) > 0 {
		return configured
	}
	return receiverModeDrillGroupLabels
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
