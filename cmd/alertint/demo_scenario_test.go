// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/ingress"
	"github.com/alertint/alertint-agent/internal/store"
)

var defaultGroupLabels = []string{"cluster", "namespace", "service"}

func mustMaterialize(t *testing.T, scenario string, keys []string, runID string) demoRun {
	t.Helper()
	sc, ok := demoScenarios()[scenario]
	if !ok {
		t.Fatalf("unknown scenario %q", scenario)
	}
	run, err := materializeScenario(sc, keys, runID, time.Now().UTC())
	if err != nil {
		t.Fatalf("materialize %s: %v", scenario, err)
	}
	return run
}

// TestMaterialize_SingleGroupKey: every burst alert carries the identical
// adapted group-label set, so the whole Drill correlates into one incident,
// and the expected group key is the correlator's sorted k=v join.
func TestMaterialize_SingleGroupKey(t *testing.T) {
	run := mustMaterialize(t, "flagship", defaultGroupLabels, "4f2a1b")

	want := "cluster=demo-cluster-4f2a1b,namespace=demo-shop,service=demo-checkout"
	if run.expectedGroupKey != want {
		t.Errorf("expectedGroupKey = %q, want %q", run.expectedGroupKey, want)
	}
	for i, a := range run.alerts.Alerts {
		for _, k := range defaultGroupLabels {
			if a.Labels[k] != run.groupLabelValues[k] {
				t.Errorf("alert[%d] label %s = %q, want %q", i, k, a.Labels[k], run.groupLabelValues[k])
			}
		}
	}
}

// TestMaterialize_CustomGroupLabels: unknown keys get demo-<key> values on
// every alert; the first configured key is run-salted. A target grouping by
// alertname still gets one homogeneous incident (group labels win).
func TestMaterialize_CustomGroupLabels(t *testing.T) {
	run := mustMaterialize(t, "flagship", []string{"team", "region"}, "aa11bb")
	for i, a := range run.alerts.Alerts {
		if a.Labels["team"] != "demo-team-aa11bb" || a.Labels["region"] != "demo-region" {
			t.Errorf("alert[%d] custom group labels = team=%q region=%q", i, a.Labels["team"], a.Labels["region"])
		}
	}

	byName := mustMaterialize(t, "flagship", []string{"alertname", "service"}, "cc22dd")
	seen := map[string]bool{}
	for _, a := range byName.alerts.Alerts {
		seen[a.Labels["alertname"]] = true
	}
	if len(seen) != 1 {
		t.Errorf("alertname-grouped burst has %d distinct alertname values, want 1 (single incident)", len(seen))
	}
}

// TestMaterialize_RunScoping: distinct runs yield disjoint fingerprints and
// different group keys (fresh incidents per rerun); one run is deterministic.
func TestMaterialize_RunScoping(t *testing.T) {
	a := mustMaterialize(t, "flagship", defaultGroupLabels, "run001")
	b := mustMaterialize(t, "flagship", defaultGroupLabels, "run002")
	a2 := mustMaterialize(t, "flagship", defaultGroupLabels, "run001")

	if a.expectedGroupKey == b.expectedGroupKey {
		t.Error("two runs share a group key; reruns inside an open window would merge")
	}
	fps := map[string]bool{}
	for _, al := range a.alerts.Alerts {
		fps[al.Fingerprint] = true
	}
	for i, al := range b.alerts.Alerts {
		if fps[al.Fingerprint] {
			t.Errorf("run b alert[%d] reuses fingerprint %s from run a", i, al.Fingerprint)
		}
		if b.alerts.Alerts[i].Fingerprint == "" {
			t.Errorf("alert[%d] has empty fingerprint", i)
		}
	}
	for i := range a.alerts.Alerts {
		if a.alerts.Alerts[i].Fingerprint != a2.alerts.Alerts[i].Fingerprint {
			t.Errorf("same run not deterministic at alert[%d]", i)
		}
	}
}

// TestMaterialize_ChangeEventOverlapsBurst: the planted deploy carries the
// adapted group labels (non-empty overlap for enrichment ranking), a
// backdated occurred_at, and parses through the real change receiver parser.
func TestMaterialize_ChangeEventOverlapsBurst(t *testing.T) {
	now := time.Now().UTC()
	sc := demoScenarios()["flagship"]
	run, err := materializeScenario(sc, defaultGroupLabels, "e3f4a5", now)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if run.change == nil {
		t.Fatal("flagship must carry a planted change event")
	}

	overlap := 0
	for k, v := range run.change.Labels {
		if run.groupLabelValues[k] == v {
			overlap++
		}
	}
	if overlap == 0 {
		t.Error("change labels share nothing with the burst's group labels")
	}
	if got := now.Sub(run.change.OccurredAt); got < 4*time.Minute || got > 6*time.Minute {
		t.Errorf("occurred_at backdated by %s, want ~5m", got)
	}

	body, err := json.Marshal(run.change)
	if err != nil {
		t.Fatalf("marshal change: %v", err)
	}
	changes, err := ingress.ParseChange(body, now)
	if err != nil {
		t.Fatalf("ParseChange rejects demo change payload: %v", err)
	}
	if len(changes) != 1 || changes[0].Kind != "deploy" || !strings.Contains(changes[0].Title, "checkout") {
		t.Errorf("parsed change = %+v, want one deploy naming checkout", changes)
	}
}

// TestMaterialize_ReceiverContract: the burst satisfies the Alertmanager v4
// receiver contract (version, fingerprint, status, startsAt) and every Demo
// alert carries the reserved marker (ADR-0013).
func TestMaterialize_ReceiverContract(t *testing.T) {
	for _, scenario := range []string{"flagship", "storm"} {
		run := mustMaterialize(t, scenario, defaultGroupLabels, "0d0d0d")
		if n := len(run.alerts.Alerts); n == 0 || n > maxDemoAlerts {
			t.Fatalf("%s: %d alerts, want 1..%d", scenario, n, maxDemoAlerts)
		}

		body, err := json.Marshal(run.alerts)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		payload, err := ingress.ParseAlertmanager(body)
		if err != nil {
			t.Fatalf("%s: ParseAlertmanager rejects demo payload: %v", scenario, err)
		}
		for i, a := range payload.Alerts {
			if a.Fingerprint == "" || a.Status != "firing" || a.StartsAt.IsZero() {
				t.Errorf("%s alert[%d] violates receiver contract: %+v", scenario, i, a)
			}
			if a.Labels[store.DemoMarkerLabel] != store.DemoMarkerValue {
				t.Errorf("%s alert[%d] missing demo marker label", scenario, i)
			}
		}
	}
}
