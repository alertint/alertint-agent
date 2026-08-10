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

func mustMaterialize(t *testing.T, scenario string, keys []string, runID string) drillRun {
	t.Helper()
	sc, ok := drillScenarios()[scenario]
	if !ok {
		t.Fatalf("unknown scenario %q", scenario)
	}
	run, err := materializeScenario(sc, keys, runID, runID, time.Now().UTC())
	if err != nil {
		t.Fatalf("materialize %s: %v", scenario, err)
	}
	return run
}

func TestMaterialize_ReceiverGroupingMode(t *testing.T) {
	run := mustMaterialize(t, "flagship", nil, "source1")
	if run.expectedGroupKey == "" {
		t.Fatal("Receiver grouping mode produced an empty expected group key")
	}
	if len(run.alerts.GroupLabels) == 0 {
		t.Fatal("Receiver grouping mode must supply Alertmanager groupLabels")
	}
	if got := drillGroupKey(run.alerts.GroupLabels); got != run.expectedGroupKey {
		t.Fatalf("payload groupLabels key = %q, want expected key %q", got, run.expectedGroupKey)
	}
}

// TestMaterialize_SingleGroupKey: every burst alert carries the identical
// adapted group-label set, so the whole Drill correlates into one incident,
// and the expected group key is the correlator's sorted k=v join.
func TestMaterialize_SingleGroupKey(t *testing.T) {
	run := mustMaterialize(t, "flagship", defaultGroupLabels, "4f2a1b")

	want := "cluster=drill-cluster-4f2a1b,namespace=drill-shop,service=drill-checkout"
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

// TestMaterialize_CustomGroupLabels: unknown keys get drill-<key> values on
// every alert; the first configured key is run-salted. A target grouping by
// alertname still gets one homogeneous incident (group labels win).
func TestMaterialize_CustomGroupLabels(t *testing.T) {
	run := mustMaterialize(t, "flagship", []string{"team", "region"}, "aa11bb")
	for i, a := range run.alerts.Alerts {
		if a.Labels["team"] != "drill-team-aa11bb" || a.Labels["region"] != "drill-region" {
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
	sc := drillScenarios()["flagship"]
	run, err := materializeScenario(sc, defaultGroupLabels, "e3f4a5", "e3f4a5", now)
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
		t.Fatalf("ParseChange rejects drill change payload: %v", err)
	}
	if len(changes) != 1 || changes[0].Kind != "deploy" || !strings.Contains(changes[0].Title, "checkout") {
		t.Errorf("parsed change = %+v, want one deploy naming checkout", changes)
	}
}

// TestMaterialize_ReceiverContract: the burst satisfies the Alertmanager v4
// receiver contract (version, fingerprint, status, startsAt) and every Drill
// alert carries the reserved marker (ADR-0013).
func TestMaterialize_ReceiverContract(t *testing.T) {
	for _, scenario := range []string{"flagship", "storm"} {
		run := mustMaterialize(t, scenario, defaultGroupLabels, "0d0d0d")
		if n := len(run.alerts.Alerts); n == 0 || n > maxDrillAlerts {
			t.Fatalf("%s: %d alerts, want 1..%d", scenario, n, maxDrillAlerts)
		}

		body, err := json.Marshal(run.alerts)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		payload, err := ingress.ParseAlertmanager(body)
		if err != nil {
			t.Fatalf("%s: ParseAlertmanager rejects drill payload: %v", scenario, err)
		}
		for i, a := range payload.Alerts {
			if a.Fingerprint == "" || a.Status != "firing" || a.StartsAt.IsZero() {
				t.Errorf("%s alert[%d] violates receiver contract: %+v", scenario, i, a)
			}
			if a.Labels[store.DrillMarkerLabel] != store.DrillMarkerValue {
				t.Errorf("%s alert[%d] missing drill marker label", scenario, i)
			}
		}
	}
}

// TestMaterialize_StormAlertsDistinct: Alertmanager v2 identifies alerts by
// their full label set, so storm alerts must be pairwise distinct or
// --via-alertmanager collapses the burst into one alert.
func TestMaterialize_StormAlertsDistinct(t *testing.T) {
	run := mustMaterialize(t, "storm", defaultGroupLabels, "aabb01")
	seen := map[string]bool{}
	for i, a := range run.alerts.Alerts {
		key := drillGroupKey(a.Labels) // full-label sorted join as identity
		if seen[key] {
			t.Fatalf("alert[%d] label set duplicates an earlier alert: %s", i, key)
		}
		seen[key] = true
	}
}

// TestMaterialize_DBOutage: the cascade scenario plants no change event
// (contrast with flagship: the finding must point at the database, not a
// deploy) and materializes as four distinct-symptom alerts in one group.
func TestMaterialize_DBOutage(t *testing.T) {
	sc, ok := drillScenarios()["db-outage"]
	if !ok {
		t.Fatal("db-outage missing from the catalog")
	}
	if sc.change != nil {
		t.Error("db-outage must not plant a change event — the cascade has no deploy to blame")
	}

	run := mustMaterialize(t, "db-outage", defaultGroupLabels, "db01aa")
	if got := len(run.alerts.Alerts); got != 4 {
		t.Fatalf("alert count = %d, want 4", got)
	}
	names := map[string]bool{}
	for i, a := range run.alerts.Alerts {
		names[a.Labels["alertname"]] = true
		for _, field := range []string{"summary", "description"} {
			if !strings.HasPrefix(a.Annotations[field], "[drill]") {
				t.Errorf("alert[%d] %s lacks the [drill] prefix", i, field)
			}
		}
		if a.Labels[store.DrillMarkerLabel] != store.DrillMarkerValue {
			t.Errorf("alert[%d] missing the drill marker label", i)
		}
	}
	if len(names) != 4 {
		t.Errorf("distinct alertnames = %d, want 4 (the cascade reads as different symptoms)", len(names))
	}
}
