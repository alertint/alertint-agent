// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestReconciliationCarriesStoredAnalysisWithoutExposingRawOutput(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)
	sid := newSituationForGroup(t, st, "briefing", now)
	_, err := st.db.ExecContext(context.Background(), `UPDATE incidents SET status='analyzed', summary=?, root_cause=?, output_json=?, enrichment_json=?, last_judged_at=? WHERE id=?`,
		"Checkout errors after deployment", "A deployment may have broken checkout.",
		`{"correlation_findings":["Errors and restarts began together"],"private_extra":"RAW_OUTPUT_MUST_NOT_LEAK"}`,
		`{"verification":{"outcome":"degraded","degradation_reason":"verification_source_unavailable"}}`, now.Format(time.RFC3339Nano), "inc-briefing")
	if err != nil {
		t.Fatal(err)
	}
	claim := claimSituation(t, st, sid, "briefing-test", now)
	in, err := st.LoadReconciliationInput(context.Background(), claim, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(in.Analyses)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Checkout errors after deployment", "A deployment may have broken checkout.", "Errors and restarts began together", "degraded"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("reconciliation discarded operator analysis %q", want)
		}
	}
	if strings.Contains(string(raw), "RAW_OUTPUT_MUST_NOT_LEAK") {
		t.Fatal("raw output escaped the bounded analysis projection")
	}
}

// Resolved is the normal persisted state after recovery. An overall supported
// verification result must not hide invalid or unavailable constituent checks.
func TestBriefingResolvedAnalysisRetainsVerificationGaps(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)
	sid := newSituationForGroup(t, st, "resolved-briefing", now)
	_, err := st.db.ExecContext(context.Background(), `UPDATE incidents SET status='resolved',summary='Checkout deployment errors',root_cause='Deployment may explain errors',output_json=?,enrichment_json=?,last_judged_at=? WHERE id=?`,
		`{"analysis_name":"Checkout deployment errors","overall_issue":"Deployment may explain errors","correlation_findings":["Restarts began together"],"severity":"critical","confidence":0.8}`,
		`{"verification":{"outcome":"supported","rounds":[{"queries":[{"outcome":"fetched"},{"outcome":"invalid","params":{"secret":"DO_NOT_PERSIST"}},{"outcome":"failed"}]}]}}`, now.Format(time.RFC3339Nano), "inc-resolved-briefing")
	if err != nil {
		t.Fatal(err)
	}
	claim := claimSituation(t, st, sid, "briefing", now)
	in, err := st.LoadReconciliationInput(context.Background(), claim, now)
	if err != nil {
		t.Fatal(err)
	}
	b := situation.BuildOperatorBriefing(in, model.LifecycleRecovered)
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"historical":true`, `"verification":"supported"`, `"verification_gaps":2`, "Deployment may explain errors"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("missing %s in %s", want, raw)
		}
	}
	if strings.Contains(string(raw), "DO_NOT_PERSIST") {
		t.Fatal("query parameters leaked")
	}
}

func TestBriefingSnapshotBoundsAndMissingProvenance(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)
	sid := newSituationForGroup(t, st, "bounds", now)
	huge := strings.Repeat("evidence ", 10000)
	_, err := st.db.ExecContext(context.Background(), `UPDATE incidents SET status='analyzed',summary=?,root_cause=?,output_json=?,enrichment_json='malformed',last_judged_at=NULL WHERE id='inc-bounds'`, huge, huge, `{"correlation_findings":["`+huge+`","second","third","fourth"],"secret":"PRIVATE_OUTPUT"}`)
	if err != nil {
		t.Fatal(err)
	}
	claim := claimSituation(t, st, sid, "bounds", now)
	in, err := st.LoadReconciliationInput(context.Background(), claim, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(in.Analyses)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 2500 || strings.Contains(string(raw), "PRIVATE_OUTPUT") || strings.Contains(string(raw), "fourth") {
		t.Fatalf("snapshot analysis not bounded: %d bytes", len(raw))
	}
	if !strings.Contains(string(raw), "…") {
		t.Fatalf("truncation is silent: %s", raw)
	}
	if len(in.Analyses) != 1 || !in.Analyses[0].Stale || in.Analyses[0].AnalyzedAt != nil || in.Analyses[0].Verification != "" {
		t.Fatalf("invented missing provenance: %s", raw)
	}
}

func TestBriefingSelectionReportsTotalCompletedAnalyses(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)
	sid := newSituationForGroup(t, st, "selection", now)
	for i := 0; i < 4; i++ {
		id := fmt.Sprintf("selected-%d", i)
		if err := st.InsertIncident(context.Background(), Incident{ID: id, GroupKey: id, FirstAlertAt: now, LastAlertAt: now, ReadyAt: now}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(context.Background(), `UPDATE incidents SET status='resolved',summary='Completed analysis',root_cause='Possible deployment failure',last_judged_at=? WHERE id=?`, now.Add(time.Duration(i)*time.Minute).Format(time.RFC3339Nano), id); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(context.Background(), `INSERT INTO situation_incidents (situation_id,incident_id,attached_at) VALUES (?,?,?)`, sid, id, now.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	claim := claimSituation(t, st, sid, "selection", now)
	in, err := st.LoadReconciliationInput(context.Background(), claim, now)
	if err != nil {
		t.Fatal(err)
	}
	b := situation.BuildOperatorBriefing(in, model.LifecycleRecovered)
	if len(in.Analyses) != 3 || b.AnalysisCount != 4 || in.Analyses[0].IncidentID != "selected-3" {
		t.Fatalf("selection must be newest 3 with honest total: %+v", b)
	}
}

// B0 compatibility port: the coherent load carries each immutable delivery's
// already-decoded labels into situation.Delivery.Labels (the same row
// Severity/Drill are read from), so the briefing can name scope and alerts
// without the pure package ever parsing labels_json.
func TestLoadReconciliationInputCarriesDeliveryLabels(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)
	sid := seedReconcileSituation(t, st, "labels", now)
	claim := claimSituation(t, st, sid, "labels-test", now)
	in, err := st.LoadReconciliationInput(context.Background(), claim, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Deliveries) == 0 {
		t.Fatal("seeded situation has no deliveries")
	}
	for _, d := range in.Deliveries {
		if d.Labels == nil || d.Labels["severity"] != d.Severity {
			t.Fatalf("delivery %s labels not loaded coherently with severity: %+v", d.ID, d.Labels)
		}
	}
}
