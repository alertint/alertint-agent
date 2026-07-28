// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

func TestGoverningEntry_CorrectionCarriesAnchorsAndSteers(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	v := &store.IncidentVerdict{
		ID: 7, IncidentID: "inc-a", Version: 3, Verdict: "correction",
		ExpectationJSON: `{"cause_alert":"KubePersistentVolumeFillingUp","cause_series":["kubelet_volume_stats_available_bytes"],"must_mention":["checkout-logs-pvc"],"must_not_conclude":["memory leak"]}`,
		WidenedJSON:     `[{"kind":"promql","source":"capture","expr":"up"}]`,
		Note:            "Real cause was the checkout-logs-pvc filling up",
		CreatedAt:       now.AddDate(0, 0, -4),
	}
	g := governingEntry(v, now)
	if g == nil || !g.Steers || g.Kind != "correction" {
		t.Fatalf("correction must steer, got %+v", g)
	}
	if g.CauseAlert != "KubePersistentVolumeFillingUp" || len(g.CauseSeries) != 1 {
		t.Fatalf("anchors missing: %+v", g)
	}
	if len(g.WidenExprs) != 1 || g.WidenExprs[0] != "up" {
		t.Fatalf("widen exprs missing: %+v", g)
	}
	if g.Age != "4d ago" || g.Date != "2026-07-28" {
		t.Fatalf("age/date wrong: %q %q", g.Age, g.Date)
	}
	if g.VerdictID != 7 || g.Version != 3 {
		t.Fatalf("provenance ids wrong: %+v", g)
	}
}

func TestGoverningEntry_ConfirmationDoesNotSteer(t *testing.T) {
	g := governingEntry(&store.IncidentVerdict{Verdict: "confirmation",
		ExpectationJSON: `{"must_mention":["ok"]}`, CreatedAt: time.Now().UTC()}, time.Now().UTC())
	if g == nil || g.Steers {
		t.Fatalf("confirmation retires steering, got %+v", g)
	}
}

func TestGoverningEntry_NilInNilOut(t *testing.T) {
	if governingEntry(nil, time.Now()) != nil {
		t.Fatal("nil verdict must yield nil entry")
	}
}

func TestBuildSteeringQueries_WidenFirstProbesDedupCap(t *testing.T) {
	g := &GoverningVerdict{Steers: true,
		WidenExprs:  []string{"up", "rate(errors_total[5m])", "up"}, // dup dropped
		CauseSeries: []string{"kubelet_volume_stats_available_bytes", "up", "s3", "s4", "s5", "s6"},
	}
	qs := buildSteeringQueries(g)
	if len(qs) != maxSteeringQueries {
		t.Fatalf("want cap %d, got %d", maxSteeringQueries, len(qs))
	}
	if qs[0].Expr != "up" || qs[1].Expr != "rate(errors_total[5m])" {
		t.Fatalf("widen queries must come first verbatim, got %+v", qs[:2])
	}
	// probe shape: bare metric-name selector, promql kind, operator source
	if qs[2].Expr != "kubelet_volume_stats_available_bytes" || qs[2].Kind != "promql" || qs[2].Source != sourceOperator {
		t.Fatalf("probe shape wrong: %+v", qs[2])
	}
	for _, q := range qs {
		if q.Source != sourceOperator {
			t.Fatalf("every steering query carries the operator source: %+v", q)
		}
	}
}

func TestBuildSteeringQueries_NonSteeringNil(t *testing.T) {
	if buildSteeringQueries(nil) != nil || buildSteeringQueries(&GoverningVerdict{Steers: false, CauseSeries: []string{"x"}}) != nil {
		t.Fatal("only a steering correction contributes queries")
	}
}

func TestOperatorEvidenceFetched(t *testing.T) {
	r := &VerificationRound{Queries: []VerificationQuery{
		{Source: sourceOperator, Outcome: OutcomeEmpty}, // empty carries no sign (ADR-0024)
		{Source: "model", Outcome: OutcomeFetched},      // wrong source
	}}
	if operatorEvidenceFetched(r) {
		t.Fatal("empty operator results and fetched model results must not count")
	}
	r.Queries[0].Outcome = OutcomeFetched
	if !operatorEvidenceFetched(r) {
		t.Fatal("a fetched operator query counts")
	}
	if operatorEvidenceFetched(nil) {
		t.Fatal("nil round: false")
	}
}
