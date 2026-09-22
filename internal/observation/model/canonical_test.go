// SPDX-License-Identifier: FSL-1.1-ALv2

package model

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCanonicalPlanIDIgnoresMapOrderAndOwnID(t *testing.T) {
	end := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	p := Plan{Capability: "prometheus_query", Phase: "assessment",
		Scope: Scope{GroupKey: "service=checkout", Source: "alertmanager",
			SubjectID: "signal-a", Labels: map[string]string{"service": "checkout", "cluster": "lab"}},
		Parameters: []byte(`{"expression":"up{service=\"checkout\",cluster=\"lab\"}"}`),
		Start:      end.Add(-15 * time.Minute), End: end, EligibleAt: end,
		Limit: 20, MaxRequests: 1, Purpose: "corroborate_member"}
	a, err := CanonicalPlanID("cycle-a", p)
	if err != nil {
		t.Fatal(err)
	}
	p.ID = "previously-assigned-id"
	p.Scope.Labels = map[string]string{"cluster": "lab", "service": "checkout"}
	b, err := CanonicalPlanID("cycle-a", p)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("identity changed: %s != %s", a, b)
	}
	c, err := CanonicalPlanID("cycle-b", p)
	if err != nil {
		t.Fatal(err)
	}
	if c == a {
		t.Fatal("different cycle reused identity")
	}
}

func basePlan(end time.Time) Plan {
	return Plan{
		Capability: CapabilityPrometheusQuery, Phase: PhaseAssessment,
		Scope: Scope{GroupKey: "service=checkout", Source: "alertmanager", SubjectID: "signal-a",
			Labels: map[string]string{"service": "checkout"}},
		Parameters: []byte(`{"expression":"up{service=\"checkout\"}"}`),
		Start:      end.Add(-15 * time.Minute), End: end, EligibleAt: end,
		Limit: 20, MaxRequests: 1, Purpose: "corroborate_member",
	}
}

func TestCanonicalPlanIDReorderedParameterKeysIdentical(t *testing.T) {
	end := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	p1 := basePlan(end)
	p1.Parameters = []byte(`{"a":1,"b":2,"c":{"x":1,"y":2}}`)
	p2 := basePlan(end)
	p2.Parameters = []byte(`{"c":{"y":2,"x":1},"b":2,"a":1}`)

	id1, err := CanonicalPlanID("cycle-a", p1)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := CanonicalPlanID("cycle-a", p2)
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Fatalf("reordered parameter keys changed identity: %s != %s", id1, id2)
	}
}

func TestCanonicalPlanIDDuplicateParameterKeyRejected(t *testing.T) {
	end := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	p := basePlan(end)
	p.Parameters = []byte(`{"a":1,"a":2}`)
	if _, err := CanonicalPlanID("cycle-a", p); err == nil {
		t.Fatal("expected duplicate-key rejection, got nil error")
	} else if !strings.Contains(err.Error(), "duplicate json key") {
		t.Fatalf("expected duplicate-key error, got: %v", err)
	}
}

func TestCanonicalPlanIDNonUTCTimeNormalizesSameAsUTC(t *testing.T) {
	loc := time.FixedZone("UTC+3", 3*60*60)
	endUTC := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	endLocal := endUTC.In(loc)

	pUTC := basePlan(endUTC)
	pLocal := basePlan(endUTC)
	pLocal.Start = pLocal.Start.In(loc)
	pLocal.End = endLocal
	pLocal.EligibleAt = endLocal

	idUTC, err := CanonicalPlanID("cycle-a", pUTC)
	if err != nil {
		t.Fatal(err)
	}
	idLocal, err := CanonicalPlanID("cycle-a", pLocal)
	if err != nil {
		t.Fatal(err)
	}
	if idUTC != idLocal {
		t.Fatalf("equivalent instants in different zones changed identity: %s != %s", idUTC, idLocal)
	}
}

func TestCanonicalPlanIDOversizeParametersRejected(t *testing.T) {
	end := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	p := basePlan(end)
	huge := strings.Repeat("a", MaxPlanParametersBytes+1)
	p.Parameters = []byte(`{"blob":"` + huge + `"}`)
	if _, err := CanonicalPlanID("cycle-a", p); err == nil {
		t.Fatal("expected oversize parameters rejection")
	}
}

func TestValidatePlanRejectsUnknownCapability(t *testing.T) {
	end := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	p := basePlan(end)
	p.Capability = "invented_capability"
	if err := ValidatePlan(p); err == nil {
		t.Fatal("expected unknown-capability rejection")
	}
}

func TestValidatePlanRejectsUnknownPhase(t *testing.T) {
	end := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	p := basePlan(end)
	p.Phase = "warmup"
	if err := ValidatePlan(p); err == nil {
		t.Fatal("expected unknown-phase rejection")
	}
}

func TestValidatePlanRejectsWindowOverHardCap(t *testing.T) {
	end := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	p := basePlan(end)
	p.Capability = CapabilityPrometheusQuery
	p.Start = end.Add(-25 * time.Hour) // hard cap is 24h for metrics
	if err := ValidatePlan(p); err == nil {
		t.Fatal("expected window-over-cap rejection")
	}
}

func TestValidatePlanAllowsSevenDayWindowForHistoryCapabilities(t *testing.T) {
	end := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	p := basePlan(end)
	p.Capability = CapabilityZabbixProblemHist
	p.Start = end.Add(-6 * 24 * time.Hour) // within the 7d cap
	if err := ValidatePlan(p); err != nil {
		t.Fatalf("expected 6-day window accepted for history capability: %v", err)
	}
}

func TestValidatePlanRejectsNegativeLimits(t *testing.T) {
	end := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	p := basePlan(end)
	p.Limit = -1
	if err := ValidatePlan(p); err == nil {
		t.Fatal("expected negative-limit rejection")
	}
}

func TestValidateRunRejectsTooManyFacts(t *testing.T) {
	facts := make([]Fact, MaxFactsPerRun+1)
	for i := range facts {
		facts[i] = Fact{ID: "f", ResultStatus: ResultConfirmedEmpty, Freshness: FreshnessFresh}
	}
	r := Run{ID: "r1", CycleID: "c1", PlanID: "p1", Status: ResultConfirmedEmpty, Facts: facts}
	if err := ValidateRun(r); err == nil {
		t.Fatal("expected too-many-facts rejection")
	}
}

func TestValidateRunRejectsUnknownResultStatus(t *testing.T) {
	r := Run{ID: "r1", CycleID: "c1", PlanID: "p1", Status: "not_a_real_status"}
	if err := ValidateRun(r); err == nil {
		t.Fatal("expected unknown-status rejection")
	}
}

func TestValidateRunRejectsFactBelongingToAnotherRun(t *testing.T) {
	r := Run{ID: "r1", CycleID: "c1", PlanID: "p1", Status: ResultConfirmedEmpty,
		Facts: []Fact{{ID: "f1", RunID: "other-run", ResultStatus: ResultConfirmedEmpty, Freshness: FreshnessFresh}}}
	if err := ValidateRun(r); err == nil {
		t.Fatal("expected cross-run fact rejection")
	}
}

func TestMaterialDigestExcludesNonMaterialAndCollectionChurn(t *testing.T) {
	now := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	facts1 := []Fact{
		{ID: "f1", RunID: "run-a", Kind: "metric_summary", Subject: "signal-a",
			SchemaVersion: 2, Value: []byte(`{"up":1}`), ResultStatus: ResultConfirmedValue,
			Freshness: FreshnessFresh, ObservedAt: now, Material: true},
		{ID: "f2", RunID: "run-a", Kind: "metric_summary", Subject: "signal-b",
			SchemaVersion: 2, Value: []byte(`{"up":0}`), ResultStatus: ResultConfirmedValue,
			Freshness: FreshnessFresh, ObservedAt: now, Material: false}, // excluded: not material
	}
	facts2 := []Fact{
		{ID: "f1-again", RunID: "run-b", Kind: "metric_summary", Subject: "signal-a",
			SchemaVersion: 2, Value: []byte(`{"up":1}`), ResultStatus: ResultConfirmedValue,
			Freshness: FreshnessFresh, ObservedAt: now.Add(5 * time.Minute), Material: true},
		{ID: "f2-again", RunID: "run-b", Kind: "metric_summary", Subject: "signal-b",
			SchemaVersion: 2, Value: []byte(`{"up":42}`), ResultStatus: ResultConfirmedValue,
			Freshness: FreshnessFresh, ObservedAt: now.Add(5 * time.Minute), Material: false},
	}

	d1, err := MaterialDigest(facts1)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := MaterialDigest(facts2)
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatalf("collection churn and non-material changes altered material digest: %s != %s", d1, d2)
	}
}

func TestMaterialDigestChangesWhenMaterialValueChanges(t *testing.T) {
	now := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	f := func(up int) []Fact {
		return []Fact{{ID: "f1", RunID: "run-a", Kind: "metric_summary", Subject: "signal-a",
			SchemaVersion: 2, Value: []byte(`{"up":` + strconv.Itoa(up) + `}`), ResultStatus: ResultConfirmedValue,
			Freshness: FreshnessFresh, ObservedAt: now, Material: true}}
	}
	d1, err := MaterialDigest(f(1))
	if err != nil {
		t.Fatal(err)
	}
	d2, err := MaterialDigest(f(0))
	if err != nil {
		t.Fatal(err)
	}
	if d1 == d2 {
		t.Fatal("changed material metric value did not change material digest")
	}
}
