// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"encoding/json"
	"testing"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestReduceFactsKeepsEvidenceStatesDistinctAndCanonical(t *testing.T) {
	facts := []observationmodel.Fact{
		{ID: "fact:z", Kind: "availability", Subject: "db", Value: json.RawMessage(`null`), SourceCapability: observationmodel.CapabilityPrometheusQuery, ObservedAt: time.Date(2026, 8, 20, 10, 0, 0, 0, time.FixedZone("EEST", 3*60*60)), Freshness: observationmodel.FreshnessUnknown, ResultStatus: observationmodel.ResultStatusUnavailable, Digest: "d-z", EvidenceRefs: []string{"run:2", "run:1", "run:1"}, Material: true},
		{ID: "fact:a", Kind: "availability", Subject: "db", Value: json.RawMessage(` { "healthy": true } `), SourceCapability: observationmodel.CapabilityStoreRead, ObservedAt: time.Date(2026, 8, 20, 7, 1, 0, 0, time.UTC), Freshness: observationmodel.FreshnessFresh, ResultStatus: observationmodel.ResultStatusConfirmedValue, Digest: "d-a", Material: true},
	}
	got, err := ReduceFacts(facts)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].ID != "fact:a" || got[1].ID != "fact:z" {
		t.Fatalf("facts = %+v", got)
	}
	if string(got[0].Value) != `{"healthy":true}` || got[1].ObservedAt.Location() != time.UTC {
		t.Fatalf("facts not canonical: %+v", got)
	}
	if got[1].ResultStatus != observationmodel.ResultStatusUnavailable || len(got[1].EvidenceRefs) != 2 {
		t.Fatalf("evidence state/refs changed: %+v", got[1])
	}
	facts[0].EvidenceRefs[0] = "mutated"
	if got[1].EvidenceRefs[1] != "run:2" {
		t.Fatal("reduced facts alias input")
	}
}

func TestReduceFactsRejectsMalformedNormalizedEvidence(t *testing.T) {
	cases := []observationmodel.Fact{
		{ID: "", Value: json.RawMessage(`{}`), ObservedAt: time.Now()},
		{ID: "fact:bad-json", Kind: "impact", Subject: "db", Value: json.RawMessage(`{`), ObservedAt: time.Now()},
	}
	for _, value := range cases {
		if _, err := ReduceFacts([]observationmodel.Fact{value}); err == nil {
			t.Fatalf("accepted malformed fact: %+v", value)
		}
	}
}

func TestCanonicalLimitationsSortAndDeduplicate(t *testing.T) {
	got := canonicalLimitations([]model.Limitation{
		{Code: "source_unavailable", Detail: "zabbix unavailable"},
		{Code: "metrics_unavailable", Detail: "prometheus unavailable"},
		{Code: "source_unavailable", Detail: "zabbix unavailable"},
	})
	if len(got) != 2 || got[0].Code != "metrics_unavailable" || got[1].Code != "source_unavailable" {
		t.Fatalf("limitations = %+v", got)
	}
}
