// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"testing"

	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/zabbix"
)

func TestBuildEvidenceSummary_UniformMapping(t *testing.T) {
	sum := buildEvidenceSummary(false,
		&MetricEnrichment{Outcome: OutcomeFetched, Snapshots: make([]MetricSnapshot, 21)},
		&LogEnrichment{Source: "loki", Outcome: OutcomeEmpty},
		&ChangeEnrichment{Outcome: OutcomeFetched, Changes: make([]ChangeView, 2)},
		&SentryEnrichment{Outcome: outcomeDegraded},
		nil,
	)
	want := []notify.SourceEvidence{
		{Source: "Prometheus", Unit: "metrics", Count: 21, State: notify.EvidenceCounted},
		{Source: "Loki", Unit: "lines", Count: 0, State: notify.EvidenceCounted},
		{Source: "Changes", Unit: "", Count: 2, State: notify.EvidenceCounted},
		{Source: "Sentry", Unit: "issues", Count: 0, State: notify.EvidenceUnreachable},
	}
	if len(sum.Sources) != len(want) {
		t.Fatalf("got %+v", sum.Sources)
	}
	for i, w := range want {
		if sum.Sources[i] != w {
			t.Errorf("source %d: got %+v want %+v", i, sum.Sources[i], w)
		}
	}
}

func TestBuildEvidenceSummary_MetricDegradedIsNeitherZeroNorUnreachable(t *testing.T) {
	// A metric timeout under load is degraded: the card must not read it as a
	// genuine zero (EvidenceCounted) nor as an outage (EvidenceUnreachable).
	sum := buildEvidenceSummary(false, &MetricEnrichment{Outcome: OutcomeDegraded}, nil, nil, nil, nil)
	if len(sum.Sources) != 1 || sum.Sources[0].State != notify.EvidenceDegraded {
		t.Fatalf("degraded metric must map to EvidenceDegraded, got %+v", sum.Sources)
	}
}

func TestBuildEvidenceSummary_ShortCircuitAndNoSources(t *testing.T) {
	// R12: short-circuit → one skipped state, never per-source zeros.
	if sum := buildEvidenceSummary(true, nil, nil, nil, nil, nil); !sum.Skipped || len(sum.Sources) != 0 {
		t.Errorf("short-circuit: got %+v", sum)
	}
	// R6/AE9: no configured sources → explicit no-sources state.
	if sum := buildEvidenceSummary(false, nil, nil, nil, nil, nil); !sum.NoSources || sum.Skipped {
		t.Errorf("no-sources: got %+v", sum)
	}
}

func TestEnrichmentSources_IncludesZabbix(t *testing.T) {
	ar := analysisResult{zabbix: &ZabbixContext{Source: "zabbix", Outcome: OutcomeFetched}}
	sources := enrichmentSources(ar, nil)
	if _, ok := sources["zabbix"]; !ok {
		t.Fatal("zabbix must join the keyed envelope")
	}
}

func TestEvidenceSummary_ZabbixRow(t *testing.T) {
	z := &ZabbixContext{
		Source:   "zabbix",
		Outcome:  OutcomeFetched,
		Operator: &ZabbixOperatorView{Runbook: "r", Dependencies: []zabbix.DepTrigger{{TriggerID: "1", Name: "up"}}},
	}
	sum := buildEvidenceSummary(false, nil, nil, nil, nil, z)
	if len(sum.Sources) != 1 || sum.Sources[0].Source != "Zabbix" {
		t.Fatalf("zabbix row missing: %+v", sum)
	}
	if sum.Sources[0].Count != 2 { // runbook + 1 dependency
		t.Fatalf("count: got %d want 2", sum.Sources[0].Count)
	}
	if sum.Sources[0].State != notify.EvidenceCounted {
		t.Fatalf("state: %v", sum.Sources[0].State)
	}

	failed := &ZabbixContext{Source: "zabbix", Outcome: OutcomeFailed}
	sum2 := buildEvidenceSummary(false, nil, nil, nil, nil, failed)
	if sum2.Sources[0].State != notify.EvidenceUnreachable {
		t.Fatalf("failed context must render unreachable: %v", sum2.Sources[0].State)
	}
}
