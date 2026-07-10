// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"testing"

	"github.com/alertint/alertint-agent/internal/notify"
)

func TestBuildEvidenceSummary_UniformMapping(t *testing.T) {
	sum := buildEvidenceSummary(false,
		&MetricEnrichment{Outcome: OutcomeFetched, Snapshots: make([]MetricSnapshot, 21)},
		&LogEnrichment{Source: "loki", Outcome: OutcomeEmpty},
		&ChangeEnrichment{Outcome: OutcomeFetched, Changes: make([]ChangeView, 2)},
		&SentryEnrichment{Outcome: outcomeDegraded},
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
	sum := buildEvidenceSummary(false, &MetricEnrichment{Outcome: OutcomeDegraded}, nil, nil, nil)
	if len(sum.Sources) != 1 || sum.Sources[0].State != notify.EvidenceDegraded {
		t.Fatalf("degraded metric must map to EvidenceDegraded, got %+v", sum.Sources)
	}
}

func TestBuildEvidenceSummary_ShortCircuitAndNoSources(t *testing.T) {
	// R12: short-circuit → one skipped state, never per-source zeros.
	if sum := buildEvidenceSummary(true, nil, nil, nil, nil); !sum.Skipped || len(sum.Sources) != 0 {
		t.Errorf("short-circuit: got %+v", sum)
	}
	// R6/AE9: no configured sources → explicit no-sources state.
	if sum := buildEvidenceSummary(false, nil, nil, nil, nil); !sum.NoSources || sum.Skipped {
		t.Errorf("no-sources: got %+v", sum)
	}
}
