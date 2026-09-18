// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestReadableVerificationKeepsCompletePurpose(t *testing.T) {
	purpose := strings.Repeat("Check request errors against latency. ", 20) + "complete final purpose"
	raw, err := json.Marshal(map[string]any{"verification": map[string]any{"rounds": []any{map[string]any{"queries": []any{map[string]any{"kind": "promql", "why": purpose, "outcome": "empty"}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	notes := selectedVerificationNotes(string(raw))
	a := model.BoundIncidentAnalysis(model.IncidentAnalysis{VerificationNotes: notes})
	if len(a.VerificationNotes) != 1 || !strings.Contains(a.VerificationNotes[0], purpose) {
		t.Fatalf("lost purpose: %+v", a)
	}
}

func TestReadableInventoryDistinguishesEmptyFromUnavailable(t *testing.T) {
	got := selectedEvidenceSummary(`{"metrics":{"outcome":"fetched","snapshots":[{},{}]},"logs":{"outcome":"failed"},"changes":{"outcome":"empty"}}`)
	for _, want := range []string{"Metric samples: 2", "Log lines: unavailable", "Changes: none returned"} {
		if !strings.Contains(got, want) {
			t.Fatal(got)
		}
	}
	if got := selectedEvidenceSummary(`{}`); got != "" {
		t.Fatal(got)
	}
}

func TestReadableProjectionPreservesSelectedSentences(t *testing.T) {
	full := strings.Repeat("Supporting evidence needs its full qualification. ", 20) + "Final qualification."
	a := model.BoundIncidentAnalysis(model.IncidentAnalysis{Summary: full, Observations: []string{full}})
	if a.Summary != full || a.Observations[0] != full {
		t.Fatal("projection cut selected sentences")
	}
}
