// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"strings"
	"testing"
	"time"
)

func TestRenderChanges_WithChanges(t *testing.T) {
	e := &ChangeEnrichment{
		Changes: []ChangeView{{
			Kind: "deploy", Title: "checkout v1.42.0 → prod", Version: "v1.42.0",
			Link: "https://x/run/1", OccurredAt: time.Now(), MatchCount: 2,
			MatchedOn:           map[string]string{"service": "checkout", "namespace": "prod"},
			DeltaBeforeIncident: "Δ8m before incident start",
		}},
	}
	out := UserPrompt(EvidencePack{}, "{}", nil, nil, e, nil, nil)
	if !strings.Contains(out, "Recent changes") || !strings.Contains(out, "Δ8m before incident start") || !strings.Contains(out, "deploy") {
		t.Fatalf("missing change block: %s", out)
	}
	// formatLabels sorts keys: namespace before service.
	if !strings.Contains(out, "{matched: namespace=prod,service=checkout}") {
		t.Fatalf("missing matched-labels segment: %s", out)
	}
}

func TestRenderChanges_NoteWhenEmpty(t *testing.T) {
	e := &ChangeEnrichment{Note: "no changes in window"}
	out := UserPrompt(EvidencePack{}, "{}", nil, nil, e, nil, nil)
	if !strings.Contains(out, "Recent changes: no changes in window") {
		t.Fatalf("missing note: %s", out)
	}
}

func TestRenderChanges_OmittedWhenNil(t *testing.T) {
	out := UserPrompt(EvidencePack{}, "{}", nil, nil, nil, nil, nil)
	if strings.Contains(out, "Recent changes") {
		t.Fatalf("changes section must be omitted when nil: %s", out)
	}
}
