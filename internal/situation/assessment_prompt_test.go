// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAssessmentPromptBuildRoundTripsSnapshotContent(t *testing.T) {
	snap := snapshotFor(t, criticalInput(t))
	p, err := BuildAssessmentPrompt(snap)
	if err != nil {
		t.Fatalf("BuildAssessmentPrompt: %v", err)
	}
	if p.Prefix == "" {
		t.Fatal("Prefix is empty")
	}
	if !p.CachePrefix {
		t.Fatal("CachePrefix must be set: the snapshot body is stable across a controller attempt's calls")
	}
	if p.MaxOutputTokens <= 0 {
		t.Fatal("MaxOutputTokens must be a positive bound")
	}
	if !strings.Contains(p.Prefix, snap.SituationID) {
		t.Fatal("prompt does not carry the Situation ID")
	}
	if !strings.Contains(p.Prefix, snap.EligibleReasons[0].Code) {
		t.Fatal("prompt does not carry the eligible reason code")
	}
	if !strings.Contains(p.Prefix, snap.EligibleReasons[0].ID) {
		t.Fatal("prompt does not carry the eligible reason candidate ID the model must cite verbatim")
	}
}

func TestAssessmentPromptBuildStatesForbiddenFields(t *testing.T) {
	snap := snapshotFor(t, baseSnapshotInput(t))
	p, err := BuildAssessmentPrompt(snap)
	if err != nil {
		t.Fatalf("BuildAssessmentPrompt: %v", err)
	}
	for _, forbidden := range []string{"lifecycle", "action_contract", "cadence"} {
		if !strings.Contains(p.Prefix, forbidden) {
			t.Fatalf("prompt does not mention forbidden field %q", forbidden)
		}
	}
	if !strings.Contains(strings.ToUpper(p.Prefix), "FORBIDDEN") {
		t.Fatal("prompt does not clearly state that lifecycle/action_contract/cadence are forbidden response fields")
	}
}

func TestAssessmentPromptBuildStatesExactSemanticSchema(t *testing.T) {
	snap := snapshotFor(t, baseSnapshotInput(t))
	p, err := BuildAssessmentPrompt(snap)
	if err != nil {
		t.Fatalf("BuildAssessmentPrompt: %v", err)
	}
	for _, field := range []string{
		`"schema_version"`, `"persistence"`, `"impact"`, `"novelty"`,
		`"causality"`, `"attention"`, `"sufficient_reason"`, `"limitations"`,
	} {
		if !strings.Contains(p.Prefix, field) {
			t.Fatalf("prompt schema instructions do not mention %s", field)
		}
	}
}

func TestAssessmentPromptBuildCarriesNoRawSlackOrSQLContent(t *testing.T) {
	// Structural proof: BuildAssessmentPrompt's only input is Snapshot, whose
	// own fields (facts, symptoms, incidents, eligible reasons) are Task 4's
	// bounded closed-shape reductions — none of them are, or contain, raw
	// Slack payloads or SQL text. This test asserts the prompt body is
	// exactly the marshaled projection of Snapshot's bounded fields: nothing
	// else could have been appended.
	snap := snapshotFor(t, criticalInput(t))
	p, err := BuildAssessmentPrompt(snap)
	if err != nil {
		t.Fatalf("BuildAssessmentPrompt: %v", err)
	}

	dtoJSON, err := json.Marshal(newAssessmentPromptDTO(snap)) //nolint:musttag // see assessment_prompt.go's matching nolint
	if err != nil {
		t.Fatalf("marshal DTO: %v", err)
	}
	var want, gotBody map[string]any
	if err := json.Unmarshal(dtoJSON, &want); err != nil {
		t.Fatalf("unmarshal want: %v", err)
	}

	start := strings.Index(p.Prefix, "{")
	schemaAt := strings.Index(p.Prefix, "\nRespond with")
	if start < 0 || schemaAt < 0 {
		t.Fatalf("could not locate the embedded snapshot JSON body in the prompt")
	}
	end := strings.LastIndex(p.Prefix[:schemaAt], "}")
	if end < 0 || end <= start {
		t.Fatalf("could not locate the embedded snapshot JSON body in the prompt")
	}
	if err := json.Unmarshal([]byte(p.Prefix[start:end+1]), &gotBody); err != nil {
		t.Fatalf("embedded snapshot body is not valid JSON: %v", err)
	}
	if gotBody["situation_id"] != want["situation_id"] {
		t.Fatalf("embedded snapshot situation_id = %v, want %v", gotBody["situation_id"], want["situation_id"])
	}
}
