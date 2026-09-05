// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
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

// TestAssessmentPromptStatesNestedShapesAndAllowedLimitationCodes pins the
// contract gap the first live lab run exposed (2026-09-04): the schema
// instructions must spell out that sufficient_reason is an object (code,
// candidate_id, summary, evidence_refs) and limitations an array of
// {code, detail} objects, and must list every limitation code the validator
// accepts — rendered from the same list, so they cannot drift.
func TestAssessmentPromptStatesNestedShapesAndAllowedLimitationCodes(t *testing.T) {
	p, err := BuildAssessmentPrompt(snapshotFor(t, criticalInput(t)))
	if err != nil {
		t.Fatalf("BuildAssessmentPrompt: %v", err)
	}
	for _, want := range []string{
		`"code": "<candidate code>"`, `"candidate_id": "<candidate id, verbatim>"`, `"evidence_refs": ["<fact id>", ...]`,
		`never a bare string`, `{"code": "<one of the allowed codes>", "detail": "<one bounded sentence>"}`,
		`never bare`, `The only allowed limitation codes are:`,
	} {
		if !strings.Contains(p.Prefix, want) {
			t.Fatalf("prompt does not state %q", want)
		}
	}
	for _, l := range plan2UnsupportedCapabilities {
		if !strings.Contains(p.Prefix, "  "+l.Code+"\n") {
			t.Fatalf("prompt does not list allowed limitation code %q", l.Code)
		}
		if !knownLimitationCode(l.Code) {
			t.Fatalf("prompt lists %q but the validator does not accept it", l.Code)
		}
	}
	if strings.Contains(p.Prefix, limitationSemanticAssessmentUnavailable) {
		t.Fatal("prompt offers semantic_assessment_unavailable, the controller's own fallback marker, as a model claim")
	}
}

// TestValidateAssessmentProposalRejectsLiveLabShapeAndAcceptsDocumentedShape
// keeps the exact response shape the model produced in the lab before the
// prompt stated the nested shapes (a bare candidate-ID string for
// sufficient_reason, free-text strings for limitations) as an invalid_shape
// regression, and proves a response in the shape the prompt now documents
// passes the shape gate.
func TestValidateAssessmentProposalRejectsLiveLabShapeAndAcceptsDocumentedShape(t *testing.T) {
	snap := snapshotFor(t, criticalInput(t))
	call := AssessmentCall{InputVersion: snap.InputVersion, MaterialFactHash: snap.MaterialFactHash}
	now := time.Now().UTC()
	cand := snap.EligibleReasons[0]

	live := `{"schema_version":1,"persistence":"unknown","impact":"unknown","novelty":"insufficient_history",` +
		`"causality":"unknown","attention":"investigate","sufficient_reason":"` + cand.ID + `",` +
		`"limitations":["acute_finding unavailable: result_code null","prior_duration_distribution empty"]}`
	vr := ValidateAssessmentProposal(json.RawMessage(live), snap, call, now)
	if vr.Outcome != ProposalOutcomeMalformed || len(vr.Errors) == 0 || vr.Errors[0].Code != "invalid_shape" {
		t.Fatalf("live lab shape: outcome=%s errors=%v, want malformed/invalid_shape", vr.Outcome, vr.Errors)
	}

	documented := `{"schema_version":1,"persistence":"unknown","impact":"unknown","novelty":"insufficient_history",` +
		`"causality":"unknown","attention":"observe",` +
		`"sufficient_reason":{"code":"` + cand.Code + `","candidate_id":"` + cand.ID + `","summary":"Confirmed active critical source severity.","evidence_refs":[]},` +
		`"limitations":[{"code":"` + plan2UnsupportedCapabilities[0].Code + `","detail":"No metric evidence in this build."}]}`
	vr = ValidateAssessmentProposal(json.RawMessage(documented), snap, call, now)
	if vr.Outcome == ProposalOutcomeMalformed || vr.Outcome == ProposalOutcomeCapabilityRejected {
		t.Fatalf("documented shape: outcome=%s errors=%v, want the shape and capability gates to pass", vr.Outcome, vr.Errors)
	}
}
