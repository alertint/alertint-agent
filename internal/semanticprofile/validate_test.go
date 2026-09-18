// SPDX-License-Identifier: FSL-1.1-ALv2

package semanticprofile

import (
	"strings"
	"testing"

	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
)

func validProfileJSON() string {
	return `{"subject_kind":"service","event_kind":"availability","possible_role":"symptom",
	"candidate_scope":["service"],"companion_signal_kinds":[],"horizon_tier":"hours",
	"useful_capabilities":["prometheus_query"],"uncertainty":[]}`
}

func TestParseProfileAcceptsWellFormedProfile(t *testing.T) {
	p, err := ParseProfile([]byte(validProfileJSON()))
	if err != nil {
		t.Fatal(err)
	}
	if p.SubjectKind != "service" || p.HorizonTier != "hours" {
		t.Fatalf("unexpected parse result: %+v", p)
	}
}

func TestParseProfileRejectsDuplicateKeys(t *testing.T) {
	raw := `{"subject_kind":"service","subject_kind":"other","event_kind":"availability",
	"possible_role":"symptom","candidate_scope":[],"companion_signal_kinds":[],
	"horizon_tier":"hours","useful_capabilities":[],"uncertainty":[]}`
	if _, err := ParseProfile([]byte(raw)); err == nil {
		t.Fatal("expected duplicate-key rejection")
	} else if !strings.Contains(err.Error(), "duplicate json key") {
		t.Fatalf("expected duplicate-key error, got: %v", err)
	}
}

func TestParseProfileRejectsForbiddenNestedPolicyField(t *testing.T) {
	// Pinned adversarial fixture: a model response that adds policy/action
	// fields the closed eight-field schema never declares.
	raw := `{"subject_kind":"service","event_kind":"availability","possible_role":"symptom",
	"candidate_scope":["service"],"companion_signal_kinds":[],"horizon_tier":"hours",
	"useful_capabilities":["prometheus_query"],"uncertainty":[],
	"attention":"observe","apply_envelope":true}`
	if _, err := ParseProfile([]byte(raw)); err == nil {
		t.Fatal("expected forbidden-field rejection")
	}
}

func TestParseProfileRejectsUnknownEnumHorizonTier(t *testing.T) {
	raw := `{"subject_kind":"service","event_kind":"availability","possible_role":"symptom",
	"candidate_scope":[],"companion_signal_kinds":[],"horizon_tier":"forever",
	"useful_capabilities":[],"uncertainty":[]}`
	if _, err := ParseProfile([]byte(raw)); err == nil {
		t.Fatal("expected unknown horizon_tier rejection")
	}
}

func TestParseProfileRejectsUnknownCapability(t *testing.T) {
	raw := `{"subject_kind":"service","event_kind":"availability","possible_role":"symptom",
	"candidate_scope":[],"companion_signal_kinds":[],"horizon_tier":"hours",
	"useful_capabilities":["invent_a_tool"],"uncertainty":[]}`
	if _, err := ParseProfile([]byte(raw)); err == nil {
		t.Fatal("expected unknown-capability rejection")
	}
}

func TestValidateProfileRejectsNineArrayValues(t *testing.T) {
	nine := make([]string, 9)
	for i := range nine {
		nine[i] = "service"
	}
	p := profilemodel.Profile{
		SubjectKind: "service", EventKind: "availability", PossibleRole: "symptom",
		CandidateScope: nine, HorizonTier: profilemodel.HorizonHours,
	}
	if err := ValidateProfile(p); err == nil {
		t.Fatal("expected 9-array-value rejection")
	}
}

func TestValidateProfileAcceptsEightArrayValues(t *testing.T) {
	eight := make([]string, 8)
	for i := range eight {
		eight[i] = "service"
	}
	p := profilemodel.Profile{
		SubjectKind: "service", EventKind: "availability", PossibleRole: "symptom",
		CandidateScope: eight, HorizonTier: profilemodel.HorizonHours,
	}
	if err := ValidateProfile(p); err != nil {
		t.Fatalf("expected 8-array-value profile accepted: %v", err)
	}
}

func TestValidateProfileRejectsOversizeMeaningField(t *testing.T) {
	p := profilemodel.Profile{
		SubjectKind: strings.Repeat("a", profilemodel.MaxMeaningFieldChars+1),
		EventKind:   "availability", PossibleRole: "symptom", HorizonTier: profilemodel.HorizonHours,
	}
	if err := ValidateProfile(p); err == nil {
		t.Fatal("expected oversize meaning field rejection")
	}
}

func TestValidateProfileRejectsOversizeUncertaintyEntry(t *testing.T) {
	p := profilemodel.Profile{
		SubjectKind: "service", EventKind: "availability", PossibleRole: "symptom",
		HorizonTier: profilemodel.HorizonHours,
		Uncertainty: []string{strings.Repeat("a", profilemodel.MaxUncertaintyChars+1)},
	}
	if err := ValidateProfile(p); err == nil {
		t.Fatal("expected oversize uncertainty entry rejection")
	}
}

func TestValidateProfileRejectsMissingRequiredField(t *testing.T) {
	p := profilemodel.Profile{EventKind: "availability", PossibleRole: "symptom", HorizonTier: profilemodel.HorizonHours}
	if err := ValidateProfile(p); err == nil {
		t.Fatal("expected missing subject_kind rejection")
	}
}
