// SPDX-License-Identifier: FSL-1.1-ALv2

package model

import (
	"encoding/json"
	"testing"
	"time"
)

// enumValidator lets the table test below drive every closed-enum type
// through the same Validate() call without type-specific plumbing.
type enumValidator interface{ Validate() error }

func TestEnumValidateClosesOverKnownValues(t *testing.T) {
	cases := []struct {
		name  string
		valid []enumValidator
		bogus enumValidator
	}{
		{
			name:  "Persistence",
			valid: []enumValidator{PersistenceTransient, PersistenceSustained, PersistenceUnknown},
			bogus: Persistence("bogus"),
		},
		{
			name:  "Impact",
			valid: []enumValidator{ImpactNoneObserved, ImpactSuspected, ImpactConfirmed, ImpactUnknown},
			bogus: Impact("bogus"),
		},
		{
			name:  "Novelty",
			valid: []enumValidator{NoveltyFamiliar, NoveltyChanged, NoveltyNew, NoveltyInsufficientHistory},
			bogus: Novelty("bogus"),
		},
		{
			name:  "Causality",
			valid: []enumValidator{CausalitySupported, CausalityCorrelated, CausalityContradicted, CausalityUnknown, CausalityOperatorConfirmed},
			bogus: Causality("bogus"),
		},
		{
			name:  "EvidenceQuality",
			valid: []enumValidator{EvidenceQualityComplete, EvidenceQualityDegraded, EvidenceQualityInsufficient},
			bogus: EvidenceQuality("bogus"),
		},
		{
			name:  "NextActor",
			valid: []enumValidator{NextActorAlertINT, NextActorOperator, NextActorNone},
			bogus: NextActor("bogus"),
		},
		{
			name:  "AlertINTAction",
			valid: []enumValidator{AlertINTActionRunAcuteTriage, AlertINTActionRetrySituationAssessment, AlertINTActionMonitorSituation, AlertINTActionVerifyRecovery},
			bogus: AlertINTAction("bogus"),
		},
		{
			name:  "AlertINTStatus",
			valid: []enumValidator{AlertINTStatusPlanned, AlertINTStatusRunning, AlertINTStatusWaiting, AlertINTStatusBlocked, AlertINTStatusExhausted, AlertINTStatusComplete},
			bogus: AlertINTStatus("bogus"),
		},
		{
			name:  "OperatorAction",
			valid: []enumValidator{OperatorActionInvestigateSituation},
			bogus: OperatorAction("bogus"),
		},
		{
			name: "NextUpdateOn",
			valid: []enumValidator{
				NextUpdateOnMaterialInput, NextUpdateOnTriageOutcome, NextUpdateOnSourceResolution,
				NextUpdateOnSourceRefire, NextUpdateOnDependencyRecovery, NextUpdateOnAssessmentRetryDue,
				NextUpdateOnRecoveryGraceExpired, NextUpdateOnLifecycleObservationDeadline,
			},
			bogus: NextUpdateOn("bogus"),
		},
		{
			name: "WaitReason",
			valid: []enumValidator{
				WaitReasonAcuteTriageDecision, WaitReasonAcuteTriageBackoff, WaitReasonAssessmentRetry,
				WaitReasonAssessmentParked, WaitReasonSourceChange, WaitReasonRecoveryGrace,
			},
			bogus: WaitReason("bogus"),
		},
		{
			name:  "Cadence",
			valid: []enumValidator{Cadence(""), CadenceFast, CadenceNormal, CadenceSlow},
			bogus: Cadence("bogus"),
		},
		{
			name:  "AssessmentDerivation",
			valid: []enumValidator{DerivationModelValidated, DerivationDeterministic, DerivationDeterministicFallback, DerivationRevalidatedReuse},
			bogus: AssessmentDerivation("bogus"),
		},
		{
			name:  "ProviderRequestStarted",
			valid: []enumValidator{ProviderRequestStartedTrue, ProviderRequestStartedFalse, ProviderRequestStartedUnknown},
			bogus: ProviderRequestStarted("bogus"),
		},
		{
			name:  "FactResultStatus",
			valid: []enumValidator{FactConfirmedValue, FactConfirmedEmpty, FactUnavailable, FactFailed, FactStale},
			bogus: FactResultStatus("bogus"),
		},
		{
			name:  "Lifecycle",
			valid: []enumValidator{LifecycleActive, LifecycleRecoveryPending, LifecycleRecovered, LifecycleClosedUnknown},
			bogus: Lifecycle("bogus"),
		},
		{
			name:  "Attention",
			valid: []enumValidator{AttentionObserve, AttentionInvestigate, AttentionUrgent},
			bogus: Attention("bogus"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, v := range tc.valid {
				if err := v.Validate(); err != nil {
					t.Errorf("valid value %v: unexpected error: %v", v, err)
				}
			}
			if err := tc.bogus.Validate(); err == nil {
				t.Errorf("bogus value %v: want error, got nil", tc.bogus)
			}
		})
	}
}

// roundTrip marshals v, unmarshals into a fresh zero value of the same type,
// remarshals, and returns both JSON encodings so callers can assert losslessness
// without fussing over time.Time comparison semantics.
func roundTrip[T any](t *testing.T, v T) (before, after []byte) {
	t.Helper()
	before, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out T
	if err := json.Unmarshal(before, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	after, err = json.Marshal(out)
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	return before, after
}

func samplePointer[T any](v T) *T { return &v }

func fullActionContract(now time.Time) ActionContract {
	action := AlertINTActionRunAcuteTriage
	status := AlertINTStatusPlanned
	return ActionContract{
		NextActor:              NextActorAlertINT,
		AlertINTAction:         &action,
		AlertINTStatus:         &status,
		OperatorActionRequired: nil,
		NextUpdateAt:           samplePointer(now.Add(time.Hour)),
		NextUpdateOn:           []NextUpdateOn{NextUpdateOnMaterialInput, NextUpdateOnTriageOutcome},
		WaitReason:             nil,
	}
}

func fullAssessment(now time.Time) Assessment {
	return Assessment{
		SchemaVersion:   AssessmentSchemaVersion,
		Persistence:     PersistenceSustained,
		Impact:          ImpactConfirmed,
		Novelty:         NoveltyChanged,
		Causality:       CausalitySupported,
		Attention:       AttentionInvestigate,
		Lifecycle:       LifecycleActive,
		EvidenceQuality: EvidenceQualityComplete,
		SufficientReason: &SufficientReason{
			Code:         "duration_milestone",
			CandidateID:  "reason-candidate-1",
			Summary:      "sustained beyond the milestone threshold",
			EvidenceRefs: []string{"fact-1", "fact-2"},
		},
		ActionContract: fullActionContract(now),
		Limitations: []Limitation{
			{Code: "semantic_assessment_unavailable", Detail: "L2 provider unavailable"},
		},
		Cadence: CadenceFast,
	}
}

func TestAssessmentJSONRoundTrip(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	before, after := roundTrip(t, fullAssessment(now))
	if string(before) != string(after) {
		t.Fatalf("round trip not lossless:\nbefore: %s\nafter:  %s", before, after)
	}
}

func TestFactJSONRoundTrip(t *testing.T) {
	f := Fact{
		ID:           "fact-1",
		SituationID:  "situation-1",
		Kind:         "duration",
		Subject:      "situation",
		Digest:       "abc123",
		InputVersion: 3,
		Value:        json.RawMessage(`{"seconds":90}`),
		ResultStatus: FactConfirmedValue,
		EvidenceRefs: []string{"delivery-1"},
		Material:     true,
		ObservedAt:   time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC),
	}
	before, after := roundTrip(t, f)
	if string(before) != string(after) {
		t.Fatalf("round trip not lossless:\nbefore: %s\nafter:  %s", before, after)
	}
}

func TestReasonCandidateJSONRoundTrip(t *testing.T) {
	r := ReasonCandidate{
		ID:                 "reason-candidate-1",
		Code:               "duration_milestone",
		Summary:            "sustained beyond the milestone threshold",
		CatalogVersion:     1,
		PredicateVersion:   1,
		EvidenceRefs:       []string{"fact-1"},
		DeterministicFloor: true,
	}
	before, after := roundTrip(t, r)
	if string(before) != string(after) {
		t.Fatalf("round trip not lossless:\nbefore: %s\nafter:  %s", before, after)
	}
}

func TestIncidentCoverageJSONRoundTrip(t *testing.T) {
	c := IncidentCoverage{
		IncidentID:          "incident-1",
		MembershipDigest:    "membership-digest",
		IncidentInputDigest: "incident-input-digest",
	}
	before, after := roundTrip(t, c)
	if string(before) != string(after) {
		t.Fatalf("round trip not lossless:\nbefore: %s\nafter:  %s", before, after)
	}
}

// TestAssessmentProposalShapeExcludesControllerOwnedFields proves the
// separate L2 proposal shape has no lifecycle, action_contract, or cadence
// keys, and that feeding it a raw JSON blob carrying those keys never
// silently populates anything on the resulting struct.
func TestAssessmentProposalShapeExcludesControllerOwnedFields(t *testing.T) {
	proposal := AssessmentProposal{
		SchemaVersion: AssessmentSchemaVersion,
		Persistence:   PersistenceSustained,
		Impact:        ImpactSuspected,
		Novelty:       NoveltyNew,
		Causality:     CausalityCorrelated,
		Attention:     AttentionObserve,
		SufficientReason: &SufficientReason{
			Code:        "duration_milestone",
			CandidateID: "reason-candidate-1",
			Summary:     "sustained beyond the milestone threshold",
		},
		Limitations: []Limitation{{Code: "semantic_assessment_unavailable", Detail: "L2 provider unavailable"}},
	}

	raw, err := json.Marshal(proposal)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var asMap map[string]json.RawMessage
	if err := json.Unmarshal(raw, &asMap); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	for _, forbidden := range []string{"lifecycle", "action_contract", "cadence"} {
		if _, present := asMap[forbidden]; present {
			t.Errorf("AssessmentProposal JSON must not carry %q, got %s", forbidden, raw)
		}
	}
	for _, want := range []string{"schema_version", "persistence", "impact", "novelty", "causality", "attention", "sufficient_reason", "limitations"} {
		if _, present := asMap[want]; !present {
			t.Errorf("AssessmentProposal JSON missing expected key %q, got %s", want, raw)
		}
	}

	// A hostile/legacy blob that also carries the controller-owned keys must
	// not populate anything on AssessmentProposal: the struct has no such
	// fields, so encoding/json silently (and safely) drops them.
	hostile := []byte(`{
		"schema_version": 1,
		"persistence": "sustained",
		"impact": "suspected",
		"novelty": "new",
		"causality": "correlated",
		"attention": "observe",
		"sufficient_reason": null,
		"limitations": [],
		"lifecycle": "active",
		"action_contract": {"next_actor": "alertint"},
		"cadence": "fast"
	}`)
	var decoded AssessmentProposal
	if err := json.Unmarshal(hostile, &decoded); err != nil {
		t.Fatalf("unmarshal hostile blob: %v", err)
	}
	reencoded, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	var reMap map[string]json.RawMessage
	if err := json.Unmarshal(reencoded, &reMap); err != nil {
		t.Fatalf("unmarshal remarshaled: %v", err)
	}
	for _, forbidden := range []string{"lifecycle", "action_contract", "cadence"} {
		if _, present := reMap[forbidden]; present {
			t.Errorf("decoded AssessmentProposal must not carry %q after round trip, got %s", forbidden, reencoded)
		}
	}
}

func TestAssessmentValidateRejectsUnknownSchemaVersion(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	a := fullAssessment(now)
	a.SchemaVersion = 99
	if err := a.Validate(now); err == nil {
		t.Fatal("want error for unknown schema_version, got nil")
	}
}

func TestAssessmentValidateRejectsUnknownEnumField(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	a := fullAssessment(now)
	a.Persistence = Persistence("bogus")
	if err := a.Validate(now); err == nil {
		t.Fatal("want error for unknown persistence value, got nil")
	}
}

// TestActionContractTerminalShape proves a nonterminal authoritative
// Assessment requires a future next_update_at, and a terminal one forbids
// both next_update_at and next_update_on.
func TestActionContractTerminalShape(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

	t.Run("nonterminal without next_update_at is rejected", func(t *testing.T) {
		a := fullAssessment(now)
		a.Lifecycle = LifecycleActive
		a.ActionContract.NextUpdateAt = nil
		if err := a.Validate(now); err == nil {
			t.Fatal("want error for nonterminal contract missing next_update_at, got nil")
		}
	})

	t.Run("nonterminal with past next_update_at is rejected", func(t *testing.T) {
		a := fullAssessment(now)
		a.Lifecycle = LifecycleActive
		a.ActionContract.NextUpdateAt = samplePointer(now.Add(-time.Minute))
		if err := a.Validate(now); err == nil {
			t.Fatal("want error for non-future next_update_at, got nil")
		}
	})

	t.Run("nonterminal with future next_update_at is accepted", func(t *testing.T) {
		a := fullAssessment(now)
		a.Lifecycle = LifecycleActive
		a.ActionContract.NextUpdateAt = samplePointer(now.Add(time.Hour))
		if err := a.Validate(now); err != nil {
			t.Fatalf("want clean validation, got %v", err)
		}
	})

	for _, terminal := range []Lifecycle{LifecycleRecovered, LifecycleClosedUnknown} {
		t.Run("terminal "+string(terminal)+" with next_update_at is rejected", func(t *testing.T) {
			a := fullAssessment(now)
			a.Lifecycle = terminal
			a.Cadence = Cadence("")
			a.ActionContract.NextUpdateAt = samplePointer(now.Add(time.Hour))
			a.ActionContract.NextUpdateOn = nil
			a.ActionContract.AlertINTAction = nil
			a.ActionContract.AlertINTStatus = nil
			a.ActionContract.NextActor = NextActorNone
			if err := a.Validate(now); err == nil {
				t.Fatal("want error for terminal contract carrying next_update_at, got nil")
			}
		})

		t.Run("terminal "+string(terminal)+" with next_update_on is rejected", func(t *testing.T) {
			a := fullAssessment(now)
			a.Lifecycle = terminal
			a.Cadence = Cadence("")
			a.ActionContract.NextUpdateAt = nil
			a.ActionContract.NextUpdateOn = []NextUpdateOn{NextUpdateOnMaterialInput}
			a.ActionContract.AlertINTAction = nil
			a.ActionContract.AlertINTStatus = nil
			a.ActionContract.NextActor = NextActorNone
			if err := a.Validate(now); err == nil {
				t.Fatal("want error for terminal contract carrying next_update_on, got nil")
			}
		})

		t.Run("terminal "+string(terminal)+" with neither update field is accepted", func(t *testing.T) {
			a := fullAssessment(now)
			a.Lifecycle = terminal
			a.Cadence = Cadence("")
			a.ActionContract.NextUpdateAt = nil
			a.ActionContract.NextUpdateOn = nil
			a.ActionContract.AlertINTAction = nil
			a.ActionContract.AlertINTStatus = nil
			a.ActionContract.NextActor = NextActorNone
			if err := a.Validate(now); err != nil {
				t.Fatalf("want clean validation, got %v", err)
			}
		})
	}
}

// TestActionContractNextActorConsistency proves next_actor must agree with
// operator_action_required / alertint_action per the closed derivation
// rules: operator wins when set; otherwise alertint when AlertINT work is
// current; otherwise none.
func TestActionContractNextActorConsistency(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	investigate := OperatorActionInvestigateSituation
	runTriage := AlertINTActionRunAcuteTriage
	planned := AlertINTStatusPlanned

	cases := []struct {
		name    string
		mutate  func(*ActionContract)
		wantErr bool
	}{
		{
			name: "operator action requires next_actor=operator",
			mutate: func(c *ActionContract) {
				c.OperatorActionRequired = &investigate
				c.NextActor = NextActorAlertINT
			},
			wantErr: true,
		},
		{
			name: "operator action with next_actor=operator is accepted",
			mutate: func(c *ActionContract) {
				c.OperatorActionRequired = &investigate
				c.NextActor = NextActorOperator
			},
			wantErr: false,
		},
		{
			name: "current alertint action requires next_actor=alertint",
			mutate: func(c *ActionContract) {
				c.OperatorActionRequired = nil
				c.AlertINTAction = &runTriage
				c.AlertINTStatus = &planned
				c.NextActor = NextActorNone
			},
			wantErr: true,
		},
		{
			name: "no action requires next_actor=none",
			mutate: func(c *ActionContract) {
				c.OperatorActionRequired = nil
				c.AlertINTAction = nil
				c.AlertINTStatus = nil
				c.NextActor = NextActorAlertINT
				c.NextUpdateAt = samplePointer(now.Add(time.Hour))
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := fullAssessment(now)
			tc.mutate(&a.ActionContract)
			err := a.Validate(now)
			if tc.wantErr && err == nil {
				t.Fatal("want error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("want clean validation, got %v", err)
			}
		})
	}
}

func TestAssessmentProposalValidateRejectsUnknownEnum(t *testing.T) {
	p := AssessmentProposal{
		SchemaVersion: AssessmentSchemaVersion,
		Persistence:   PersistenceSustained,
		Impact:        ImpactSuspected,
		Novelty:       NoveltyNew,
		Causality:     CausalityCorrelated,
		Attention:     AttentionObserve,
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("want clean validation, got %v", err)
	}
	p.Novelty = Novelty("bogus")
	if err := p.Validate(); err == nil {
		t.Fatal("want error for unknown novelty value, got nil")
	}
}

func TestSufficientReasonValidateRequiresIdentity(t *testing.T) {
	valid := SufficientReason{Code: "duration_milestone", CandidateID: "reason-candidate-1", Summary: "x"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("want clean validation, got %v", err)
	}
	missingCode := valid
	missingCode.Code = ""
	if err := missingCode.Validate(); err == nil {
		t.Fatal("want error for missing code, got nil")
	}
	missingCandidate := valid
	missingCandidate.CandidateID = ""
	if err := missingCandidate.Validate(); err == nil {
		t.Fatal("want error for missing candidate_id, got nil")
	}
}

func TestLimitationValidateRequiresCode(t *testing.T) {
	if err := (Limitation{Code: "semantic_assessment_unavailable"}).Validate(); err != nil {
		t.Fatalf("want clean validation, got %v", err)
	}
	if err := (Limitation{Detail: "no code"}).Validate(); err == nil {
		t.Fatal("want error for missing code, got nil")
	}
}
