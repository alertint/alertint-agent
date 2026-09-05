// SPDX-License-Identifier: FSL-1.1-ALv2

package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ptr returns a pointer to a copy of v. Kept distinct from assessment_test.go's
// samplePointer so history_test.go's fixtures read close to the plan's own
// example test code.
func ptr[T any](v T) *T { return &v }

// ----------------------------------------------------------------------
// Closed enums
// ----------------------------------------------------------------------

// TestTransitionRelatedEnumsValidate table-tests every closed value for the
// enums this file defines (except TransitionActor, which has its own test
// below since Plan 3 accepts only three of its four defined values).
func TestTransitionRelatedEnumsValidate(t *testing.T) {
	cases := []struct {
		name  string
		valid []enumValidator
		bogus enumValidator
	}{
		{
			name: "TransitionReason",
			valid: []enumValidator{
				ReasonFirstAuthoritativeState, ReasonMaterialAssessmentChanged, ReasonAttentionChanged,
				ReasonOperatorContractChanged, ReasonInvestigationStarted, ReasonInvestigationConcluded,
				ReasonRecoveryObserved, ReasonRecoveryFailed, ReasonRecovered, ReasonClosedUnknown,
				ReasonRecurrenceMilestone, ReasonTriageStateChanged, ReasonOperatorArtifactRecorded,
			},
			bogus: TransitionReason("bogus"),
		},
		{
			name: "JournalKind",
			valid: []enumValidator{
				JournalNone, JournalPublication, JournalInvestigationStarted, JournalInvestigationChanged,
				JournalEvidenceConclusion, JournalOperatorContractChanged, JournalRecoveryPending,
				JournalRecoveryRefired, JournalRecurrenceMilestone, JournalRecovered, JournalClosedUnknown,
				JournalOperatorNote, JournalCapturedVerdict,
			},
			bogus: JournalKind("bogus"),
		},
		{
			name:  "EffectClass",
			valid: []enumValidator{EffectRootSync, EffectThreadAppend, EffectBroadcastHandoff, EffectInstallationGapRecovery},
			bogus: EffectClass("bogus"),
		},
		{
			name:  "IntentStatus",
			valid: []enumValidator{IntentPending, IntentDelivered, IntentBlockedConfiguration, IntentFailed, IntentWithheld, IntentSuperseded},
			bogus: IntentStatus("bogus"),
		},
		{
			name:  "InterruptionPriority",
			valid: []enumValidator{InterruptionLow, InterruptionMedium, InterruptionHigh, InterruptionCritical},
			bogus: InterruptionPriority("bogus"),
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

// TestTransitionActorValidate proves Plan 3 accepts exactly
// deterministic_controller, llm, and attributed_operator, and rejects
// operator_policy even though it is a defined TransitionActor constant
// (reserved for Plan 5; spec.md "Domain model").
func TestTransitionActorValidate(t *testing.T) {
	for _, a := range []TransitionActor{ActorDeterministicController, ActorLLM, ActorAttributedOperator} {
		if err := a.Validate(); err != nil {
			t.Errorf("valid actor %q: unexpected error: %v", a, err)
		}
	}
	if err := ActorOperatorPolicy.Validate(); err == nil {
		t.Error("operator_policy: want error in Plan 3, got nil")
	}
	if err := TransitionActor("bogus").Validate(); err == nil {
		t.Error("bogus actor: want error, got nil")
	}
}

// TestInterruptionPriorityOrdering proves the deterministic ranking
// low < medium < high < critical.
func TestInterruptionPriorityOrdering(t *testing.T) {
	order := []InterruptionPriority{InterruptionLow, InterruptionMedium, InterruptionHigh, InterruptionCritical}
	for i := range order {
		for j := range order {
			want := i < j
			if got := order[i].Less(order[j]); got != want {
				t.Errorf("%s.Less(%s) = %v, want %v", order[i], order[j], got, want)
			}
		}
	}
}

// ----------------------------------------------------------------------
// JournalData
// ----------------------------------------------------------------------

func fullJournalData(now time.Time) JournalData {
	return JournalData{
		Headline:        "situation opened",
		Detail:          "first authoritative state derived from incident_created",
		AttributedActor: "alice",
		ActionStatus:    "planned",
		RecurrenceCount: 2,
		Delayed:         false,
		NoLongerCurrent: false,
		OccurredAt:      now,
	}
}

func TestJournalDataJSONRoundTrip(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	before, after := roundTrip(t, fullJournalData(now))
	if string(before) != string(after) {
		t.Fatalf("round trip not lossless:\nbefore: %s\nafter:  %s", before, after)
	}
}

func TestJournalDataValidate(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	base := fullJournalData(now)
	if err := base.Validate(); err != nil {
		t.Fatalf("valid journal data: unexpected error: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*JournalData)
	}{
		{"headline over max length", func(j *JournalData) { j.Headline = strings.Repeat("a", maxJournalHeadlineLength+1) }},
		{"detail over max length", func(j *JournalData) { j.Detail = strings.Repeat("a", maxJournalDetailLength+1) }},
		{"attributed_actor over max length", func(j *JournalData) { j.AttributedActor = strings.Repeat("a", maxIdentifierLength+1) }},
		{"action_status over max length", func(j *JournalData) { j.ActionStatus = strings.Repeat("a", maxIdentifierLength+1) }},
		{"negative recurrence_count", func(j *JournalData) { j.RecurrenceCount = -1 }},
		{"zero occurred_at", func(j *JournalData) { j.OccurredAt = time.Time{} }},
		{"non-UTC occurred_at", func(j *JournalData) { j.OccurredAt = now.In(time.FixedZone("test", 3600)) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := fullJournalData(now)
			tc.mutate(&j)
			if err := j.Validate(); err == nil {
				t.Fatalf("%s: want error, got nil", tc.name)
			}
		})
	}
}

// ----------------------------------------------------------------------
// AssessmentConclusion / ProjectionFacts (R3)
// ----------------------------------------------------------------------

func fullAssessmentConclusion() AssessmentConclusion {
	return AssessmentConclusion{
		Persistence:             PersistenceSustained,
		Impact:                  ImpactConfirmed,
		Novelty:                 NoveltyChanged,
		Causality:               CausalitySupported,
		EvidenceQuality:         EvidenceQualityComplete,
		LimitationCodes:         []string{"semantic_assessment_unavailable"},
		SufficientReasonCode:    "duration_milestone",
		SufficientReasonSummary: "sustained beyond the milestone threshold",
	}
}

func TestAssessmentConclusionJSONRoundTrip(t *testing.T) {
	before, after := roundTrip(t, fullAssessmentConclusion())
	if string(before) != string(after) {
		t.Fatalf("round trip not lossless:\nbefore: %s\nafter:  %s", before, after)
	}
}

func TestAssessmentConclusionCanonicalizesNilLimitationCodes(t *testing.T) {
	c := fullAssessmentConclusion()
	c.LimitationCodes = nil
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"limitation_codes":[]`) {
		t.Errorf("want canonical empty limitation_codes array, got %s", b)
	}
}

func TestAssessmentConclusionValidate(t *testing.T) {
	valid := fullAssessmentConclusion()
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid assessment conclusion: unexpected error: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*AssessmentConclusion)
	}{
		{"bad persistence", func(c *AssessmentConclusion) { c.Persistence = Persistence("bogus") }},
		{"bad impact", func(c *AssessmentConclusion) { c.Impact = Impact("bogus") }},
		{"bad novelty", func(c *AssessmentConclusion) { c.Novelty = Novelty("bogus") }},
		{"bad causality", func(c *AssessmentConclusion) { c.Causality = Causality("bogus") }},
		{"bad evidence_quality", func(c *AssessmentConclusion) { c.EvidenceQuality = EvidenceQuality("bogus") }},
		{"sufficient_reason_summary over max length", func(c *AssessmentConclusion) {
			c.SufficientReasonSummary = strings.Repeat("a", maxJournalDetailLength+1)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := fullAssessmentConclusion()
			tc.mutate(&c)
			if err := c.Validate(); err == nil {
				t.Fatalf("%s: want error, got nil", tc.name)
			}
		})
	}
}

func fullProjectionFacts(now time.Time) ProjectionFacts {
	assessment := fullAssessmentConclusion()
	return ProjectionFacts{
		PublicHandle:            ptr("sit-abc123"),
		EffectiveStartedAt:      now.Add(-time.Hour),
		EffectiveStartedAtBasis: SourceTimeBasisSourcePayload,
		Assessment:              &assessment,
	}
}

func TestProjectionFactsJSONRoundTrip(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	before, after := roundTrip(t, fullProjectionFacts(now))
	if string(before) != string(after) {
		t.Fatalf("round trip not lossless:\nbefore: %s\nafter:  %s", before, after)
	}
}

func TestProjectionFactsValidate(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	valid := fullProjectionFacts(now)
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid projection facts: unexpected error: %v", err)
	}

	t.Run("zero effective_started_at rejected", func(t *testing.T) {
		p := fullProjectionFacts(now)
		p.EffectiveStartedAt = time.Time{}
		if err := p.Validate(); err == nil {
			t.Fatal("want error, got nil")
		}
	})

	t.Run("non-UTC effective_started_at rejected", func(t *testing.T) {
		p := fullProjectionFacts(now)
		p.EffectiveStartedAt = now.In(time.FixedZone("test", 3600))
		if err := p.Validate(); err == nil {
			t.Fatal("want error, got nil")
		}
	})

	t.Run("bad effective_started_at_basis rejected", func(t *testing.T) {
		p := fullProjectionFacts(now)
		p.EffectiveStartedAtBasis = SourceTimeBasis("bogus")
		if err := p.Validate(); err == nil {
			t.Fatal("want error, got nil")
		}
	})

	t.Run("empty public_handle rejected", func(t *testing.T) {
		p := fullProjectionFacts(now)
		p.PublicHandle = ptr("")
		if err := p.Validate(); err == nil {
			t.Fatal("want error, got nil")
		}
	})

	t.Run("non-UTC recovery_observed_at rejected", func(t *testing.T) {
		p := fullProjectionFacts(now)
		p.RecoveryObservedAt = ptr(now.In(time.FixedZone("test", 3600)))
		if err := p.Validate(); err == nil {
			t.Fatal("want error, got nil")
		}
	})

	t.Run("terminal_at without terminal_reason rejected", func(t *testing.T) {
		p := fullProjectionFacts(now)
		p.TerminalAt = ptr(now)
		if err := p.Validate(); err == nil {
			t.Fatal("want error, got nil")
		}
	})

	t.Run("terminal_reason without terminal_at rejected", func(t *testing.T) {
		p := fullProjectionFacts(now)
		p.TerminalReason = ptr(TerminalReasonObservationDeadline)
		if err := p.Validate(); err == nil {
			t.Fatal("want error, got nil")
		}
	})

	t.Run("terminal_at with terminal_reason accepted", func(t *testing.T) {
		p := fullProjectionFacts(now)
		p.TerminalAt = ptr(now)
		p.TerminalReason = ptr(TerminalReasonObservationDeadline)
		if err := p.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("bad terminal_reason rejected", func(t *testing.T) {
		p := fullProjectionFacts(now)
		p.TerminalAt = ptr(now)
		bogus := TerminalReason("bogus")
		p.TerminalReason = &bogus
		if err := p.Validate(); err == nil {
			t.Fatal("want error, got nil")
		}
	})

	t.Run("invalid nested assessment rejected", func(t *testing.T) {
		p := fullProjectionFacts(now)
		bad := fullAssessmentConclusion()
		bad.Persistence = Persistence("bogus")
		p.Assessment = &bad
		if err := p.Validate(); err == nil {
			t.Fatal("want error, got nil")
		}
	})
}

// ----------------------------------------------------------------------
// Transition
// ----------------------------------------------------------------------

func fullTransition(now time.Time) Transition {
	priority := InterruptionHigh
	return Transition{
		ID:                   "transition-1",
		SituationID:          "situation-1",
		Sequence:             1,
		InputVersion:         1,
		MaterialFactHash:     "hash-1",
		AssessmentID:         ptr("assessment-1"),
		Lifecycle:            LifecycleActive,
		Attention:            AttentionUrgent,
		ActionContract:       fullActionContract(now),
		SufficientReasonID:   ptr("reason-1"),
		InterruptionPriority: &priority,
		Reason:               ReasonFirstAuthoritativeState,
		JournalKind:          JournalPublication,
		Journal:              fullJournalData(now),
		Projection:           fullProjectionFacts(now),
		EvidenceRefs:         []string{"fact-1"},
		Actor:                ActorDeterministicController,
		CreatedAt:            now,
	}
}

func TestTransitionJSONRoundTrip(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	before, after := roundTrip(t, fullTransition(now))
	if string(before) != string(after) {
		t.Fatalf("round trip not lossless:\nbefore: %s\nafter:  %s", before, after)
	}
}

func TestTransitionCanonicalizesNilEvidenceRefs(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	tr := fullTransition(now)
	tr.EvidenceRefs = nil
	b, err := json.Marshal(tr)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"evidence_refs":[]`) {
		t.Errorf("want canonical empty evidence_refs array, got %s", b)
	}
}

func TestTransitionValidate(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	valid := fullTransition(now)
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid transition: unexpected error: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Transition)
	}{
		{"empty id", func(tr *Transition) { tr.ID = "" }},
		{"id over max length", func(tr *Transition) { tr.ID = strings.Repeat("a", maxIdentifierLength+1) }},
		{"empty situation_id", func(tr *Transition) { tr.SituationID = "" }},
		{"sequence zero", func(tr *Transition) { tr.Sequence = 0 }},
		{"input_version zero", func(tr *Transition) { tr.InputVersion = 0 }},
		{"empty material_fact_hash", func(tr *Transition) { tr.MaterialFactHash = "" }},
		{"empty assessment_id when set", func(tr *Transition) { tr.AssessmentID = ptr("") }},
		{"bad lifecycle", func(tr *Transition) { tr.Lifecycle = Lifecycle("bogus") }},
		{"bad attention", func(tr *Transition) { tr.Attention = Attention("bogus") }},
		{"empty sufficient_reason_id when set", func(tr *Transition) { tr.SufficientReasonID = ptr("") }},
		{"bad interruption_priority", func(tr *Transition) { tr.InterruptionPriority = ptr(InterruptionPriority("bogus")) }},
		{"bad reason", func(tr *Transition) { tr.Reason = TransitionReason("bogus") }},
		{"bad journal_kind", func(tr *Transition) { tr.JournalKind = JournalKind("bogus") }},
		{"invalid journal", func(tr *Transition) { tr.Journal.OccurredAt = time.Time{} }},
		{"invalid projection", func(tr *Transition) { tr.Projection.EffectiveStartedAt = time.Time{} }},
		{"operator_policy actor rejected", func(tr *Transition) { tr.Actor = ActorOperatorPolicy }},
		{"bad actor", func(tr *Transition) { tr.Actor = TransitionActor("bogus") }},
		{"evidence_refs over max count", func(tr *Transition) {
			refs := make([]string, maxEvidenceRefs+1)
			for i := range refs {
				refs[i] = "ref"
			}
			tr.EvidenceRefs = refs
		}},
		{"zero created_at", func(tr *Transition) { tr.CreatedAt = time.Time{} }},
		{"non-UTC created_at", func(tr *Transition) { tr.CreatedAt = now.In(time.FixedZone("test", 3600)) }},
		{"terminal contract shape violated", func(tr *Transition) { tr.Lifecycle = LifecycleRecovered }},
		{"operator_artifact_recorded without input id", func(tr *Transition) {
			tr.Reason = ReasonOperatorArtifactRecorded
			tr.OperatorArtifactInputID = nil
		}},
		{"non-artifact reason with input id set", func(tr *Transition) {
			tr.OperatorArtifactInputID = ptr("input-1")
		}},
		{"empty operator_artifact_input_id when set", func(tr *Transition) {
			tr.Reason = ReasonOperatorArtifactRecorded
			tr.OperatorArtifactInputID = ptr("")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := fullTransition(now)
			tc.mutate(&tr)
			if err := tr.Validate(); err == nil {
				t.Fatalf("%s: want error, got nil", tc.name)
			}
		})
	}
}

// TestTransitionValidateOperatorArtifactRecordedRequiresInputID proves R1's
// exact pairing: operator_artifact_input_id is required when (and only
// when) reason is operator_artifact_recorded.
func TestTransitionValidateOperatorArtifactRecordedRequiresInputID(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	tr := fullTransition(now)
	tr.Reason = ReasonOperatorArtifactRecorded
	tr.OperatorArtifactInputID = ptr("input-1")
	if err := tr.Validate(); err != nil {
		t.Fatalf("operator_artifact_recorded with input id: unexpected error: %v", err)
	}
}

// ----------------------------------------------------------------------
// EpisodeSummary
// ----------------------------------------------------------------------

func fullEpisodeSummary(now time.Time) EpisodeSummary {
	return EpisodeSummary{
		SituationID:              "situation-1",
		PublicHandle:             "sit-abc123",
		Version:                  1,
		SourceTransitionSequence: 1,
		Title:                    "database connection pool exhausted",
		InitialPublicationReason: "first_authoritative_state",
		LatestMaterialReason:     "material_assessment_changed",
		EvidenceConclusion:       "confirmed via connection pool metrics",
		ImpactSummary:            "elevated latency on checkout",
		InvestigationWork:        []string{"checked connection pool metrics"},
		InvestigationStarted:     true,
		CurrentAttention:         AttentionInvestigate,
		PeakAttention:            AttentionUrgent,
		ActionContract:           fullActionContract(now),
		RecordedOperatorContext:  []string{"operator confirmed deploy rollback"},
		EffectiveStartedAt:       now.Add(-time.Hour),
		RecurrenceCount:          0,
		UpdatedAt:                now,
	}
}

func TestEpisodeSummaryJSONRoundTrip(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	before, after := roundTrip(t, fullEpisodeSummary(now))
	if string(before) != string(after) {
		t.Fatalf("round trip not lossless:\nbefore: %s\nafter:  %s", before, after)
	}
}

func TestEpisodeSummaryCanonicalizesNilSlices(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	e := fullEpisodeSummary(now)
	e.InvestigationWork = nil
	e.RecordedOperatorContext = nil
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"investigation_work":[]`) {
		t.Errorf("want canonical empty investigation_work array, got %s", b)
	}
	if !strings.Contains(string(b), `"recorded_operator_context":[]`) {
		t.Errorf("want canonical empty recorded_operator_context array, got %s", b)
	}
}

func TestEpisodeSummaryValidate(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	valid := fullEpisodeSummary(now)
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid episode summary: unexpected error: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*EpisodeSummary)
	}{
		{"empty situation_id", func(e *EpisodeSummary) { e.SituationID = "" }},
		{"version zero", func(e *EpisodeSummary) { e.Version = 0 }},
		{"source_transition_sequence zero", func(e *EpisodeSummary) { e.SourceTransitionSequence = 0 }},
		{"empty title", func(e *EpisodeSummary) { e.Title = "" }},
		{"bad current_attention", func(e *EpisodeSummary) { e.CurrentAttention = Attention("bogus") }},
		{"bad peak_attention", func(e *EpisodeSummary) { e.PeakAttention = Attention("bogus") }},
		{"zero effective_started_at", func(e *EpisodeSummary) { e.EffectiveStartedAt = time.Time{} }},
		{"non-UTC effective_started_at", func(e *EpisodeSummary) { e.EffectiveStartedAt = now.In(time.FixedZone("test", 3600)) }},
		{"non-UTC recovery_observed_at", func(e *EpisodeSummary) { e.RecoveryObservedAt = ptr(now.In(time.FixedZone("test", 3600))) }},
		{"negative duration_seconds", func(e *EpisodeSummary) { e.DurationSeconds = ptr(int64(-1)) }},
		{"negative recurrence_count", func(e *EpisodeSummary) { e.RecurrenceCount = -1 }},
		{"zero updated_at", func(e *EpisodeSummary) { e.UpdatedAt = time.Time{} }},
		{"non-UTC updated_at", func(e *EpisodeSummary) { e.UpdatedAt = now.In(time.FixedZone("test", 3600)) }},
		{"terminal contract shape violated", func(e *EpisodeSummary) { e.TerminalAt = ptr(now) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := fullEpisodeSummary(now)
			tc.mutate(&e)
			if err := e.Validate(); err == nil {
				t.Fatalf("%s: want error, got nil", tc.name)
			}
		})
	}
}

// ----------------------------------------------------------------------
// NotificationIntent
// ----------------------------------------------------------------------

func validIntent() NotificationIntent {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	return NotificationIntent{
		ID:              "intent-1",
		IdempotencyKey:  "situation-1:root_sync:summary-3",
		EffectClass:     EffectRootSync,
		SituationID:     ptr("situation-1"),
		TransitionID:    ptr("transition-1"),
		SummaryVersion:  ptr(3),
		ClientMessageID: "11111111-1111-1111-1111-111111111111",
		Status:          IntentPending,
		CreatedAt:       now,
	}
}

// TestNotificationIntentValidateGapRecovery is the plan's binding example:
// installation_gap_recovery with no Situation/Transition reference and a
// gap generation validates cleanly.
func TestNotificationIntentValidateGapRecovery(t *testing.T) {
	in := validIntent()
	in.EffectClass = EffectInstallationGapRecovery
	in.SituationID, in.TransitionID = nil, nil
	in.SummaryVersion = nil
	in.GapGeneration = ptr("gap-7")
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
}

// TestNotificationIntentValidateEffectClassRequirements proves the
// effect-class-specific reference rules: installation_gap_recovery forbids
// Situation/Transition references and requires a gap generation; the three
// Situation effects each require a Situation/Transition (and, for
// root_sync, a summary version) reference; gap_generation is accepted only
// on installation_gap_recovery; contract_deadline_at is accepted only on
// root_sync.
func TestNotificationIntentValidateEffectClassRequirements(t *testing.T) {
	deadline := time.Date(2026, 9, 5, 13, 0, 0, 0, time.UTC)

	cases := []struct {
		name    string
		mutate  func(*NotificationIntent)
		wantErr bool
	}{
		{"root_sync valid", func(n *NotificationIntent) {}, false},
		{"root_sync missing situation_id", func(n *NotificationIntent) { n.SituationID = nil }, true},
		{"root_sync missing transition_id", func(n *NotificationIntent) { n.TransitionID = nil }, true},
		{"root_sync missing summary_version", func(n *NotificationIntent) { n.SummaryVersion = nil }, true},
		{"root_sync with gap_generation forbidden", func(n *NotificationIntent) { n.GapGeneration = ptr("gap-1") }, true},
		{"root_sync with contract_deadline_at accepted", func(n *NotificationIntent) { n.ContractDeadlineAt = &deadline }, false},

		{"thread_append valid", func(n *NotificationIntent) {
			n.EffectClass = EffectThreadAppend
			n.SummaryVersion = nil
		}, false},
		{"thread_append missing situation_id", func(n *NotificationIntent) {
			n.EffectClass = EffectThreadAppend
			n.SummaryVersion = nil
			n.SituationID = nil
		}, true},
		{"thread_append missing transition_id", func(n *NotificationIntent) {
			n.EffectClass = EffectThreadAppend
			n.SummaryVersion = nil
			n.TransitionID = nil
		}, true},
		{"thread_append with contract_deadline_at forbidden", func(n *NotificationIntent) {
			n.EffectClass = EffectThreadAppend
			n.SummaryVersion = nil
			n.ContractDeadlineAt = &deadline
		}, true},

		{"broadcast_handoff valid", func(n *NotificationIntent) {
			n.EffectClass = EffectBroadcastHandoff
			n.SummaryVersion = nil
		}, false},
		{"broadcast_handoff missing transition_id", func(n *NotificationIntent) {
			n.EffectClass = EffectBroadcastHandoff
			n.SummaryVersion = nil
			n.TransitionID = nil
		}, true},

		{"installation_gap_recovery valid", func(n *NotificationIntent) {
			n.EffectClass = EffectInstallationGapRecovery
			n.SituationID, n.TransitionID, n.SummaryVersion = nil, nil, nil
			n.GapGeneration = ptr("gap-1")
		}, false},
		{"installation_gap_recovery forbids situation_id", func(n *NotificationIntent) {
			n.EffectClass = EffectInstallationGapRecovery
			n.TransitionID, n.SummaryVersion = nil, nil
			n.GapGeneration = ptr("gap-1")
		}, true},
		{"installation_gap_recovery forbids transition_id", func(n *NotificationIntent) {
			n.EffectClass = EffectInstallationGapRecovery
			n.SituationID, n.SummaryVersion = nil, nil
			n.GapGeneration = ptr("gap-1")
		}, true},
		{"installation_gap_recovery forbids summary_version", func(n *NotificationIntent) {
			n.EffectClass = EffectInstallationGapRecovery
			n.SituationID, n.TransitionID = nil, nil
			n.GapGeneration = ptr("gap-1")
		}, true},
		{"installation_gap_recovery requires gap_generation", func(n *NotificationIntent) {
			n.EffectClass = EffectInstallationGapRecovery
			n.SituationID, n.TransitionID, n.SummaryVersion = nil, nil, nil
		}, true},
		{"installation_gap_recovery with contract_deadline_at forbidden", func(n *NotificationIntent) {
			n.EffectClass = EffectInstallationGapRecovery
			n.SituationID, n.TransitionID, n.SummaryVersion = nil, nil, nil
			n.GapGeneration = ptr("gap-1")
			n.ContractDeadlineAt = &deadline
		}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := validIntent()
			tc.mutate(&n)
			err := n.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("want error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("want no error, got %v", err)
			}
		})
	}
}

func TestNotificationIntentValidateRequiresIdentity(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*NotificationIntent)
	}{
		{"empty id", func(n *NotificationIntent) { n.ID = "" }},
		{"id over max length", func(n *NotificationIntent) { n.ID = strings.Repeat("a", maxIdentifierLength+1) }},
		{"empty idempotency_key", func(n *NotificationIntent) { n.IdempotencyKey = "" }},
		{"empty client_message_id", func(n *NotificationIntent) { n.ClientMessageID = "" }},
		{"bad effect_class", func(n *NotificationIntent) { n.EffectClass = EffectClass("bogus") }},
		{"bad status", func(n *NotificationIntent) { n.Status = IntentStatus("bogus") }},
		{"zero created_at", func(n *NotificationIntent) { n.CreatedAt = time.Time{} }},
		{"non-UTC created_at", func(n *NotificationIntent) { n.CreatedAt = n.CreatedAt.In(time.FixedZone("test", 3600)) }},
		{"negative attempt_count", func(n *NotificationIntent) { n.AttemptCount = -1 }},
		{"bad interruption_priority", func(n *NotificationIntent) { n.InterruptionPriority = ptr(InterruptionPriority("bogus")) }},
		{"empty situation_id when set", func(n *NotificationIntent) { n.SituationID = ptr("") }},
		{"empty claim_owner when set", func(n *NotificationIntent) { n.ClaimOwner = ptr("") }},
		{"empty last_error_class when set", func(n *NotificationIntent) { n.LastErrorClass = ptr("") }},
		{"non-UTC lease_expires_at", func(n *NotificationIntent) {
			n.LeaseExpiresAt = ptr(n.CreatedAt.In(time.FixedZone("test", 3600)))
		}},
		{"non-UTC delivered_at", func(n *NotificationIntent) {
			n.DeliveredAt = ptr(n.CreatedAt.In(time.FixedZone("test", 3600)))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := validIntent()
			tc.mutate(&n)
			if err := n.Validate(); err == nil {
				t.Fatalf("%s: want error, got nil", tc.name)
			}
		})
	}
}
