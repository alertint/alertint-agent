// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Plan 3 Task 4 fixtures. Every helper here is prefixed `hs` (history
// slice) so it never collides with Plan 2's existing package-level test
// helpers (mustTime, fixedClock, baseSnapshotInput, ct*, ...). mustTime
// itself is reused from snapshot_test.go.
// ----------------------------------------------------------------------

const (
	hsSituationID = "1f0f5a0c-0000-4000-8000-000000000001"
	hsGroupKey    = "service=checkout"
	hsIncidentID  = "incident-0001"
	hsHash1       = "sha256:1111111111"
	hsHash2       = "sha256:2222222222"
)

func hsNow(t *testing.T) time.Time {
	t.Helper()
	return mustTime(t, "2026-09-06T10:00:00Z")
}

// hsRunningTriageContract is a valid nonterminal Operator contract in which
// AlertINT is currently running Acute Triage.
func hsRunningTriageContract(next time.Time) model.ActionContract {
	action := model.AlertINTActionRunAcuteTriage
	status := model.AlertINTStatusRunning
	return model.ActionContract{
		NextActor:      model.NextActorAlertINT,
		AlertINTAction: &action,
		AlertINTStatus: &status,
		NextUpdateAt:   timePtr(next),
		NextUpdateOn:   []model.NextUpdateOn{model.NextUpdateOnTriageOutcome},
	}
}

// hsMonitoringContract is a valid nonterminal Operator contract in which no
// AlertINT investigation is current — AlertINT is only monitoring.
func hsMonitoringContract(next time.Time) model.ActionContract {
	action := model.AlertINTActionMonitorSituation
	status := model.AlertINTStatusWaiting
	wait := model.WaitReasonSourceChange
	return model.ActionContract{
		NextActor:      model.NextActorAlertINT,
		AlertINTAction: &action,
		AlertINTStatus: &status,
		NextUpdateAt:   timePtr(next),
		NextUpdateOn:   []model.NextUpdateOn{model.NextUpdateOnMaterialInput},
		WaitReason:     &wait,
	}
}

// hsOperatorContract is a valid nonterminal Operator contract that hands the
// next move to a human while AlertINT's own Acute Triage work continues —
// the contract validator's own rule that "operator action wins even when
// AlertINT work continues". Keeping the AlertINT action current isolates
// the handoff from an investigation conclusion.
func hsOperatorContract(next time.Time) model.ActionContract {
	op := model.OperatorActionInvestigateSituation
	action := model.AlertINTActionRunAcuteTriage
	status := model.AlertINTStatusRunning
	return model.ActionContract{
		NextActor:              model.NextActorOperator,
		AlertINTAction:         &action,
		AlertINTStatus:         &status,
		OperatorActionRequired: &op,
		NextUpdateAt:           timePtr(next),
		NextUpdateOn:           []model.NextUpdateOn{model.NextUpdateOnMaterialInput},
	}
}

// hsTerminalContract is the only shape a terminal Transition may carry.
func hsTerminalContract() model.ActionContract {
	return model.ActionContract{NextActor: model.NextActorNone}
}

func hsConclusion() model.AssessmentConclusion {
	return model.AssessmentConclusion{
		Persistence:             model.PersistenceSustained,
		Impact:                  model.ImpactSuspected,
		Novelty:                 model.NoveltyNew,
		Causality:               model.CausalityCorrelated,
		EvidenceQuality:         model.EvidenceQualityComplete,
		LimitationCodes:         []string{},
		SufficientReasonCode:    reasonCodeCriticalAnchor,
		SufficientReasonSummary: "Confirmed active critical source severity.",
	}
}

func hsAssessment(contract model.ActionContract, concl model.AssessmentConclusion,
	lifecycle model.Lifecycle, attention model.Attention) model.Assessment {
	a := model.Assessment{
		SchemaVersion:   model.AssessmentSchemaVersion,
		Persistence:     concl.Persistence,
		Impact:          concl.Impact,
		Novelty:         concl.Novelty,
		Causality:       concl.Causality,
		Attention:       attention,
		Lifecycle:       lifecycle,
		EvidenceQuality: concl.EvidenceQuality,
		ActionContract:  contract,
		Limitations:     []model.Limitation{},
		Cadence:         model.CadenceFast,
	}
	if lifecycle.Terminal() {
		a.Cadence = model.Cadence("")
	}
	if concl.SufficientReasonCode != "" {
		a.SufficientReason = &model.SufficientReason{
			Code:         concl.SufficientReasonCode,
			CandidateID:  "candidate-" + concl.SufficientReasonCode,
			Summary:      concl.SufficientReasonSummary,
			EvidenceRefs: []string{"fact-anchor"},
		}
	}
	return a
}

func hsSituation(now time.Time, inputVersion int, lifecycle model.Lifecycle, attention model.Attention) model.Situation {
	return model.Situation{
		ID:                      hsSituationID,
		GroupKey:                hsGroupKey,
		Lifecycle:               lifecycle,
		Attention:               attention,
		InputVersion:            inputVersion,
		OpenedAt:                now.Add(-time.Hour),
		EffectiveStartedAt:      now.Add(-90 * time.Minute),
		EffectiveStartedAtBasis: model.SourceTimeBasisSourcePayload,
		FirstReceivedAt:         now.Add(-89 * time.Minute),
		LastLifecycleObservedAt: now,
		NextAssessmentAt:        now.Add(time.Minute),
		DueReasons:              []model.DueReason{model.DueMembershipChanged},
		CreatedAt:               now.Add(-time.Hour),
		UpdatedAt:               now,
	}
}

// hsChange is the baseline AuthoritativeChange: an active, investigate-level
// Situation whose current authoritative Assessment has AlertINT running
// Acute Triage, with no prior Transition (a first authoritative state).
func hsChange(t *testing.T) AuthoritativeChange {
	t.Helper()
	now := hsNow(t)
	concl := hsConclusion()
	contract := hsRunningTriageContract(now.Add(time.Minute))
	sit := hsSituation(now, 7, model.LifecycleActive, model.AttentionInvestigate)
	return AuthoritativeChange{
		Situation:    sit,
		AssessmentID: stringPtrOf("assessment-0001"),
		Assessment:   hsAssessment(contract, concl, model.LifecycleActive, model.AttentionInvestigate),
		Derivation:   model.DerivationModelValidated,
		Projection: model.ProjectionFacts{
			EffectiveStartedAt:      sit.EffectiveStartedAt,
			EffectiveStartedAtBasis: sit.EffectiveStartedAtBasis,
			Assessment:              &concl,
		},
		MaterialFactHash: hsHash1,
		EvidenceRefs:     []string{"fact-b", "fact-a"},
		Incidents:        []IncidentState{hsIncident("pending", nil)},
		RecurrenceCount:  0,
		Now:              now,
	}
}

func hsIncident(phase string, decision *string) IncidentState {
	return IncidentState{
		ID:       hsIncidentID,
		GroupKey: hsGroupKey,
		Status:   "ready",
		Triage:   TriageState{Phase: phase, Decision: decision},
	}
}

// hsFirst builds the single Transition the baseline change produces, for use
// as the next cycle's PriorTransition.
func hsFirst(t *testing.T) model.Transition {
	t.Helper()
	got, err := BuildTransitions(hsChange(t))
	if err != nil {
		t.Fatalf("BuildTransitions(baseline): %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("BuildTransitions(baseline) = %d transitions, want 1", len(got))
	}
	return got[0]
}

// hsPriorSummary folds the baseline Transition into the first Episode
// summary, for use as the next cycle's PriorSummary.
func hsPriorSummary(t *testing.T, prior model.Transition) model.EpisodeSummary {
	t.Helper()
	sum, err := ProjectEpisode(nil, prior)
	if err != nil {
		t.Fatalf("ProjectEpisode(nil, first): %v", err)
	}
	return sum
}

// hsNext returns a second-cycle change carrying the prior Transition and
// summary at a bumped input version, one minute later.
func hsNext(t *testing.T) AuthoritativeChange {
	t.Helper()
	prior := hsFirst(t)
	sum := hsPriorSummary(t, prior)
	next := hsChange(t)
	next.Now = next.Now.Add(time.Minute)
	next.Situation.InputVersion = 8
	next.Situation.UpdatedAt = next.Now
	next.PriorTransition = &prior
	next.PriorSummary = &sum
	next.AssessmentID = stringPtrOf("assessment-0002")
	next.Assessment.ActionContract = hsRunningTriageContract(next.Now.Add(time.Minute))
	return next
}

func hsArtifact(id, kind string, occurredAt time.Time) OperatorArtifactInput {
	a := OperatorArtifactInput{
		InputID:             id,
		Kind:                kind,
		AppliedInputVersion: 8,
		OccurredAt:          occurredAt,
		AttributedActor:     "operator@example.com",
		Headline:            "Checked the deploy log",
		Detail:              "Rollback started at 09:58.",
	}
	switch kind {
	case artifactKindAnnotation:
		a.AnnotationID = stringPtrOf("annotation-" + id)
	case artifactKindVerdict:
		a.VerdictID = stringPtrOf("verdict-" + id)
	}
	return a
}

// hsUseReason rewrites both halves of the Sufficient reason a change
// carries — the projection's closed conclusion code (what materiality and
// priority read) and the Assessment's own selection.
func hsUseReason(c *AuthoritativeChange, code string) {
	concl := hsConclusion()
	if c.Projection.Assessment != nil {
		concl = *c.Projection.Assessment
	}
	concl.SufficientReasonCode = code
	concl.SufficientReasonSummary = "Sufficient reason " + code + "."
	c.Projection.Assessment = &concl
	if c.Assessment.SufficientReason != nil {
		c.Assessment.SufficientReason.Code = code
		c.Assessment.SufficientReason.Summary = concl.SufficientReasonSummary
	}
}

// hsRecovered turns a change into a committed recovery: terminal lifecycle,
// terminal contract, recovery observation retained, no terminal reason
// (migration 0014: recovered carries terminal_at with a NULL terminal_reason).
func hsRecovered(c *AuthoritativeChange) {
	c.Situation.Lifecycle = model.LifecycleRecovered
	c.Assessment.Lifecycle = model.LifecycleRecovered
	c.Assessment.Cadence = model.Cadence("")
	c.Assessment.ActionContract = hsTerminalContract()
	c.Situation.RecoveryObservedAt = timePtr(c.Now.Add(-10 * time.Minute))
	c.Situation.TerminalAt = timePtr(c.Now)
	c.Projection.RecoveryObservedAt = timePtr(c.Now.Add(-10 * time.Minute))
	c.Projection.TerminalAt = timePtr(c.Now)
}

// hsClosedUnknown turns a change into a committed closure with uncertainty.
func hsClosedUnknown(c *AuthoritativeChange) {
	c.Situation.Lifecycle = model.LifecycleClosedUnknown
	c.Assessment.Lifecycle = model.LifecycleClosedUnknown
	c.Assessment.Cadence = model.Cadence("")
	c.Assessment.ActionContract = hsTerminalContract()
	reason := model.TerminalReasonObservationDeadline
	c.Situation.TerminalAt = timePtr(c.Now)
	c.Situation.TerminalReason = &reason
	c.Projection.TerminalAt = timePtr(c.Now)
	c.Projection.TerminalReason = &reason
}

func hsOnly(t *testing.T, change AuthoritativeChange) model.Transition {
	t.Helper()
	got, err := BuildTransitions(change)
	if err != nil {
		t.Fatalf("BuildTransitions: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("BuildTransitions = %d transitions, want exactly 1: %+v", len(got), got)
	}
	if err := got[0].Validate(); err != nil {
		t.Fatalf("derived transition failed model validation: %v", err)
	}
	return got[0]
}

// ----------------------------------------------------------------------
// Step 1: the material-change catalog.
// ----------------------------------------------------------------------

func TestBuildTransitionsCatalog(t *testing.T) {
	now := hsNow(t)

	cases := []struct {
		name        string
		change      func(t *testing.T) AuthoritativeChange
		reason      model.TransitionReason
		actor       model.TransitionActor
		journal     model.JournalKind
		evidence    []string
		pokeAllowed bool
		headlineHas string
	}{
		{
			name:        "first authoritative state",
			change:      hsChange,
			reason:      model.ReasonFirstAuthoritativeState,
			actor:       model.ActorLLM,
			journal:     model.JournalPublication,
			evidence:    []string{"fact-a", "fact-anchor", "fact-b"},
			pokeAllowed: true,
		},
		{
			name: "material assessment change",
			change: func(t *testing.T) AuthoritativeChange {
				t.Helper()
				c := hsNext(t)
				concl := hsConclusion()
				concl.Impact = model.ImpactConfirmed
				c.Projection.Assessment = &concl
				c.Assessment.Impact = model.ImpactConfirmed
				return c
			},
			reason:      model.ReasonMaterialAssessmentChanged,
			actor:       model.ActorLLM,
			journal:     model.JournalInvestigationChanged,
			evidence:    []string{"fact-a", "fact-anchor", "fact-b"},
			pokeAllowed: false,
		},
		{
			name: "attention change",
			change: func(t *testing.T) AuthoritativeChange {
				t.Helper()
				c := hsNext(t)
				c.Situation.Attention = model.AttentionUrgent
				c.Assessment.Attention = model.AttentionUrgent
				return c
			},
			reason:      model.ReasonAttentionChanged,
			actor:       model.ActorLLM,
			journal:     model.JournalOperatorContractChanged,
			pokeAllowed: true,
			headlineHas: "urgent",
		},
		{
			name: "operator contract change",
			change: func(t *testing.T) AuthoritativeChange {
				t.Helper()
				c := hsNext(t)
				c.Assessment.ActionContract = hsOperatorContract(c.Now.Add(time.Minute))
				return c
			},
			reason:      model.ReasonOperatorContractChanged,
			actor:       model.ActorDeterministicController,
			journal:     model.JournalOperatorContractChanged,
			pokeAllowed: true,
			headlineHas: "operator",
		},
		{
			name: "investigation started",
			change: func(t *testing.T) AuthoritativeChange {
				t.Helper()
				c := hsChange(t)
				c.Assessment.ActionContract = hsMonitoringContract(c.Now.Add(time.Minute))
				prior, err := BuildTransitions(c)
				if err != nil {
					t.Fatalf("BuildTransitions(prior): %v", err)
				}
				sum := hsPriorSummary(t, prior[0])
				n := hsNext(t)
				n.PriorTransition = &prior[0]
				n.PriorSummary = &sum
				return n
			},
			reason:      model.ReasonInvestigationStarted,
			actor:       model.ActorDeterministicController,
			journal:     model.JournalInvestigationStarted,
			pokeAllowed: false,
		},
		{
			name: "investigation concluded",
			change: func(t *testing.T) AuthoritativeChange {
				t.Helper()
				c := hsNext(t)
				c.Assessment.ActionContract = hsMonitoringContract(c.Now.Add(time.Minute))
				return c
			},
			reason:      model.ReasonInvestigationConcluded,
			actor:       model.ActorLLM,
			journal:     model.JournalEvidenceConclusion,
			pokeAllowed: false,
		},
		{
			name: "recovery observed",
			change: func(t *testing.T) AuthoritativeChange {
				t.Helper()
				c := hsNext(t)
				c.Situation.Lifecycle = model.LifecycleRecoveryPending
				c.Assessment.Lifecycle = model.LifecycleRecoveryPending
				c.Situation.RecoveryObservedAt = timePtr(c.Now)
				c.Projection.RecoveryObservedAt = timePtr(c.Now)
				c.Projection.GraceUntil = timePtr(c.Now.Add(10 * time.Minute))
				return c
			},
			reason:      model.ReasonRecoveryObserved,
			actor:       model.ActorDeterministicController,
			journal:     model.JournalRecoveryPending,
			pokeAllowed: false,
		},
		{
			name: "recovery failed",
			change: func(t *testing.T) AuthoritativeChange {
				t.Helper()
				c := hsChange(t)
				c.Situation.Lifecycle = model.LifecycleRecoveryPending
				c.Assessment.Lifecycle = model.LifecycleRecoveryPending
				c.Projection.RecoveryObservedAt = timePtr(c.Now.Add(-time.Minute))
				prior, err := BuildTransitions(c)
				if err != nil {
					t.Fatalf("BuildTransitions(prior): %v", err)
				}
				sum := hsPriorSummary(t, prior[0])
				n := hsNext(t)
				n.PriorTransition = &prior[0]
				n.PriorSummary = &sum
				return n
			},
			reason:      model.ReasonRecoveryFailed,
			actor:       model.ActorDeterministicController,
			journal:     model.JournalRecoveryRefired,
			pokeAllowed: false,
		},
		{
			name: "recovered",
			change: func(t *testing.T) AuthoritativeChange {
				t.Helper()
				c := hsNext(t)
				hsRecovered(&c)
				return c
			},
			reason:      model.ReasonRecovered,
			actor:       model.ActorDeterministicController,
			journal:     model.JournalRecovered,
			pokeAllowed: false,
		},
		{
			name: "closed unknown",
			change: func(t *testing.T) AuthoritativeChange {
				t.Helper()
				c := hsNext(t)
				hsClosedUnknown(&c)
				return c
			},
			reason:      model.ReasonClosedUnknown,
			actor:       model.ActorDeterministicController,
			journal:     model.JournalClosedUnknown,
			pokeAllowed: false,
			headlineHas: "uncertain",
		},
		{
			name: "recurrence milestone",
			change: func(t *testing.T) AuthoritativeChange {
				t.Helper()
				c := hsNext(t)
				c.RecurrenceCount = 5
				return c
			},
			reason:      model.ReasonRecurrenceMilestone,
			actor:       model.ActorDeterministicController,
			journal:     model.JournalRecurrenceMilestone,
			pokeAllowed: false,
			headlineHas: "5",
		},
		{
			name: "triage state changed by a B+ skip decision",
			change: func(t *testing.T) AuthoritativeChange {
				t.Helper()
				c := hsNext(t)
				c.TriageDecisions = []TriageDecision{{
					IncidentID:            hsIncidentID,
					Decision:              TriageDecisionSkip,
					DecisionReason:        DecisionReasonCleanSkip,
					SituationID:           hsSituationID,
					SituationInputVersion: 8,
					DecidedAt:             c.Now,
				}}
				return c
			},
			reason:      model.ReasonTriageStateChanged,
			actor:       model.ActorDeterministicController,
			journal:     model.JournalInvestigationChanged,
			pokeAllowed: false,
			headlineHas: "skipped",
		},
		{
			name: "triage state changed by the pre-claim minimum-member clean skip",
			change: func(t *testing.T) AuthoritativeChange {
				t.Helper()
				c := hsNext(t)
				c.Situation.DueReasons = []model.DueReason{model.DueTriageChanged}
				c.Incidents = []IncidentState{hsIncident(triagePhaseSkipped, nil)}
				return c
			},
			reason:      model.ReasonTriageStateChanged,
			actor:       model.ActorDeterministicController,
			journal:     model.JournalInvestigationChanged,
			pokeAllowed: false,
			headlineHas: "skipped",
		},
		{
			name: "attributed annotation",
			change: func(t *testing.T) AuthoritativeChange {
				t.Helper()
				c := hsNext(t)
				c.OperatorArtifacts = []OperatorArtifactInput{hsArtifact("input-1", artifactKindAnnotation, now)}
				return c
			},
			reason:      model.ReasonOperatorArtifactRecorded,
			actor:       model.ActorAttributedOperator,
			journal:     model.JournalOperatorNote,
			evidence:    []string{"annotation:annotation-input-1"},
			pokeAllowed: false,
			headlineHas: "deploy log",
		},
		{
			name: "captured verdict",
			change: func(t *testing.T) AuthoritativeChange {
				t.Helper()
				c := hsNext(t)
				c.OperatorArtifacts = []OperatorArtifactInput{hsArtifact("input-2", artifactKindVerdict, now)}
				return c
			},
			reason:      model.ReasonOperatorArtifactRecorded,
			actor:       model.ActorAttributedOperator,
			journal:     model.JournalCapturedVerdict,
			evidence:    []string{"verdict:verdict-input-2"},
			pokeAllowed: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := hsOnly(t, tc.change(t))
			if got.Reason != tc.reason {
				t.Errorf("reason = %q, want %q", got.Reason, tc.reason)
			}
			if got.Actor != tc.actor {
				t.Errorf("actor = %q, want %q", got.Actor, tc.actor)
			}
			if got.JournalKind != tc.journal {
				t.Errorf("journal kind = %q, want %q", got.JournalKind, tc.journal)
			}
			if tc.evidence != nil {
				if strings.Join(got.EvidenceRefs, ",") != strings.Join(tc.evidence, ",") {
					t.Errorf("evidence refs = %v, want %v", got.EvidenceRefs, tc.evidence)
				}
			}
			if pokeEligible := got.InterruptionPriority != nil; pokeEligible != tc.pokeAllowed {
				t.Errorf("main-channel poke eligible = %v (priority %v), want %v",
					pokeEligible, got.InterruptionPriority, tc.pokeAllowed)
			}
			if tc.headlineHas != "" {
				full := got.Journal.Headline + " " + got.Journal.Detail
				if !strings.Contains(strings.ToLower(full), strings.ToLower(tc.headlineHas)) {
					t.Errorf("journal %q / %q contains no %q", got.Journal.Headline, got.Journal.Detail, tc.headlineHas)
				}
			}
			if got.Journal.OccurredAt.IsZero() {
				t.Error("journal occurred_at is zero")
			}
			if got.Projection.EffectiveStartedAt.IsZero() {
				t.Error("projection effective_started_at is zero (R3)")
			}
		})
	}
}

// TestBuildTransitionsCleanSkipNeverStartsInvestigation pins the brief's
// explicit clean-skip rule: the skip journals, but never reads as
// investigation having run.
func TestBuildTransitionsCleanSkipNeverStartsInvestigation(t *testing.T) {
	c := hsNext(t)
	c.Situation.DueReasons = []model.DueReason{model.DueTriageChanged}
	c.Incidents = []IncidentState{hsIncident(triagePhaseSkipped, nil)}
	tr := hsOnly(t, c)

	sum, err := ProjectEpisode(c.PriorSummary, tr)
	if err != nil {
		t.Fatalf("ProjectEpisode: %v", err)
	}
	if sum.InvestigationStarted {
		t.Error("a clean skip must never set InvestigationStarted")
	}
	if tr.JournalKind == model.JournalInvestigationStarted {
		t.Error("a clean skip must never journal investigation_started")
	}
}

// ----------------------------------------------------------------------
// Step 1: R1 — artifact ordering.
// ----------------------------------------------------------------------

func TestBuildTransitionsArtifactOrdering(t *testing.T) {
	now := hsNow(t)

	t.Run("two artifacts plus a material state change yield three in order", func(t *testing.T) {
		c := hsNext(t)
		c.Situation.Attention = model.AttentionUrgent
		c.Assessment.Attention = model.AttentionUrgent
		c.OperatorArtifacts = []OperatorArtifactInput{
			hsArtifact("input-1", artifactKindAnnotation, now),
			hsArtifact("input-2", artifactKindVerdict, now.Add(time.Second)),
		}
		got, err := BuildTransitions(c)
		if err != nil {
			t.Fatalf("BuildTransitions: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("got %d transitions, want 3", len(got))
		}
		wantReasons := []model.TransitionReason{
			model.ReasonOperatorArtifactRecorded,
			model.ReasonOperatorArtifactRecorded,
			model.ReasonAttentionChanged,
		}
		for i, want := range wantReasons {
			if got[i].Reason != want {
				t.Errorf("transition %d reason = %q, want %q", i, got[i].Reason, want)
			}
			if err := got[i].Validate(); err != nil {
				t.Errorf("transition %d failed model validation: %v", i, err)
			}
		}
		if got[0].OperatorArtifactInputID == nil || *got[0].OperatorArtifactInputID != "input-1" {
			t.Errorf("first artifact transition input id = %v, want input-1", got[0].OperatorArtifactInputID)
		}
		if got[1].OperatorArtifactInputID == nil || *got[1].OperatorArtifactInputID != "input-2" {
			t.Errorf("second artifact transition input id = %v, want input-2", got[1].OperatorArtifactInputID)
		}
		if got[2].OperatorArtifactInputID != nil {
			t.Error("controller-state transition must not carry an artifact input id")
		}
		for i := range got {
			if want := i + 2; got[i].Sequence != want {
				t.Errorf("transition %d sequence = %d, want %d", i, got[i].Sequence, want)
			}
		}
	})

	t.Run("two artifacts with no state change yield two", func(t *testing.T) {
		c := hsNext(t)
		c.OperatorArtifacts = []OperatorArtifactInput{
			hsArtifact("input-1", artifactKindAnnotation, now),
			hsArtifact("input-2", artifactKindAnnotation, now.Add(time.Second)),
		}
		got, err := BuildTransitions(c)
		if err != nil {
			t.Fatalf("BuildTransitions: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d transitions, want 2", len(got))
		}
		for i := range got {
			if got[i].Reason != model.ReasonOperatorArtifactRecorded {
				t.Errorf("transition %d reason = %q, want operator_artifact_recorded", i, got[i].Reason)
			}
		}
	})

	t.Run("a terminal state change journals the pending artifact first", func(t *testing.T) {
		c := hsNext(t)
		hsClosedUnknown(&c)
		c.OperatorArtifacts = []OperatorArtifactInput{hsArtifact("input-9", artifactKindAnnotation, now)}

		got, err := BuildTransitions(c)
		if err != nil {
			t.Fatalf("BuildTransitions: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d transitions, want 2", len(got))
		}
		if got[0].Reason != model.ReasonOperatorArtifactRecorded {
			t.Errorf("first reason = %q, want operator_artifact_recorded", got[0].Reason)
		}
		if got[1].Reason != model.ReasonClosedUnknown {
			t.Errorf("second reason = %q, want closed_unknown", got[1].Reason)
		}
		if got[0].Sequence >= got[1].Sequence {
			t.Errorf("artifact sequence %d must precede terminal sequence %d", got[0].Sequence, got[1].Sequence)
		}
	})

	t.Run("nothing pending and nothing material yields no transitions", func(t *testing.T) {
		got, err := BuildTransitions(hsNext(t))
		if err != nil {
			t.Fatalf("BuildTransitions: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("got %d transitions, want 0: %+v", len(got), got)
		}
	})
}

// ----------------------------------------------------------------------
// Step 1: R4 — materiality is semantic.
// ----------------------------------------------------------------------

func TestMaterialityRevalidatedReuseCreatesNoTransition(t *testing.T) {
	c := hsNext(t)
	// Exactly Plan 2's revalidated_reuse shape: a new authoritative
	// Assessment ID, a new Sufficient-reason candidate ID, new per-input
	// evidence identities, a freshly recomputed next_update_at — and an
	// unchanged semantic tuple.
	c.Derivation = model.DerivationRevalidatedReuse
	c.AssessmentID = stringPtrOf("assessment-0002")
	c.Assessment.SufficientReason.CandidateID = "candidate-refreshed"
	c.Assessment.SufficientReason.EvidenceRefs = []string{"fact-anchor-v8"}
	c.Assessment.ActionContract.NextUpdateAt = timePtr(c.Now.Add(17 * time.Minute))
	c.EvidenceRefs = []string{"fact-a-v8", "fact-b-v8"}
	c.MaterialFactHash = hsHash2

	got, err := BuildTransitions(c)
	if err != nil {
		t.Fatalf("BuildTransitions: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("revalidated_reuse produced %d transitions, want 0: %+v", len(got), got)
	}
}

func TestMaterialityTupleMembers(t *testing.T) {
	cases := []struct {
		name  string
		muton func(c *AuthoritativeChange)
		want  model.TransitionReason
	}{
		{"lifecycle", func(c *AuthoritativeChange) {
			c.Situation.Lifecycle = model.LifecycleRecoveryPending
			c.Assessment.Lifecycle = model.LifecycleRecoveryPending
			c.Situation.RecoveryObservedAt = timePtr(c.Now)
			c.Projection.RecoveryObservedAt = timePtr(c.Now)
		}, model.ReasonRecoveryObserved},
		{"attention", func(c *AuthoritativeChange) {
			c.Situation.Attention = model.AttentionUrgent
			c.Assessment.Attention = model.AttentionUrgent
		}, model.ReasonAttentionChanged},
		{"next actor and operator action", func(c *AuthoritativeChange) {
			c.Assessment.ActionContract = hsOperatorContract(c.Now.Add(time.Minute))
		}, model.ReasonOperatorContractChanged},
		{"alertint status", func(c *AuthoritativeChange) {
			blocked := model.AlertINTStatusBlocked
			c.Assessment.ActionContract.AlertINTStatus = &blocked
		}, model.ReasonOperatorContractChanged},
		{"next update on", func(c *AuthoritativeChange) {
			c.Assessment.ActionContract.NextUpdateOn = []model.NextUpdateOn{model.NextUpdateOnSourceResolution}
		}, model.ReasonOperatorContractChanged},
		{"wait reason", func(c *AuthoritativeChange) {
			w := model.WaitReasonAcuteTriageBackoff
			c.Assessment.ActionContract.WaitReason = &w
		}, model.ReasonOperatorContractChanged},
		{"sufficient reason code", func(c *AuthoritativeChange) {
			concl := hsConclusion()
			concl.SufficientReasonCode = reasonCodeDurationOutlier
			c.Projection.Assessment = &concl
			c.Assessment.SufficientReason.Code = reasonCodeDurationOutlier
		}, model.ReasonMaterialAssessmentChanged},
		{"assessment conclusion code", func(c *AuthoritativeChange) {
			concl := hsConclusion()
			concl.Causality = model.CausalitySupported
			c.Projection.Assessment = &concl
			c.Assessment.Causality = model.CausalitySupported
		}, model.ReasonMaterialAssessmentChanged},
		{"limitation codes", func(c *AuthoritativeChange) {
			concl := hsConclusion()
			concl.LimitationCodes = []string{"semantic_assessment_unavailable"}
			c.Projection.Assessment = &concl
		}, model.ReasonMaterialAssessmentChanged},
		{"triage decision", func(c *AuthoritativeChange) {
			c.TriageDecisions = []TriageDecision{{
				IncidentID: hsIncidentID, Decision: TriageDecisionSkip,
				DecisionReason: DecisionReasonCleanSkip, SituationID: hsSituationID,
				SituationInputVersion: 8, DecidedAt: c.Now,
			}}
		}, model.ReasonTriageStateChanged},
		{"recurrence milestone", func(c *AuthoritativeChange) {
			c.RecurrenceCount = 10
		}, model.ReasonRecurrenceMilestone},
	}

	for _, tc := range cases {
		t.Run(tc.name+" is material", func(t *testing.T) {
			c := hsNext(t)
			tc.muton(&c)
			got := hsOnly(t, c)
			if got.Reason != tc.want {
				t.Errorf("reason = %q, want %q", got.Reason, tc.want)
			}
		})
	}
}

func TestMaterialityIgnoresNonSemanticChurn(t *testing.T) {
	cases := []struct {
		name  string
		muton func(c *AuthoritativeChange)
	}{
		{"assessment id", func(c *AuthoritativeChange) { c.AssessmentID = stringPtrOf("assessment-9999") }},
		{"material fact hash", func(c *AuthoritativeChange) { c.MaterialFactHash = hsHash2 }},
		{"next_update_at", func(c *AuthoritativeChange) {
			c.Assessment.ActionContract.NextUpdateAt = timePtr(c.Now.Add(42 * time.Minute))
		}},
		{"reason candidate id", func(c *AuthoritativeChange) {
			c.Assessment.SufficientReason.CandidateID = "candidate-v8"
		}},
		{"evidence ids", func(c *AuthoritativeChange) { c.EvidenceRefs = []string{"fact-x", "fact-y"} }},
		{"sufficient reason prose", func(c *AuthoritativeChange) {
			concl := hsConclusion()
			concl.SufficientReasonSummary = "Reworded but identical judgment."
			c.Projection.Assessment = &concl
		}},
		{"input version alone", func(c *AuthoritativeChange) { c.Situation.InputVersion = 99 }},
		{"non-milestone recurrence count", func(c *AuthoritativeChange) { c.RecurrenceCount = 2 }},
	}

	for _, tc := range cases {
		t.Run(tc.name+" is not material", func(t *testing.T) {
			c := hsNext(t)
			tc.muton(&c)
			got, err := BuildTransitions(c)
			if err != nil {
				t.Fatalf("BuildTransitions: %v", err)
			}
			if len(got) != 0 {
				t.Fatalf("got %d transitions, want 0: %+v", len(got), got)
			}
		})
	}
}

// ----------------------------------------------------------------------
// Step 2: deterministic identity and authority.
// ----------------------------------------------------------------------

func TestTransitionIdentityIsDeterministic(t *testing.T) {
	build := func(mut func(c *AuthoritativeChange)) []model.Transition {
		t.Helper()
		c := hsNext(t)
		c.Situation.Attention = model.AttentionUrgent
		c.Assessment.Attention = model.AttentionUrgent
		c.OperatorArtifacts = []OperatorArtifactInput{hsArtifact("input-1", artifactKindAnnotation, hsNow(t))}
		if mut != nil {
			mut(&c)
		}
		got, err := BuildTransitions(c)
		if err != nil {
			t.Fatalf("BuildTransitions: %v", err)
		}
		return got
	}

	a := build(nil)
	b := build(nil)
	if len(a) != 2 || len(b) != 2 {
		t.Fatalf("want 2 transitions per run, got %d and %d", len(a), len(b))
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			t.Errorf("transition %d id is not deterministic: %q vs %q", i, a[i].ID, b[i].ID)
		}
		if a[i].ID == "" {
			t.Errorf("transition %d id is empty", i)
		}
	}
	if a[0].ID == a[1].ID {
		t.Error("two transitions in one commit share an id")
	}

	other := build(func(c *AuthoritativeChange) {
		c.Situation.InputVersion = 9
		c.OperatorArtifacts[0].AppliedInputVersion = 9
	})
	for i := range a {
		if a[i].ID == other[i].ID {
			t.Errorf("transition %d id did not change with the authoritative input version", i)
		}
	}
}

func TestTransitionIdentityFollowsArtifactIdentity(t *testing.T) {
	base := hsNext(t)
	base.OperatorArtifacts = []OperatorArtifactInput{hsArtifact("input-1", artifactKindAnnotation, hsNow(t))}
	first, err := BuildTransitions(base)
	if err != nil {
		t.Fatalf("BuildTransitions: %v", err)
	}

	other := hsNext(t)
	other.OperatorArtifacts = []OperatorArtifactInput{hsArtifact("input-2", artifactKindAnnotation, hsNow(t))}
	second, err := BuildTransitions(other)
	if err != nil {
		t.Fatalf("BuildTransitions: %v", err)
	}
	if first[0].ID == second[0].ID {
		t.Error("two different artifact inputs produced the same transition id")
	}
}

func TestOperatorArtifactAuthorityIsBounded(t *testing.T) {
	prior := hsFirst(t)
	sum := hsPriorSummary(t, prior)
	c := hsNext(t)
	c.OperatorArtifacts = []OperatorArtifactInput{hsArtifact("input-1", artifactKindAnnotation, hsNow(t))}

	got, err := BuildTransitions(c)
	if err != nil {
		t.Fatalf("BuildTransitions: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d transitions, want 1 (the artifact alone)", len(got))
	}
	art := got[0]

	if art.Actor != model.ActorAttributedOperator {
		t.Errorf("actor = %q, want attributed_operator", art.Actor)
	}
	if art.Lifecycle != prior.Lifecycle {
		t.Errorf("an annotation changed lifecycle: %q -> %q", prior.Lifecycle, art.Lifecycle)
	}
	if art.Attention != prior.Attention {
		t.Errorf("an annotation changed Attention: %q -> %q", prior.Attention, art.Attention)
	}
	if art.ActionContract.NextActor != prior.ActionContract.NextActor {
		t.Errorf("an annotation changed the operator contract's next actor: %q -> %q",
			prior.ActionContract.NextActor, art.ActionContract.NextActor)
	}
	if (art.Projection.Assessment == nil) != (prior.Projection.Assessment == nil) {
		t.Fatal("an annotation changed whether an Assessment conclusion is recorded")
	}
	if canonicalDigest(*art.Projection.Assessment) != canonicalDigest(*prior.Projection.Assessment) {
		t.Errorf("an annotation changed the Assessment conclusion: %+v -> %+v",
			*prior.Projection.Assessment, *art.Projection.Assessment)
	}
	if art.InterruptionPriority != nil {
		t.Errorf("an annotation is never a main-channel poke, got priority %q", *art.InterruptionPriority)
	}
	if art.Journal.AttributedActor != "operator@example.com" {
		t.Errorf("attributed actor = %q, want operator@example.com", art.Journal.AttributedActor)
	}

	folded, err := ProjectEpisode(&sum, art)
	if err != nil {
		t.Fatalf("ProjectEpisode: %v", err)
	}
	if len(folded.RecordedOperatorContext) != 1 {
		t.Fatalf("recorded operator context = %v, want exactly one entry", folded.RecordedOperatorContext)
	}
	if folded.CurrentAttention != sum.CurrentAttention {
		t.Errorf("an annotation changed the summary's Attention: %q -> %q", sum.CurrentAttention, folded.CurrentAttention)
	}
}

func TestOperatorArtifactAuthorityRejectsUnknownKindAndPolicyActor(t *testing.T) {
	t.Run("unknown artifact kind", func(t *testing.T) {
		c := hsNext(t)
		bad := hsArtifact("input-1", artifactKindAnnotation, hsNow(t))
		bad.Kind = "operator_policy_recorded"
		c.OperatorArtifacts = []OperatorArtifactInput{bad}
		if _, err := BuildTransitions(c); err == nil {
			t.Fatal("want error for an unknown artifact kind, got nil")
		}
	})

	t.Run("annotation without an annotation id", func(t *testing.T) {
		c := hsNext(t)
		bad := hsArtifact("input-1", artifactKindAnnotation, hsNow(t))
		bad.AnnotationID = nil
		c.OperatorArtifacts = []OperatorArtifactInput{bad}
		if _, err := BuildTransitions(c); err == nil {
			t.Fatal("want error for an annotation with no annotation id, got nil")
		}
	})

	t.Run("operator_policy is never produced", func(t *testing.T) {
		c := hsNext(t)
		c.Situation.Attention = model.AttentionUrgent
		c.Assessment.Attention = model.AttentionUrgent
		c.OperatorArtifacts = []OperatorArtifactInput{hsArtifact("input-1", artifactKindVerdict, hsNow(t))}
		got, err := BuildTransitions(c)
		if err != nil {
			t.Fatalf("BuildTransitions: %v", err)
		}
		for i, tr := range got {
			if tr.Actor == model.ActorOperatorPolicy {
				t.Errorf("transition %d used the reserved Plan 5 operator_policy actor", i)
			}
			if err := tr.Actor.Validate(); err != nil {
				t.Errorf("transition %d actor rejected by the model: %v", i, err)
			}
		}
	})
}

// ----------------------------------------------------------------------
// Steps 4/5: the pure Episode fold.
// ----------------------------------------------------------------------

func TestProjectEpisodeStartsAtVersionOne(t *testing.T) {
	first := hsFirst(t)
	sum, err := ProjectEpisode(nil, first)
	if err != nil {
		t.Fatalf("ProjectEpisode: %v", err)
	}
	if sum.Version != 1 {
		t.Errorf("version = %d, want 1", sum.Version)
	}
	if sum.SourceTransitionSequence != first.Sequence {
		t.Errorf("source transition sequence = %d, want %d", sum.SourceTransitionSequence, first.Sequence)
	}
	if !sum.EffectiveStartedAt.Equal(first.Projection.EffectiveStartedAt) {
		t.Errorf("effective start = %s, want the projection's %s (never CreatedAt %s)",
			sum.EffectiveStartedAt, first.Projection.EffectiveStartedAt, first.CreatedAt)
	}
	if sum.EffectiveStartedAt.Equal(first.CreatedAt) {
		t.Error("effective start must not come from the transition's creation time (R3)")
	}
	if sum.InitialPublicationReason != string(model.ReasonFirstAuthoritativeState) {
		t.Errorf("initial publication reason = %q, want %q", sum.InitialPublicationReason, model.ReasonFirstAuthoritativeState)
	}
	if sum.PeakAttention != model.AttentionInvestigate || sum.CurrentAttention != model.AttentionInvestigate {
		t.Errorf("attention = %q/%q, want investigate/investigate", sum.CurrentAttention, sum.PeakAttention)
	}
	if err := sum.Validate(); err != nil {
		t.Errorf("folded summary failed model validation: %v", err)
	}
}

func TestProjectEpisodeAdvancesExactlyOncePerTransition(t *testing.T) {
	c := hsNext(t)
	c.Situation.Attention = model.AttentionUrgent
	c.Assessment.Attention = model.AttentionUrgent
	c.OperatorArtifacts = []OperatorArtifactInput{
		hsArtifact("input-1", artifactKindAnnotation, hsNow(t)),
		hsArtifact("input-2", artifactKindVerdict, hsNow(t).Add(time.Second)),
	}
	got, err := BuildTransitions(c)
	if err != nil {
		t.Fatalf("BuildTransitions: %v", err)
	}

	sum := *c.PriorSummary
	startVersion := sum.Version
	for i, tr := range got {
		next, err := ProjectEpisode(&sum, tr)
		if err != nil {
			t.Fatalf("ProjectEpisode(%d): %v", i, err)
		}
		if next.Version != sum.Version+1 {
			t.Fatalf("fold %d advanced version %d -> %d, want exactly one", i, sum.Version, next.Version)
		}
		sum = next
	}
	if sum.Version != startVersion+len(got) {
		t.Errorf("version = %d, want %d", sum.Version, startVersion+len(got))
	}
	if sum.PeakAttention != model.AttentionUrgent || sum.CurrentAttention != model.AttentionUrgent {
		t.Errorf("attention = %q/%q, want urgent/urgent", sum.CurrentAttention, sum.PeakAttention)
	}
	if len(sum.RecordedOperatorContext) != 2 {
		t.Errorf("recorded operator context = %v, want two entries", sum.RecordedOperatorContext)
	}
}

func TestProjectEpisodeKeepsPeakAttentionThroughDeEscalation(t *testing.T) {
	c := hsNext(t)
	c.Situation.Attention = model.AttentionUrgent
	c.Assessment.Attention = model.AttentionUrgent
	urgent := hsOnly(t, c)
	sum, err := ProjectEpisode(c.PriorSummary, urgent)
	if err != nil {
		t.Fatalf("ProjectEpisode: %v", err)
	}

	back := hsNext(t)
	back.Now = back.Now.Add(time.Minute)
	back.Situation.InputVersion = 9
	back.PriorTransition = &urgent
	back.PriorSummary = &sum
	calmed := hsOnly(t, back)
	if calmed.Reason != model.ReasonAttentionChanged {
		t.Fatalf("reason = %q, want attention_changed", calmed.Reason)
	}
	final, err := ProjectEpisode(&sum, calmed)
	if err != nil {
		t.Fatalf("ProjectEpisode: %v", err)
	}
	if final.CurrentAttention != model.AttentionInvestigate {
		t.Errorf("current attention = %q, want investigate", final.CurrentAttention)
	}
	if final.PeakAttention != model.AttentionUrgent {
		t.Errorf("peak attention = %q, want urgent retained", final.PeakAttention)
	}
}

func TestProjectEpisodeTerminalDurationAndOutcome(t *testing.T) {
	c := hsNext(t)
	hsRecovered(&c)
	c.Projection.PublicHandle = stringPtrOf("SIT-7QK2")

	tr := hsOnly(t, c)
	sum, err := ProjectEpisode(c.PriorSummary, tr)
	if err != nil {
		t.Fatalf("ProjectEpisode: %v", err)
	}
	if sum.TerminalAt == nil || !sum.TerminalAt.Equal(c.Now) {
		t.Fatalf("terminal at = %v, want %s", sum.TerminalAt, c.Now)
	}
	want := int64(c.Now.Sub(sum.EffectiveStartedAt) / time.Second)
	if sum.DurationSeconds == nil || *sum.DurationSeconds != want {
		t.Errorf("duration seconds = %v, want %d (terminal - effective start)", sum.DurationSeconds, want)
	}
	if sum.PublicHandle != "SIT-7QK2" {
		t.Errorf("public handle = %q, want SIT-7QK2", sum.PublicHandle)
	}
	if sum.FinalOutcome == "" {
		t.Error("final outcome is empty on a terminal fold")
	}
	if sum.RecoveryObservedAt == nil {
		t.Error("recovery observation lost on the terminal fold")
	}
}

func TestProjectEpisodeClosedUnknownRecordsUncertainty(t *testing.T) {
	c := hsNext(t)
	hsClosedUnknown(&c)

	tr := hsOnly(t, c)
	sum, err := ProjectEpisode(c.PriorSummary, tr)
	if err != nil {
		t.Fatalf("ProjectEpisode: %v", err)
	}
	if sum.RemainingUncertainty == "" {
		t.Error("closed_unknown recorded no remaining uncertainty")
	}
	if sum.InvestigationStarted {
		t.Error("a direct closed_unknown must not set InvestigationStarted")
	}
	if got := DeriveOrientation(sum, tr); got != OrientationClosedUncertain {
		t.Errorf("orientation = %q, want %q", got, OrientationClosedUncertain)
	}
}

func TestProjectEpisodeRejectsIncoherentFolds(t *testing.T) {
	first := hsFirst(t)
	sum, err := ProjectEpisode(nil, first)
	if err != nil {
		t.Fatalf("ProjectEpisode: %v", err)
	}

	next := func() model.Transition {
		c := hsNext(t)
		c.Situation.Attention = model.AttentionUrgent
		c.Assessment.Attention = model.AttentionUrgent
		return hsOnly(t, c)
	}

	t.Run("duplicate sequence", func(t *testing.T) {
		tr := next()
		tr.Sequence = sum.SourceTransitionSequence
		if _, err := ProjectEpisode(&sum, tr); err == nil {
			t.Fatal("want error for a duplicate sequence, got nil")
		}
	})

	t.Run("skipped sequence", func(t *testing.T) {
		tr := next()
		tr.Sequence = sum.SourceTransitionSequence + 2
		if _, err := ProjectEpisode(&sum, tr); err == nil {
			t.Fatal("want error for a skipped sequence, got nil")
		}
	})

	t.Run("situation mismatch", func(t *testing.T) {
		tr := next()
		tr.SituationID = "1f0f5a0c-0000-4000-8000-00000000ffff"
		if _, err := ProjectEpisode(&sum, tr); err == nil {
			t.Fatal("want error for a Situation mismatch, got nil")
		}
	})

	t.Run("time reversal", func(t *testing.T) {
		tr := next()
		tr.CreatedAt = sum.UpdatedAt.Add(-time.Second)
		if _, err := ProjectEpisode(&sum, tr); err == nil {
			t.Fatal("want error for a time reversal, got nil")
		}
	})

	t.Run("mutation after a terminal transition", func(t *testing.T) {
		c := hsNext(t)
		hsRecovered(&c)
		terminal := hsOnly(t, c)
		terminalSummary, err := ProjectEpisode(c.PriorSummary, terminal)
		if err != nil {
			t.Fatalf("ProjectEpisode(terminal): %v", err)
		}

		later := next()
		later.Sequence = terminalSummary.SourceTransitionSequence + 1
		later.CreatedAt = terminalSummary.UpdatedAt.Add(time.Minute)
		if _, err := ProjectEpisode(&terminalSummary, later); err == nil {
			t.Fatal("want error for a post-terminal fold, got nil")
		}
	})
}

func TestProjectEpisodeOrientationStateMachine(t *testing.T) {
	// Observed -> Investigating -> Monitoring -> Recovered, plus the refire
	// return from Monitoring to Investigating.
	observedChange := hsChange(t)
	observedChange.Assessment.ActionContract = hsMonitoringContract(observedChange.Now.Add(time.Minute))
	observed := hsOnly(t, observedChange)
	sum, err := ProjectEpisode(nil, observed)
	if err != nil {
		t.Fatalf("ProjectEpisode: %v", err)
	}
	if got := DeriveOrientation(sum, observed); got != OrientationObserved {
		t.Fatalf("orientation = %q, want %q", got, OrientationObserved)
	}

	step := func(prior model.Transition, priorSum model.EpisodeSummary, version int, mut func(c *AuthoritativeChange)) (model.Transition, model.EpisodeSummary) {
		t.Helper()
		c := hsChange(t)
		c.Now = prior.CreatedAt.Add(time.Minute)
		c.Situation.InputVersion = version
		c.PriorTransition = &prior
		c.PriorSummary = &priorSum
		c.Assessment.ActionContract = hsRunningTriageContract(c.Now.Add(time.Minute))
		if mut != nil {
			mut(&c)
		}
		tr := hsOnly(t, c)
		next, err := ProjectEpisode(&priorSum, tr)
		if err != nil {
			t.Fatalf("ProjectEpisode: %v", err)
		}
		return tr, next
	}

	investigating, sum := step(observed, sum, 8, nil)
	if got := DeriveOrientation(sum, investigating); got != OrientationInvestigating {
		t.Fatalf("orientation = %q, want %q", got, OrientationInvestigating)
	}
	if !sum.InvestigationStarted {
		t.Fatal("investigation start was not recorded in the summary")
	}

	monitoring, sum := step(investigating, sum, 9, func(c *AuthoritativeChange) {
		c.Situation.Lifecycle = model.LifecycleRecoveryPending
		c.Assessment.Lifecycle = model.LifecycleRecoveryPending
		c.Situation.RecoveryObservedAt = timePtr(c.Now)
		c.Projection.RecoveryObservedAt = timePtr(c.Now)
	})
	if got := DeriveOrientation(sum, monitoring); got != OrientationMonitoring {
		t.Fatalf("orientation = %q, want %q", got, OrientationMonitoring)
	}

	refired, refiredSum := step(monitoring, sum, 10, nil)
	if refired.Reason != model.ReasonRecoveryFailed {
		t.Fatalf("reason = %q, want recovery_failed", refired.Reason)
	}
	if got := DeriveOrientation(refiredSum, refired); got != OrientationInvestigating {
		t.Fatalf("refire orientation = %q, want %q", got, OrientationInvestigating)
	}

	recovered, recoveredSum := step(monitoring, sum, 10, hsRecovered)
	if got := DeriveOrientation(recoveredSum, recovered); got != OrientationRecovered {
		t.Fatalf("orientation = %q, want %q", got, OrientationRecovered)
	}
}

func TestProjectEpisodeAccumulatesInvestigationWork(t *testing.T) {
	first := hsFirst(t)
	sum := hsPriorSummary(t, first)

	c := hsNext(t)
	c.Assessment.ActionContract = hsMonitoringContract(c.Now.Add(time.Minute))
	concluded := hsOnly(t, c)
	sum, err := ProjectEpisode(&sum, concluded)
	if err != nil {
		t.Fatalf("ProjectEpisode: %v", err)
	}
	if len(sum.InvestigationWork) == 0 {
		t.Fatal("investigation work is empty after a conclusion")
	}
	if sum.EvidenceConclusion == "" {
		t.Error("evidence conclusion is empty after a conclusion")
	}
	if sum.LatestMaterialReason != string(model.ReasonInvestigationConcluded) {
		t.Errorf("latest material reason = %q, want investigation_concluded", sum.LatestMaterialReason)
	}
	if sum.ImpactSummary == "" {
		t.Error("impact summary is empty")
	}
}

// ----------------------------------------------------------------------
// HistoryCommit composition (the value Task 5 commits).
// ----------------------------------------------------------------------

func TestBuildTransitionsHistoryCommitComposition(t *testing.T) {
	c := hsNext(t)
	c.Situation.Attention = model.AttentionUrgent
	c.Assessment.Attention = model.AttentionUrgent
	c.OperatorArtifacts = []OperatorArtifactInput{hsArtifact("input-1", artifactKindAnnotation, hsNow(t))}

	commit, err := BuildHistoryCommit(c, PublicationInput{
		Situation:       c.Situation,
		PriorTransition: c.PriorTransition,
		RootPublished:   true,
		SlackFloor:      model.InterruptionLow,
		RepageCooldown:  15 * time.Minute,
		Now:             c.Now,
	})
	if err != nil {
		t.Fatalf("BuildHistoryCommit: %v", err)
	}
	if len(commit.Transitions) != 2 {
		t.Fatalf("got %d transitions, want 2", len(commit.Transitions))
	}
	if commit.Summary == nil {
		t.Fatal("summary is nil after a material commit")
	}
	if want := c.PriorSummary.Version + 2; commit.Summary.Version != want {
		t.Errorf("summary version = %d, want %d", commit.Summary.Version, want)
	}
	if len(commit.Intents) == 0 {
		t.Error("no notification intents planned for a material commit")
	}

	quiet, err := BuildHistoryCommit(hsNext(t), PublicationInput{
		Situation:      hsNext(t).Situation,
		RootPublished:  true,
		SlackFloor:     model.InterruptionLow,
		RepageCooldown: 15 * time.Minute,
		Now:            c.Now,
	})
	if err != nil {
		t.Fatalf("BuildHistoryCommit(quiet): %v", err)
	}
	if len(quiet.Transitions) != 0 || quiet.Summary != nil || len(quiet.Intents) != 0 {
		t.Errorf("a quiet cycle produced %+v, want an empty commit", quiet)
	}
}

func TestBuildTransitionsRejectsIncoherentInput(t *testing.T) {
	t.Run("prior transition from another Situation", func(t *testing.T) {
		c := hsNext(t)
		other := *c.PriorTransition
		other.SituationID = "1f0f5a0c-0000-4000-8000-00000000ffff"
		c.PriorTransition = &other
		if _, err := BuildTransitions(c); err == nil {
			t.Fatal("want error, got nil")
		}
	})

	t.Run("terminal lifecycle without a terminal instant", func(t *testing.T) {
		c := hsNext(t)
		c.Situation.Lifecycle = model.LifecycleRecovered
		c.Assessment.Lifecycle = model.LifecycleRecovered
		c.Assessment.Cadence = model.Cadence("")
		c.Assessment.ActionContract = hsTerminalContract()
		if _, err := BuildTransitions(c); err == nil {
			t.Fatal("want error, got nil")
		}
	})

	// Migration 0014's lifecycle CHECK, both directions: closed_unknown
	// carries a terminal reason, recovered never does. ProjectionFacts
	// alone cannot enforce this (it has no lifecycle), and without it a
	// closed_unknown with no reason folds into the Episode summary as a
	// clean recovery.
	t.Run("closed_unknown without a terminal reason", func(t *testing.T) {
		c := hsNext(t)
		hsClosedUnknown(&c)
		c.Situation.TerminalReason = nil
		c.Projection.TerminalReason = nil
		if _, err := BuildTransitions(c); err == nil {
			t.Fatal("want error, got nil")
		}
	})

	t.Run("recovered with a terminal reason", func(t *testing.T) {
		c := hsNext(t)
		hsRecovered(&c)
		reason := model.TerminalReasonObservationDeadline
		c.Situation.TerminalReason = &reason
		c.Projection.TerminalReason = &reason
		if _, err := BuildTransitions(c); err == nil {
			t.Fatal("want error, got nil")
		}
	})

	t.Run("non-UTC now", func(t *testing.T) {
		c := hsNext(t)
		c.Now = c.Now.In(time.FixedZone("test", 3600))
		if _, err := BuildTransitions(c); err == nil {
			t.Fatal("want error, got nil")
		}
	})

	t.Run("prior transition without a prior summary", func(t *testing.T) {
		c := hsNext(t)
		c.PriorSummary = nil
		if _, err := BuildTransitions(c); err == nil {
			t.Fatal("want error, got nil")
		}
	})
}

func TestBuildTransitionsMarksDrills(t *testing.T) {
	c := hsNext(t)
	c.Drill = true
	c.Situation.Attention = model.AttentionUrgent
	c.Assessment.Attention = model.AttentionUrgent
	c.OperatorArtifacts = []OperatorArtifactInput{hsArtifact("input-1", artifactKindAnnotation, hsNow(t))}
	got, err := BuildTransitions(c)
	if err != nil {
		t.Fatalf("BuildTransitions: %v", err)
	}
	for i, tr := range got {
		if !tr.Drill {
			t.Errorf("transition %d lost the Drill marker", i)
		}
	}
}
