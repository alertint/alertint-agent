// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"fmt"
	"strings"
	"testing"
	"time"

	slacklib "github.com/slack-go/slack"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Fixtures. Prefixed `rs` (render situation) so they never collide with
// any package-level helper this file's sibling test files add.
// ----------------------------------------------------------------------

const rsSituationID = "1f0f5a0c-0000-4000-8000-0000000000a1"

func rsMustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse time %q: %v", s, err)
	}
	return tm.UTC()
}

func rsTimePtr(t time.Time) *time.Time { return &t }

func rsRunningTriageContract(next time.Time) model.ActionContract {
	action := model.AlertINTActionRunAcuteTriage
	status := model.AlertINTStatusRunning
	return model.ActionContract{
		NextActor:      model.NextActorAlertINT,
		AlertINTAction: &action,
		AlertINTStatus: &status,
		NextUpdateAt:   rsTimePtr(next),
		NextUpdateOn:   []model.NextUpdateOn{model.NextUpdateOnTriageOutcome},
	}
}

func rsMonitoringContract(next time.Time) model.ActionContract {
	action := model.AlertINTActionVerifyRecovery
	status := model.AlertINTStatusWaiting
	wait := model.WaitReasonRecoveryGrace
	return model.ActionContract{
		NextActor:      model.NextActorAlertINT,
		AlertINTAction: &action,
		AlertINTStatus: &status,
		NextUpdateAt:   rsTimePtr(next),
		NextUpdateOn:   []model.NextUpdateOn{model.NextUpdateOnRecoveryGraceExpired},
		WaitReason:     &wait,
	}
}

func rsTerminalContract() model.ActionContract {
	return model.ActionContract{NextActor: model.NextActorNone}
}

// rsObserveContract is a valid nonterminal contract with no current
// AlertINT action or Operator ask — the pre-investigation "just observing"
// state.
func rsObserveContract(next time.Time) model.ActionContract {
	return model.ActionContract{
		NextActor:    model.NextActorNone,
		NextUpdateAt: rsTimePtr(next),
		NextUpdateOn: []model.NextUpdateOn{model.NextUpdateOnLifecycleObservationDeadline},
	}
}

func rsAssessment(causality model.Causality, impact model.Impact) *model.AssessmentConclusion {
	return &model.AssessmentConclusion{
		Persistence:             model.PersistenceSustained,
		Impact:                  impact,
		Novelty:                 model.NoveltyFamiliar,
		Causality:               causality,
		EvidenceQuality:         model.EvidenceQualityComplete,
		SufficientReasonSummary: "checkout latency exceeded threshold for 10 minutes",
	}
}

func rsProjection(startedAt time.Time, assessment *model.AssessmentConclusion) model.ProjectionFacts {
	return model.ProjectionFacts{
		EffectiveStartedAt:      startedAt,
		EffectiveStartedAtBasis: model.SourceTimeBasisSourcePayload,
		Assessment:              assessment,
	}
}

// rsTransition builds a valid Transition fixture. Callers mutate the
// returned value's Projection/Journal fields directly for scenarios that
// need extra facts (recovery instants, terminal reason, drill).
func rsTransition(seq int, lifecycle model.Lifecycle, attention model.Attention, contract model.ActionContract,
	reason model.TransitionReason, journalKind model.JournalKind, journal model.JournalData,
	projection model.ProjectionFacts, createdAt time.Time) model.Transition {
	return model.Transition{
		ID:               fmt.Sprintf("transition-%03d", seq),
		SituationID:      rsSituationID,
		Sequence:         seq,
		InputVersion:     seq,
		MaterialFactHash: "sha256:abc123",
		Lifecycle:        lifecycle,
		Attention:        attention,
		ActionContract:   contract,
		Reason:           reason,
		JournalKind:      journalKind,
		Journal:          journal,
		Projection:       projection,
		EvidenceRefs:     []string{"evidence-1"},
		Actor:            model.ActorDeterministicController,
		CreatedAt:        createdAt,
	}
}

// rsSummary builds a valid EpisodeSummary fixture coherent with a
// Transition of the given sequence.
func rsSummary(seq int, title string, attention model.Attention, contract model.ActionContract,
	startedAt, updatedAt time.Time) model.EpisodeSummary {
	return model.EpisodeSummary{
		SituationID:              rsSituationID,
		Version:                  seq,
		SourceTransitionSequence: seq,
		Title:                    title,
		CurrentAttention:         attention,
		PeakAttention:            attention,
		ActionContract:           contract,
		EffectiveStartedAt:       startedAt,
		UpdatedAt:                updatedAt,
		InvestigationWork:        []string{},
		RecordedOperatorContext:  []string{},
	}
}

func rsFallbackBlocksText(msg RenderedMessage) string {
	var b strings.Builder
	for _, blk := range msg.Blocks {
		switch v := blk.(type) {
		case *slacklib.SectionBlock:
			if v.Text != nil {
				b.WriteString(v.Text.Text)
				b.WriteString("\n")
			}
		case *slacklib.ContextBlock:
			for _, el := range v.ContextElements.Elements {
				if txt, ok := el.(*slacklib.TextBlockObject); ok {
					b.WriteString(txt.Text)
					b.WriteString("\n")
				}
			}
		}
	}
	return b.String()
}

func rsCountBold(s, phase string) int {
	return strings.Count(s, "*"+phase+"*")
}

// ----------------------------------------------------------------------
// Step 1: first/updated root, orientation, R4 deadline rendering.
// ----------------------------------------------------------------------

func TestRenderSituationRootFirstAndUpdated(t *testing.T) {
	started := rsMustTime(t, "2026-09-05T09:00:00Z")
	now := rsMustTime(t, "2026-09-05T10:00:00Z")
	deadline := now.Add(90 * time.Second) // ceil-rounds to 2 minutes

	cases := []struct {
		name          string
		lifecycle     model.Lifecycle
		attention     model.Attention
		reason        model.TransitionReason
		contract      model.ActionContract
		investigation []string
		wantBoldPhase string
		wantOrient    string
		wantContract  string
	}{
		{
			name:          "first publication, before investigation",
			lifecycle:     model.LifecycleActive,
			attention:     model.AttentionObserve,
			reason:        model.ReasonFirstAuthoritativeState,
			contract:      rsObserveContract(deadline),
			wantBoldPhase: "Observed",
			wantOrient:    "observed",
			wantContract:  "No action currently required",
		},
		{
			name:          "updated after investigation starts",
			lifecycle:     model.LifecycleActive,
			attention:     model.AttentionInvestigate,
			reason:        model.ReasonInvestigationStarted,
			contract:      rsRunningTriageContract(deadline),
			investigation: []string{"ran acute triage"},
			wantBoldPhase: "Investigating",
			wantOrient:    "investigating",
			wantContract:  "AlertINT is running Acute Triage",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			contract := c.contract
			tr := rsTransition(1, c.lifecycle, c.attention, contract, c.reason,
				model.JournalPublication, model.JournalData{Headline: "Situation published", OccurredAt: started},
				rsProjection(started, rsAssessment(model.CausalitySupported, model.ImpactConfirmed)), now)
			summary := rsSummary(1, "Situation checkout-001", c.attention, contract, started, now)
			summary.InvestigationStarted = len(c.investigation) > 0
			summary.InvestigationWork = c.investigation
			summary.EvidenceConclusion = "checkout latency exceeded threshold"
			summary.ImpactSummary = "Confirmed impact"
			summary.LatestMaterialReason = string(c.reason)

			got, err := RenderSituationRoot(SituationRootInput{
				Summary:            summary,
				SourceTransition:   tr,
				ContractDeadlineAt: &deadline,
				Now:                now,
			})
			if err != nil {
				t.Fatalf("RenderSituationRoot() error = %v", err)
			}
			text := rsFallbackBlocksText(got)

			if rsCountBold(text, c.wantBoldPhase) != 1 {
				t.Fatalf("orientation chain = %q, want exactly one bold phase %q", text, c.wantBoldPhase)
			}
			// Exactly one bolded phase overall (no other phase word wrapped
			// in "*...*").
			totalBoldMarkers := strings.Count(text, "*Observed*") + strings.Count(text, "*Investigating*") +
				strings.Count(text, "*Monitoring*") + strings.Count(text, "*Recovered*") + strings.Count(text, "*Closed uncertain*")
			if totalBoldMarkers != 1 {
				t.Fatalf("expected exactly one bolded orientation phase, got %d in %q", totalBoldMarkers, text)
			}
			if !strings.Contains(got.Text, c.wantOrient) {
				t.Fatalf("fallback text = %q, want to mention orientation %q", got.Text, c.wantOrient)
			}
			if !strings.Contains(text, c.wantContract) {
				t.Fatalf("body = %q, want the compact contract line %q", text, c.wantContract)
			}
			if !strings.Contains(text, "update by") || !strings.Contains(text, "(2 min)") {
				t.Fatalf("body = %q, want a ceil-rounded 2-minute countdown", text)
			}
			if !strings.Contains(text, "<!date^") {
				t.Fatalf("body = %q, want a Slack viewer-local date token", text)
			}
		})
	}
}

func TestRenderSituationRootDeadlineOverdue(t *testing.T) {
	started := rsMustTime(t, "2026-09-05T09:00:00Z")
	now := rsMustTime(t, "2026-09-05T10:00:00Z")
	pastDeadline := now.Add(-5 * time.Minute)

	contract := rsRunningTriageContract(now.Add(time.Hour)) // stored contract's own deadline; irrelevant to R4
	tr := rsTransition(2, model.LifecycleActive, model.AttentionInvestigate, contract,
		model.ReasonInvestigationStarted, model.JournalInvestigationStarted,
		model.JournalData{Headline: "AlertINT investigation started", OccurredAt: started},
		rsProjection(started, nil), now)
	summary := rsSummary(2, "Situation checkout-001", model.AttentionInvestigate, contract, started, now)

	got, err := RenderSituationRoot(SituationRootInput{
		Summary:            summary,
		SourceTransition:   tr,
		ContractDeadlineAt: &pastDeadline, // R4: the DELIVERING intent's deadline, distinct from the stored contract's
		Now:                now,
	})
	if err != nil {
		t.Fatalf("RenderSituationRoot() error = %v", err)
	}
	text := rsFallbackBlocksText(got)
	if !strings.Contains(text, "update overdue since") {
		t.Fatalf("body = %q, want an overdue promise, never a current one", text)
	}
	if strings.Contains(text, "update by") {
		t.Fatalf("body = %q, must not also render a current promise", text)
	}
}

func TestRenderSituationRootRendersIntentDeadlineNotSummaryContract(t *testing.T) {
	// R4: the root renders the DELIVERING INTENT's contract deadline, never
	// the Episode summary's own stored ActionContract.NextUpdateAt.
	started := rsMustTime(t, "2026-09-05T09:00:00Z")
	now := rsMustTime(t, "2026-09-05T10:00:00Z")
	storedDeadline := now.Add(time.Hour) // far in the future, in the STORED contract
	intentDeadline := now.Add(90 * time.Second)

	contract := rsRunningTriageContract(storedDeadline)
	tr := rsTransition(1, model.LifecycleActive, model.AttentionInvestigate, contract,
		model.ReasonInvestigationStarted, model.JournalInvestigationStarted,
		model.JournalData{Headline: "AlertINT investigation started", OccurredAt: started},
		rsProjection(started, nil), now)
	summary := rsSummary(1, "Situation checkout-001", model.AttentionInvestigate, contract, started, now)

	got, err := RenderSituationRoot(SituationRootInput{
		Summary:            summary,
		SourceTransition:   tr,
		ContractDeadlineAt: &intentDeadline,
		Now:                now,
	})
	if err != nil {
		t.Fatalf("RenderSituationRoot() error = %v", err)
	}
	text := rsFallbackBlocksText(got)
	if !strings.Contains(text, "(2 min)") {
		t.Fatalf("body = %q, want the intent's 2-minute deadline, not the stored contract's 60-minute one", text)
	}
	if strings.Contains(text, "(60 min)") {
		t.Fatalf("body = %q, must never render the Episode summary's own stored deadline", text)
	}
}

func TestRenderSituationRootRequiresContractDeadlineForNonterminal(t *testing.T) {
	started := rsMustTime(t, "2026-09-05T09:00:00Z")
	now := rsMustTime(t, "2026-09-05T10:00:00Z")
	contract := rsRunningTriageContract(now.Add(time.Hour))
	tr := rsTransition(1, model.LifecycleActive, model.AttentionInvestigate, contract,
		model.ReasonInvestigationStarted, model.JournalInvestigationStarted,
		model.JournalData{Headline: "x", OccurredAt: started}, rsProjection(started, nil), now)
	summary := rsSummary(1, "Situation x", model.AttentionInvestigate, contract, started, now)

	_, err := RenderSituationRoot(SituationRootInput{Summary: summary, SourceTransition: tr, Now: now})
	if err == nil {
		t.Fatal("RenderSituationRoot() error = nil, want an error: a nonterminal root requires R4's contract deadline")
	}
}

func TestRenderSituationRootRejectsContractDeadlineForTerminal(t *testing.T) {
	started := rsMustTime(t, "2026-09-05T09:00:00Z")
	now := rsMustTime(t, "2026-09-05T10:00:00Z")
	terminalAt := now
	contract := rsTerminalContract()
	proj := rsProjection(started, rsAssessment(model.CausalitySupported, model.ImpactConfirmed))
	proj.TerminalAt = &terminalAt
	tr := rsTransition(3, model.LifecycleRecovered, model.AttentionObserve, contract,
		model.ReasonRecovered, model.JournalRecovered,
		model.JournalData{Headline: "Recovered", OccurredAt: now}, proj, now)
	summary := rsSummary(3, "Situation x", model.AttentionObserve, contract, started, now)
	summary.TerminalAt = &terminalAt
	summary.FinalOutcome = "Recovered without recorded operator intervention"

	deadline := now.Add(time.Minute)
	_, err := RenderSituationRoot(SituationRootInput{
		Summary: summary, SourceTransition: tr, ContractDeadlineAt: &deadline, Now: now,
	})
	if err == nil {
		t.Fatal("RenderSituationRoot() error = nil, want an error: a terminal root must not carry a contract deadline")
	}
}

func TestRenderSituationRootValidatesCoherence(t *testing.T) {
	started := rsMustTime(t, "2026-09-05T09:00:00Z")
	now := rsMustTime(t, "2026-09-05T10:00:00Z")
	deadline := now.Add(time.Minute)
	contract := rsRunningTriageContract(deadline)
	tr := rsTransition(1, model.LifecycleActive, model.AttentionInvestigate, contract,
		model.ReasonInvestigationStarted, model.JournalInvestigationStarted,
		model.JournalData{Headline: "x", OccurredAt: started}, rsProjection(started, nil), now)

	t.Run("mismatched situation", func(t *testing.T) {
		summary := rsSummary(1, "x", model.AttentionInvestigate, contract, started, now)
		summary.SituationID = "some-other-situation"
		if _, err := RenderSituationRoot(SituationRootInput{Summary: summary, SourceTransition: tr, ContractDeadlineAt: &deadline, Now: now}); err == nil {
			t.Fatal("want an error for a summary/transition situation mismatch")
		}
	})
	t.Run("mismatched sequence", func(t *testing.T) {
		summary := rsSummary(1, "x", model.AttentionInvestigate, contract, started, now)
		summary.SourceTransitionSequence = 99
		if _, err := RenderSituationRoot(SituationRootInput{Summary: summary, SourceTransition: tr, ContractDeadlineAt: &deadline, Now: now}); err == nil {
			t.Fatal("want an error for a summary/transition sequence mismatch")
		}
	})
}

// ----------------------------------------------------------------------
// Monitoring / recovered / closed-uncertain orientation coverage.
// ----------------------------------------------------------------------

func TestRenderSituationRootMonitoringOrientation(t *testing.T) {
	started := rsMustTime(t, "2026-09-05T09:00:00Z")
	now := rsMustTime(t, "2026-09-05T10:00:00Z")
	graceUntil := now.Add(10 * time.Minute)
	recoveryObserved := now.Add(-time.Minute)

	contract := rsMonitoringContract(graceUntil)
	proj := rsProjection(started, nil)
	proj.RecoveryObservedAt = &recoveryObserved
	proj.GraceUntil = &graceUntil
	tr := rsTransition(4, model.LifecycleRecoveryPending, model.AttentionInvestigate, contract,
		model.ReasonRecoveryObserved, model.JournalRecoveryPending,
		model.JournalData{Headline: "Recovery observed; watching for sustained recovery", OccurredAt: recoveryObserved},
		proj, now)
	summary := rsSummary(4, "Situation x", model.AttentionInvestigate, contract, started, now)
	summary.InvestigationStarted = true
	summary.RecoveryObservedAt = &recoveryObserved

	got, err := RenderSituationRoot(SituationRootInput{Summary: summary, SourceTransition: tr, ContractDeadlineAt: &graceUntil, Now: now})
	if err != nil {
		t.Fatalf("RenderSituationRoot() error = %v", err)
	}
	text := rsFallbackBlocksText(got)
	if rsCountBold(text, "Monitoring") != 1 {
		t.Fatalf("body = %q, want Monitoring bolded", text)
	}
	if !strings.Contains(text, "Watching for sustained recovery") {
		t.Fatalf("body = %q, want the fixed Monitoring contract phrase", text)
	}
}

func TestRenderSituationRootRecoveredAlwaysIncludesMonitoring(t *testing.T) {
	started := rsMustTime(t, "2026-09-05T09:00:00Z")
	recoveryObserved := rsMustTime(t, "2026-09-05T09:30:00Z")
	terminalAt := rsMustTime(t, "2026-09-05T10:00:00Z")
	now := terminalAt

	contract := rsTerminalContract()
	proj := rsProjection(started, rsAssessment(model.CausalitySupported, model.ImpactConfirmed))
	proj.RecoveryObservedAt = &recoveryObserved
	proj.TerminalAt = &terminalAt
	tr := rsTransition(5, model.LifecycleRecovered, model.AttentionObserve, contract,
		model.ReasonRecovered, model.JournalRecovered,
		model.JournalData{Headline: "Recovered", OccurredAt: terminalAt}, proj, now)

	summary := rsSummary(5, "Situation x", model.AttentionObserve, contract, started, now)
	summary.PeakAttention = model.AttentionUrgent
	summary.RecoveryObservedAt = &recoveryObserved
	summary.TerminalAt = &terminalAt
	duration := int64(terminalAt.Sub(started) / time.Second)
	summary.DurationSeconds = &duration
	summary.FinalOutcome = "Recovered without recorded operator intervention"

	got, err := RenderSituationRoot(SituationRootInput{Summary: summary, SourceTransition: tr, Now: now})
	if err != nil {
		t.Fatalf("RenderSituationRoot() error = %v", err)
	}
	text := rsFallbackBlocksText(got)
	if !strings.Contains(text, "Observed → Investigating → Monitoring → *Recovered*") {
		t.Fatalf("chain = %q, recovered must always show Monitoring with exactly Recovered bolded", text)
	}
	if !strings.Contains(text, "without recorded operator intervention") {
		t.Fatalf("body = %q, want the exact no-recorded-operator-intervention phrase", text)
	}
	if strings.Contains(text, "Actor: none") || strings.Contains(text, "next_actor") {
		t.Fatalf("body = %q, terminal root must never collapse to a literal Actor: none", text)
	}
	if !strings.Contains(text, "Peak attention") || !strings.Contains(text, "urgent") {
		t.Fatalf("body = %q, want peak Attention rendered", text)
	}
}

func TestRenderSituationRootClosedUncertainMonitoringVisibility(t *testing.T) {
	started := rsMustTime(t, "2026-09-05T09:00:00Z")
	terminalAt := rsMustTime(t, "2026-09-06T09:00:00Z")
	now := terminalAt
	terminalReason := model.TerminalReasonObservationDeadline

	cases := []struct {
		name                 string
		recoveryObservedAt   *time.Time // on the closing Transition's OWN projection
		recoveryEverObserved bool       // caller-supplied ledger-scan fact
		wantMonitoring       bool
	}{
		{
			name:           "never recovery-pending anywhere in the episode",
			wantMonitoring: false,
		},
		{
			name:               "closing directly out of recovery_pending",
			recoveryObservedAt: rsTimePtr(started.Add(time.Hour)),
			wantMonitoring:     true,
		},
		{
			name:                 "refired earlier, closed later from active (ledger scan says yes)",
			recoveryEverObserved: true,
			wantMonitoring:       true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			contract := rsTerminalContract()
			proj := rsProjection(started, rsAssessment(model.CausalityUnknown, model.ImpactUnknown))
			proj.RecoveryObservedAt = c.recoveryObservedAt
			proj.TerminalAt = &terminalAt
			proj.TerminalReason = &terminalReason
			tr := rsTransition(9, model.LifecycleClosedUnknown, model.AttentionInvestigate, contract,
				model.ReasonClosedUnknown, model.JournalClosedUnknown,
				model.JournalData{Headline: "Closed with uncertainty", OccurredAt: terminalAt}, proj, now)

			summary := rsSummary(9, "Situation x", model.AttentionInvestigate, contract, started, now)
			summary.TerminalAt = &terminalAt
			summary.RecoveryObservedAt = c.recoveryObservedAt
			summary.FinalOutcome = "Closed with uncertainty (observation_deadline)"
			summary.RemainingUncertainty = "AlertINT could not confirm resolution: observation_deadline."

			got, err := RenderSituationRoot(SituationRootInput{
				Summary: summary, SourceTransition: tr, Now: now, RecoveryEverObserved: c.recoveryEverObserved,
			})
			if err != nil {
				t.Fatalf("RenderSituationRoot() error = %v", err)
			}
			text := rsFallbackBlocksText(got)
			hasMonitoring := strings.Contains(text, "Monitoring")
			if hasMonitoring != c.wantMonitoring {
				t.Fatalf("chain = %q, Monitoring present = %v, want %v", text, hasMonitoring, c.wantMonitoring)
			}
			if rsCountBold(text, "Closed uncertain") != 1 {
				t.Fatalf("chain = %q, want exactly one bolded Closed uncertain", text)
			}
			if !strings.Contains(text, "reporting observed symptoms and checks only") {
				t.Fatalf("body = %q, unknown causality must stay observed symptoms, never a root cause", text)
			}
			if strings.Contains(strings.ToLower(text), "root cause") {
				t.Fatalf("body = %q, must never claim a root cause", text)
			}
		})
	}
}

// ----------------------------------------------------------------------
// Step 2: full-picture content, empty-section disappearance, drill.
// ----------------------------------------------------------------------

func TestRenderSituationRootFullPicture(t *testing.T) {
	started := rsMustTime(t, "2026-09-05T09:00:00Z")
	recoveryObserved := rsMustTime(t, "2026-09-05T09:50:00Z")
	terminalAt := rsMustTime(t, "2026-09-05T10:00:00Z")
	now := terminalAt
	terminalReason := model.TerminalReasonResolutionMissing

	contract := rsTerminalContract()
	proj := rsProjection(started, rsAssessment(model.CausalityCorrelated, model.ImpactSuspected))
	proj.RecoveryObservedAt = &recoveryObserved
	proj.TerminalAt = &terminalAt
	proj.TerminalReason = &terminalReason
	tr := rsTransition(12, model.LifecycleClosedUnknown, model.AttentionUrgent, contract,
		model.ReasonClosedUnknown, model.JournalClosedUnknown,
		model.JournalData{Headline: "Closed with uncertainty", OccurredAt: terminalAt}, proj, now)

	summary := rsSummary(12, "Situation checkout-009", model.AttentionUrgent, contract, started, now)
	summary.PeakAttention = model.AttentionUrgent
	summary.EvidenceConclusion = "checkout latency exceeded threshold for 10 minutes"
	summary.ImpactSummary = "Suspected impact"
	summary.InvestigationWork = []string{"ran acute triage", "checked upstream dependency health"}
	summary.InvestigationStarted = true
	summary.RecordedOperatorContext = []string{"ops: acknowledged, escalating to payments team"}
	summary.RecoveryObservedAt = &recoveryObserved
	summary.TerminalAt = &terminalAt
	duration := int64(terminalAt.Sub(started) / time.Second)
	summary.DurationSeconds = &duration
	summary.RecurrenceCount = 3
	summary.FinalOutcome = "Closed with uncertainty (resolution_missing)"
	summary.RemainingUncertainty = "AlertINT could not confirm resolution: resolution_missing. Evidence quality: degraded."

	got, err := RenderSituationRoot(SituationRootInput{Summary: summary, SourceTransition: tr, Now: now})
	if err != nil {
		t.Fatalf("RenderSituationRoot() error = %v", err)
	}
	text := rsFallbackBlocksText(got)

	for _, want := range []string{
		summary.EvidenceConclusion,
		summary.ImpactSummary,
		"ran acute triage",
		"checked upstream dependency health",
		"ops: acknowledged, escalating to payments team",
		"urgent",                     // peak attention
		"recurred ×3",                // recurrence
		"Recovery observed",          // recovery timing
		summary.FinalOutcome,         // outcome
		summary.RemainingUncertainty, // remaining uncertainty
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("full-picture body missing %q; got %q", want, text)
		}
	}

	t.Run("empty optional sections disappear", func(t *testing.T) {
		bare := summary
		bare.EvidenceConclusion = ""
		bare.ImpactSummary = ""
		bare.InvestigationWork = nil
		bare.RecordedOperatorContext = nil
		bare.RecurrenceCount = 0
		bare.RemainingUncertainty = ""
		bareTr := tr
		bareProj := proj
		bareProj.RecoveryObservedAt = nil
		bareTr.Projection = bareProj
		bareTr.Projection.Assessment = nil
		bare.RecoveryObservedAt = nil

		got, err := RenderSituationRoot(SituationRootInput{Summary: bare, SourceTransition: bareTr, Now: now})
		if err != nil {
			t.Fatalf("RenderSituationRoot() error = %v", err)
		}
		bareText := rsFallbackBlocksText(got)
		for _, mustNotContain := range []string{
			"Evidence conclusion:", "recurred ×", "Recovery observed", "Remaining uncertainty:",
			"AlertINT checked:", "Recorded operator context:",
		} {
			if strings.Contains(bareText, mustNotContain) {
				t.Fatalf("empty-section body still contains %q; got %q", mustNotContain, bareText)
			}
		}
		// The facts that ARE present must still be exact and unchanged.
		if !strings.Contains(bareText, bare.FinalOutcome) {
			t.Fatalf("empty-section body missing final outcome; got %q", bareText)
		}
	})
}

func TestRenderSituationRootDrillMarker(t *testing.T) {
	started := rsMustTime(t, "2026-09-05T09:00:00Z")
	now := rsMustTime(t, "2026-09-05T10:00:00Z")
	deadline := now.Add(time.Minute)
	contract := rsRunningTriageContract(deadline)
	tr := rsTransition(1, model.LifecycleActive, model.AttentionInvestigate, contract,
		model.ReasonInvestigationStarted, model.JournalInvestigationStarted,
		model.JournalData{Headline: "x", OccurredAt: started}, rsProjection(started, nil), now)
	tr.Drill = true
	summary := rsSummary(1, "Situation x", model.AttentionInvestigate, contract, started, now)

	got, err := RenderSituationRoot(SituationRootInput{Summary: summary, SourceTransition: tr, ContractDeadlineAt: &deadline, Now: now})
	if err != nil {
		t.Fatalf("RenderSituationRoot() error = %v", err)
	}
	if !strings.Contains(got.Text, "DRILL") {
		t.Fatalf("fallback text = %q, want a DRILL marker", got.Text)
	}
	text := rsFallbackBlocksText(got)
	if !strings.Contains(text, "DRILL") {
		t.Fatalf("body = %q, want a DRILL marker", text)
	}
}

// ----------------------------------------------------------------------
// Journal rendering.
// ----------------------------------------------------------------------

func TestRenderSituationJournalRendersFromTransitionOnly(t *testing.T) {
	occurred := rsMustTime(t, "2026-09-05T09:15:00Z")
	tr := rsTransition(2, model.LifecycleActive, model.AttentionInvestigate, rsRunningTriageContract(occurred.Add(time.Hour)),
		model.ReasonInvestigationStarted, model.JournalInvestigationStarted,
		model.JournalData{Headline: "AlertINT investigation started", Detail: "AlertINT action: run_acute_triage (running)", OccurredAt: occurred},
		rsProjection(occurred.Add(-time.Hour), nil), occurred)

	got, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatalf("RenderSituationJournal() error = %v", err)
	}
	text := rsFallbackBlocksText(got)
	if !strings.Contains(text, "AlertINT investigation started") {
		t.Fatalf("body = %q, want the Transition's own headline", text)
	}
	if !strings.Contains(text, "AlertINT action: run_acute_triage (running)") {
		t.Fatalf("body = %q, want the Transition's own detail", text)
	}
	if !strings.Contains(text, "<!date^") {
		t.Fatalf("body = %q, want a Slack viewer-local date token for occurred_at", text)
	}
	if got.Text == "" {
		t.Fatal("fallback text must not be empty")
	}
}

func TestRenderSituationJournalOperatorHandoff(t *testing.T) {
	// A broadcast handoff renders identically to any other journal entry —
	// reply_broadcast is a delivery-layer decision (cmd/alertint's
	// deliverer), never a rendering difference.
	occurred := rsMustTime(t, "2026-09-05T09:15:00Z")
	action := model.OperatorActionInvestigateSituation
	contract := model.ActionContract{
		NextActor:              model.NextActorOperator,
		OperatorActionRequired: &action,
		NextUpdateAt:           rsTimePtr(occurred.Add(time.Hour)),
		NextUpdateOn:           []model.NextUpdateOn{model.NextUpdateOnMaterialInput},
	}
	tr := rsTransition(3, model.LifecycleActive, model.AttentionUrgent, contract,
		model.ReasonOperatorContractChanged, model.JournalOperatorContractChanged,
		model.JournalData{Headline: "Operator action required: investigate_situation", OccurredAt: occurred},
		rsProjection(occurred.Add(-time.Hour), nil), occurred)

	got, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatalf("RenderSituationJournal() error = %v", err)
	}
	if !strings.Contains(rsFallbackBlocksText(got), "Operator action required") {
		t.Fatalf("body = %q, want the operator handoff headline", rsFallbackBlocksText(got))
	}
}

func TestRenderSituationJournalDelayedNoLongerCurrent(t *testing.T) {
	occurred := rsMustTime(t, "2026-09-05T09:15:00Z")
	base := rsTransition(4, model.LifecycleActive, model.AttentionUrgent, rsRunningTriageContract(occurred.Add(time.Hour)),
		model.ReasonOperatorContractChanged, model.JournalOperatorContractChanged,
		model.JournalData{Headline: "Operator action required: investigate_situation", OccurredAt: occurred},
		rsProjection(occurred.Add(-time.Hour), nil), occurred)

	t.Run("current", func(t *testing.T) {
		got, err := RenderSituationJournal(base)
		if err != nil {
			t.Fatalf("RenderSituationJournal() error = %v", err)
		}
		text := rsFallbackBlocksText(got)
		if strings.Contains(text, "no longer current") || strings.Contains(text, "delayed") {
			t.Fatalf("body = %q, must not mark a current handoff as delayed/no-longer-current", text)
		}
	})

	t.Run("demoted broadcast: delayed and no longer current", func(t *testing.T) {
		stale := base
		stale.Journal.Delayed = true
		stale.Journal.NoLongerCurrent = true
		got, err := RenderSituationJournal(stale)
		if err != nil {
			t.Fatalf("RenderSituationJournal() error = %v", err)
		}
		text := rsFallbackBlocksText(got)
		if !strings.Contains(text, "no longer current") {
			t.Fatalf("body = %q, want a no-longer-current marker", text)
		}
		if !strings.Contains(text, "delayed") {
			t.Fatalf("body = %q, want a delayed marker", text)
		}
		// The original ledger row is never mutated.
		if base.Journal.Delayed || base.Journal.NoLongerCurrent {
			t.Fatal("rendering a local copy must not mutate the original Transition value")
		}
	})
}

func TestRenderSituationJournalRejectsNoJournal(t *testing.T) {
	occurred := rsMustTime(t, "2026-09-05T09:15:00Z")
	tr := rsTransition(5, model.LifecycleActive, model.AttentionInvestigate, rsRunningTriageContract(occurred.Add(time.Hour)),
		model.ReasonTriageStateChanged, model.JournalNone,
		model.JournalData{OccurredAt: occurred}, rsProjection(occurred.Add(-time.Hour), nil), occurred)

	if _, err := RenderSituationJournal(tr); err == nil {
		t.Fatal("RenderSituationJournal() error = nil, want an error for journal_kind = none")
	}
}

func TestRenderSituationJournalDrillMarker(t *testing.T) {
	occurred := rsMustTime(t, "2026-09-05T09:15:00Z")
	tr := rsTransition(6, model.LifecycleActive, model.AttentionInvestigate, rsRunningTriageContract(occurred.Add(time.Hour)),
		model.ReasonInvestigationStarted, model.JournalInvestigationStarted,
		model.JournalData{Headline: "AlertINT investigation started", OccurredAt: occurred},
		rsProjection(occurred.Add(-time.Hour), nil), occurred)
	tr.Drill = true

	got, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatalf("RenderSituationJournal() error = %v", err)
	}
	if !strings.Contains(got.Text, "DRILL") {
		t.Fatalf("fallback text = %q, want a DRILL marker", got.Text)
	}
}

// ----------------------------------------------------------------------
// Installation Delivery-gap recovery notice.
// ----------------------------------------------------------------------

func TestRenderDeliveryGapNotice(t *testing.T) {
	opened := rsMustTime(t, "2026-09-05T09:00:00Z")
	recovered := rsMustTime(t, "2026-09-05T09:07:30Z")

	got, err := RenderDeliveryGapNotice(GapNoticeInput{
		GapID: "gap-1", OpenedAt: opened, RecoveredAt: recovered,
		AffectedSituationCount: 4, DelayedEffectCount: 11,
	})
	if err != nil {
		t.Fatalf("RenderDeliveryGapNotice() error = %v", err)
	}
	if got.Blocks != nil {
		t.Fatalf("RenderDeliveryGapNotice() Blocks = %v, want nil (plain text, matching PostSystemMessage)", got.Blocks)
	}
	for _, want := range []string{"4 Situation(s)", "11 delayed effect(s)", "<!date^", "7m30s"} {
		if !strings.Contains(got.Text, want) {
			t.Fatalf("gap notice text = %q, want to contain %q", got.Text, want)
		}
	}
}

func TestRenderDeliveryGapNoticeValidation(t *testing.T) {
	opened := rsMustTime(t, "2026-09-05T09:00:00Z")
	recovered := rsMustTime(t, "2026-09-05T09:07:30Z")
	valid := GapNoticeInput{GapID: "gap-1", OpenedAt: opened, RecoveredAt: recovered}

	cases := []struct {
		name   string
		mutate func(in GapNoticeInput) GapNoticeInput
	}{
		{"empty id", func(in GapNoticeInput) GapNoticeInput { in.GapID = ""; return in }},
		{"zero opened_at", func(in GapNoticeInput) GapNoticeInput { in.OpenedAt = time.Time{}; return in }},
		{"zero recovered_at", func(in GapNoticeInput) GapNoticeInput { in.RecoveredAt = time.Time{}; return in }},
		{"recovered before opened", func(in GapNoticeInput) GapNoticeInput { in.RecoveredAt = opened.Add(-time.Minute); return in }},
		{"negative affected count", func(in GapNoticeInput) GapNoticeInput { in.AffectedSituationCount = -1; return in }},
		{"negative delayed count", func(in GapNoticeInput) GapNoticeInput { in.DelayedEffectCount = -1; return in }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := RenderDeliveryGapNotice(c.mutate(valid)); err == nil {
				t.Fatalf("RenderDeliveryGapNotice(%s) error = nil, want an error", c.name)
			}
		})
	}
}
