// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func canonicalPublication(now time.Time, lifecycle model.Lifecycle, firing int, kinds ...model.CandidateKind) PublicationInput {
	sitID, trID := "canonical-situation", "canonical-transition"
	candidates := make([]model.MaterialCandidate, 0, len(kinds))
	for _, kind := range kinds {
		candidates = append(candidates, model.MaterialCandidate{Kind: kind})
	}
	tr := model.Transition{ID: trID, SituationID: sitID, Sequence: 1, Lifecycle: lifecycle,
		JournalKind: model.JournalEvidenceConclusion, Attention: model.AttentionUrgent, CreatedAt: now,
		Projection: model.ProjectionFacts{Briefing: &model.OperatorBriefing{
			Flow:   &model.OperatorFlow{FirstReceivedAt: now, CorrelationOpenedAt: now},
			Firing: firing, Total: 1, Work: model.WorkProjection{Phase: model.WorkPhaseCollecting},
		}, OperatorDelta: &model.OperatorDelta{Candidates: candidates}},
	}
	return PublicationInput{
		Situation: model.Situation{ID: sitID}, Transitions: []model.Transition{tr},
		Summary:    model.EpisodeSummary{SituationID: sitID, Version: 1, SourceTransitionSequence: 1},
		SlackFloor: model.InterruptionLow, Now: now,
	}
}

func TestCanonicalDelayedInitialPublicationSkipsStaleCorrelation(t *testing.T) {
	in := canonicalPublication(time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC), model.LifecycleRecoveryPending, 0,
		model.CandidateUsefulFinding, model.CandidateAllClear)
	in.Transitions[0].Projection.Briefing.Work.Phase = model.WorkPhaseSettled
	got := replyKinds(hsPlan(t, in))
	want := []model.NotificationReplyKind{model.ReplyAnalysisCompleted, model.ReplyRecoveryObserved}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("delayed initial reply kinds = %v, want current developments %v", got, want)
	}
}

func replyKinds(intents []model.NotificationIntent) []model.NotificationReplyKind {
	var out []model.NotificationReplyKind
	for _, in := range intents {
		if in.EffectClass == model.EffectThreadAppend || in.EffectClass == model.EffectBroadcastHandoff {
			out = append(out, in.ReplyKind)
		}
	}
	return out
}

func TestCanonicalInitialPublicationIncludesCorrelationReply(t *testing.T) {
	in := canonicalPublication(time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC), model.LifecycleActive, 1)
	got := hsPlan(t, in)
	kinds := replyKinds(got)
	if len(kinds) != 1 || kinds[0] != model.ReplyCorrelationStarted {
		t.Fatalf("initial canonical reply kinds = %v, want [correlation_started]", kinds)
	}
}

func TestCanonicalAnalysisAndRecoveryAreSeparateOrderedReplies(t *testing.T) {
	in := canonicalPublication(time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC), model.LifecycleRecoveryPending, 0,
		model.CandidateUsefulFinding, model.CandidateAllClear)
	in.RootPublished = true
	completed := in.Now.Add(20 * time.Second)
	in.Transitions[0].Projection.Briefing.Flow.InvestigationCompletedAt = &completed
	planned := hsPlan(t, in)
	got := replyKinds(planned)
	want := []model.NotificationReplyKind{model.ReplyAnalysisCompleted, model.ReplyRecoveryObserved}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("canonical reply kinds = %v, want %v", got, want)
	}
	if got[0] == got[1] {
		t.Fatal("analysis and recovery collapsed into one delivery obligation")
	}
	replayed := hsPlan(t, in)
	firstReplies, secondReplies := hsReplyIntents(planned), hsReplyIntents(replayed)
	if firstReplies[0].ID != secondReplies[0].ID || firstReplies[1].ID != secondReplies[1].ID {
		t.Fatalf("replay changed split reply identities: first=%v second=%v", firstReplies, secondReplies)
	}
	if firstReplies[0].ID == firstReplies[1].ID || firstReplies[0].ClientMessageID == firstReplies[1].ClientMessageID {
		t.Fatal("split replies share an idempotency identity")
	}
}

func TestCanonicalRecoveryDoesNotWaitForUnfinishedAnalysis(t *testing.T) {
	in := canonicalPublication(time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC), model.LifecycleRecoveryPending, 0,
		model.CandidateAllClear)
	in.RootPublished = true
	got := replyKinds(hsPlan(t, in))
	if len(got) != 1 || got[0] != model.ReplyRecoveryObserved {
		t.Fatalf("canonical recovery reply kinds = %v, want [recovery_observed]", got)
	}
}

func TestCanonicalInvestigationReplyRequiresActualExecution(t *testing.T) {
	now := time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC)
	in := canonicalPublication(now, model.LifecycleActive, 1, model.CandidateFirstExecutionAssurance)
	in.RootPublished = true
	if got := replyKinds(hsPlan(t, in)); len(got) != 0 {
		t.Fatalf("execution assurance without a recorded start produced replies %v", got)
	}
	started := now.Add(30 * time.Second)
	in.Transitions[0].Projection.Briefing.Flow.InvestigationStartedAt = &started
	got := replyKinds(hsPlan(t, in))
	if len(got) != 1 || got[0] != model.ReplyInvestigationStarted {
		t.Fatalf("actual execution reply kinds = %v, want [investigation_started]", got)
	}
}

func TestCanonicalCompletionSuppressesSameTransitionStartAssurance(t *testing.T) {
	now := time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC)
	in := canonicalPublication(now, model.LifecycleRecovered, 0,
		model.CandidateFirstExecutionAssurance, model.CandidateUsefulFinding,
		model.CandidateAllClear, model.CandidateTerminalEnd)
	in.RootPublished = true
	started := now.Add(-20 * time.Second)
	in.Transitions[0].Projection.Briefing.Flow.InvestigationStartedAt = &started
	in.Transitions[0].Projection.Briefing.Work.Phase = model.WorkPhaseSettled
	got := replyKinds(hsPlan(t, in))
	want := []model.NotificationReplyKind{
		model.ReplyAnalysisCompleted, model.ReplyRecoveryObserved, model.ReplyRecovered,
	}
	if len(got) != len(want) {
		t.Fatalf("same-transition completed reply kinds = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("same-transition completed reply kinds = %v, want %v", got, want)
		}
	}
}
