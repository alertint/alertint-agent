// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// B5 round-2 repair regressions (lead review 2026-09-09, R1).
//
// ReplyEligible decided WHICH facts the operator is owed. Rendering the
// whole Transition anyway delivers the rejected ones beside the accepted
// one — an uncommunicated obstacle's "clearance" and a request that was
// never made. The selection must control the outbound payload on both
// reply classes, and a rejected candidate must not come back through B4's
// legacy-boolean fallback either.
// ----------------------------------------------------------------------

// dsSelectionTransition is one briefing-bearing Transition carrying an
// eligible finding beside two candidates delivered history rejects: a
// clearance for an obstacle never communicated, and a withdrawal of a
// request never made.
func dsSelectionTransition(t *testing.T, now time.Time) model.Transition {
	t.Helper()
	tr := sdTransition(2, model.LifecycleActive, sdRunningTriageContract(now.Add(time.Minute)),
		model.ReasonMaterialAssessmentChanged, model.JournalEvidenceConclusion,
		model.JournalData{Headline: "New finding", OccurredAt: now},
		model.ProjectionFacts{EffectiveStartedAt: now, EffectiveStartedAtBasis: model.SourceTimeBasisSourcePayload}, now)
	action := model.OperatorActionInvestigateSituation
	tr.Projection.Briefing = &model.OperatorBriefing{Scope: "checkout", Firing: 1, Total: 1,
		Work: model.WorkProjection{ExecutionStarted: true}}
	tr.Projection.OperatorDelta = &model.OperatorDelta{Candidates: []model.MaterialCandidate{
		{Kind: model.CandidateUsefulFinding, Finding: &model.FindingFacts{IncidentID: "i",
			Hypothesis: "Deployment broke checkout", Observations: []string{"Errors began after deploy"}}},
		{Kind: model.CandidateAbilityChanged, Limitation: &model.LimitationFacts{
			Code: model.LimitationInvestigationUnavailable, Cleared: true}},
		{Kind: model.CandidateActionChanged, Action: &model.ActionFacts{Action: action, Withdrawn: true}},
	}}
	return tr
}

// dsAssertSelected checks both rendered surfaces of the single outbound
// operation: the eligible finding survives, the rejected pair does not.
func dsAssertSelected(t *testing.T, api *fakeSlackAPI) {
	t.Helper()
	if len(api.posts) != 1 {
		t.Fatalf("want exactly one outbound PostMessage, got %d", len(api.posts))
	}
	post := api.posts[0]
	for surface, text := range map[string]string{"fallback": post.Text, "blocks": sdBlocksText(t, post.Blocks)} {
		t.Logf("%s:\n%s", surface, text)
		if !strings.Contains(text, "Errors began after deploy") {
			t.Errorf("%s dropped the eligible finding", surface)
		}
		if strings.Contains(text, "unavailable") || strings.Contains(strings.ToLower(text), "no longer needed") {
			t.Errorf("%s delivered a rejected candidate beside the eligible finding", surface)
		}
	}
}

// R1/1: the quiet thread reply carries only the selected candidates.
func TestSituationDelivererThreadAppendRendersOnlySelectedCandidates(t *testing.T) {
	now := sdMustTime(t, "2026-09-09T10:00:00Z")
	tr := dsSelectionTransition(t, now)
	if got := situation.ReplyEligible(tr.Projection.OperatorDelta.Candidates, situation.DeliveredHistory{}, true); len(got) != 1 {
		t.Fatalf("fixture: exactly the finding must be eligible, got %+v", got)
	}
	fs := &fakeDelivererStore{transitions: map[string]model.Transition{tr.ID: tr},
		rootOK: true, rootChannel: "C", rootTS: "100.1"}
	api := &fakeSlackAPI{}
	d := NewSituationDeliverer(fs, api, "C", func() time.Time { return now })
	if _, err := d.Deliver(context.Background(), sdThreadIntent(model.EffectThreadAppend, tr.ID, tr.Sequence, now)); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	dsAssertSelected(t, api)
}

// R1/2: the broadcast class renders the same selection — one rule, both
// delivery classes.
func TestSituationDelivererBroadcastRendersOnlySelectedCandidates(t *testing.T) {
	now := sdMustTime(t, "2026-09-09T10:00:00Z")
	tr := dsSelectionTransition(t, now)
	fs := &fakeDelivererStore{transitions: map[string]model.Transition{tr.ID: tr},
		rootOK: true, rootChannel: "C", rootTS: "100.1"}
	api := &fakeSlackAPI{}
	d := NewSituationDeliverer(fs, api, "C", func() time.Time { return now })
	if _, err := d.Deliver(context.Background(), sdThreadIntent(model.EffectBroadcastHandoff, tr.ID, tr.Sequence, now)); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	dsAssertSelected(t, api)
}

// R1/3: a rejected candidate must not reappear through B4's legacy-boolean
// fallback. B4 falls back to AbilityLost/HumanRequestChanged only when no
// candidate of that kind rode the delta — so removing the rejected
// candidate must remove its legacy twin with it, never resurrect it.
func TestSituationDelivererRejectedCandidateDoesNotFallBackToALegacyFlag(t *testing.T) {
	now := sdMustTime(t, "2026-09-09T10:00:00Z")
	tr := dsSelectionTransition(t, now)
	tr.Projection.OperatorDelta.AbilityLost = true
	tr.Projection.OperatorDelta.HumanRequestChanged = true
	fs := &fakeDelivererStore{transitions: map[string]model.Transition{tr.ID: tr},
		rootOK: true, rootChannel: "C", rootTS: "100.1"}
	api := &fakeSlackAPI{}
	d := NewSituationDeliverer(fs, api, "C", func() time.Time { return now })
	if _, err := d.Deliver(context.Background(), sdThreadIntent(model.EffectThreadAppend, tr.ID, tr.Sequence, now)); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if len(api.posts) != 1 {
		t.Fatalf("want exactly one outbound PostMessage, got %d", len(api.posts))
	}
	post := api.posts[0]
	for surface, text := range map[string]string{"fallback": post.Text, "blocks": sdBlocksText(t, post.Blocks)} {
		t.Logf("%s:\n%s", surface, text)
		if !strings.Contains(text, "Errors began after deploy") {
			t.Errorf("%s dropped the eligible finding", surface)
		}
		if strings.Contains(text, "Automatic work cannot proceed") || strings.Contains(text, "Analysis unavailable") {
			t.Errorf("%s resurrected the rejected limitation through the legacy AbilityLost fallback", surface)
		}
		if strings.Contains(text, "Human action request changed") {
			t.Errorf("%s resurrected the rejected action through the legacy HumanRequestChanged fallback", surface)
		}
	}
}

// R1/4: an accepted candidate the operator has NOT been told about still
// renders — the selection narrows, it never suppresses an owed fact.
func TestSituationDelivererKeepsACommunicatedObstaclesClearance(t *testing.T) {
	now := sdMustTime(t, "2026-09-09T10:00:00Z")
	tr := dsSelectionTransition(t, now)
	fs := &fakeDelivererStore{transitions: map[string]model.Transition{tr.ID: tr},
		rootOK: true, rootChannel: "C", rootTS: "100.1",
		history: situation.DeliveredHistory{
			CommunicatedLimitationCodes: []string{model.LimitationInvestigationUnavailable}}}
	api := &fakeSlackAPI{}
	d := NewSituationDeliverer(fs, api, "C", func() time.Time { return now })
	if _, err := d.Deliver(context.Background(), sdThreadIntent(model.EffectThreadAppend, tr.ID, tr.Sequence, now)); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	text := api.posts[0].Text + "\n" + sdBlocksText(t, api.posts[0].Blocks)
	if !strings.Contains(text, "no longer recorded") {
		t.Fatalf("a communicated obstacle's clearance must still be delivered:\n%s", text)
	}
}

// R5, outbound: an obstacle queued during a delivery gap and the clearance
// planned while it waited must both reach Slack, in order, and the second
// must actually correct the first. The history this fake returns is folded
// from what the deliverer ALREADY posted, so the assertion is about the
// real rendered sequence, not a hand-set flag.
type dsOrderedStore struct {
	*fakeDelivererStore

	communicated []string
}

func (s *dsOrderedStore) GetCommunicatedHistory(_ context.Context, _ string, before int) (situation.DeliveredHistory, error) {
	_ = before
	return situation.DeliveredHistory{CommunicatedLimitationCodes: append([]string(nil), s.communicated...)}, nil
}

func TestSituationDelivererDelayedObstacleIsFollowedByItsCorrection(t *testing.T) {
	now := sdMustTime(t, "2026-09-09T10:00:00Z")
	obstacle := sdTransition(2, model.LifecycleActive, sdRunningTriageContract(now.Add(time.Minute)),
		model.ReasonMaterialAssessmentChanged, model.JournalOperatorContractChanged,
		model.JournalData{Headline: "Coverage limited", OccurredAt: now},
		model.ProjectionFacts{EffectiveStartedAt: now, EffectiveStartedAtBasis: model.SourceTimeBasisSourcePayload}, now)
	obstacle.Projection.Briefing = &model.OperatorBriefing{Scope: "checkout", Firing: 1, Total: 1}
	obstacle.Projection.OperatorDelta = &model.OperatorDelta{Candidates: []model.MaterialCandidate{
		{Kind: model.CandidateAbilityChanged, Limitation: &model.LimitationFacts{
			Code: model.LimitationInvestigationUnavailable}}}}

	clearance := obstacle
	clearance.ID, clearance.Sequence = "transition-003", 3
	clearance.Projection.OperatorDelta = &model.OperatorDelta{Candidates: []model.MaterialCandidate{
		{Kind: model.CandidateAbilityChanged, Limitation: &model.LimitationFacts{
			Code: model.LimitationInvestigationUnavailable, Cleared: true}}}}

	fs := &dsOrderedStore{fakeDelivererStore: &fakeDelivererStore{
		transitions: map[string]model.Transition{obstacle.ID: obstacle, clearance.ID: clearance},
		rootOK:      true, rootChannel: "C", rootTS: "100.1"}}
	api := &fakeSlackAPI{}
	d := NewSituationDeliverer(fs, api, "C", func() time.Time { return now })

	for _, tr := range []model.Transition{obstacle, clearance} {
		if _, err := d.Deliver(context.Background(), sdThreadIntent(model.EffectThreadAppend, tr.ID, tr.Sequence, now)); err != nil {
			t.Fatalf("Deliver %s: %v", tr.ID, err)
		}
		// Fold what actually went out, exactly as the store fold does.
		for _, c := range tr.Projection.OperatorDelta.Candidates {
			if c.Limitation != nil && !c.Limitation.Cleared {
				fs.communicated = append(fs.communicated, c.Limitation.Code)
			}
		}
	}
	if len(api.posts) != 2 {
		t.Fatalf("want the obstacle and its correction, got %d posts", len(api.posts))
	}
	first, second := api.posts[0].Text, api.posts[1].Text
	t.Logf("first:\n%s\nsecond:\n%s", first, second)
	if !strings.Contains(first, "unavailable analysis") {
		t.Errorf("the delayed obstacle lost its limitation: %s", first)
	}
	if !strings.Contains(second, "no longer recorded") {
		t.Errorf("the obstacle was published with nothing to correct it: %s", second)
	}
}
