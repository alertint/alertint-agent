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
// B5 round-4 repair regressions (lead review round 3, 2026-09-09, R1),
// on the outbound payload itself.
//
// The retained mixed row keeps its material scope change and loses the
// start assurance the work has moved past. Selection alone is not the
// deliverable: both rendered surfaces of both reply classes are checked.
// ----------------------------------------------------------------------

// ds4MixedStart is one reply row carrying the transient start assurance
// beside a material scope change — the row §5.3 must not supersede whole.
func ds4MixedStart(now time.Time) model.Transition {
	tr := sdTransition(2, model.LifecycleActive, sdRunningTriageContract(now.Add(time.Minute)),
		model.ReasonInvestigationStarted, model.JournalInvestigationStarted,
		model.JournalData{Headline: "Investigation started", OccurredAt: now},
		model.ProjectionFacts{EffectiveStartedAt: now, EffectiveStartedAtBasis: model.SourceTimeBasisSourcePayload}, now)
	tr.Projection.Briefing = &model.OperatorBriefing{Scope: "checkout + payments", Firing: 1, Total: 1,
		Work: model.WorkProjection{ExecutionStarted: true, Phase: model.WorkPhaseExecuting,
			InvestigatedAlertIDs: []string{"a"}, InvestigatedNames: []string{"AlertA"},
			InvestigatedCount: 1, InvestigatedCountKnown: true}}
	tr.Projection.OperatorDelta = &model.OperatorDelta{Candidates: []model.MaterialCandidate{
		{Kind: model.CandidateFirstExecutionAssurance,
			Members: &model.MemberFacts{FiringCount: 1, Total: 1, CountKnown: true}},
		{Kind: model.CandidateMembersChanged, Members: &model.MemberFacts{FiringCount: 1, Total: 1,
			PreviousScope: "checkout", Scope: "checkout + payments"}},
	}}
	return tr
}

// ds4AssuranceStated reports whether the assurance's own sentence is on the
// operator's screen.
//
// It is checked as a standalone line, because the reply's *AlertINT:*
// status line opens with the same verb: that line is this Transition's own
// recorded status and next update, which every reply carries and which no
// candidate selection governs. Only the delta's assurance line is the fact
// this repair suppresses.
func ds4AssuranceStated(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "*AlertINT:*") {
			continue
		}
		if strings.HasPrefix(line, "Investigating") {
			return true
		}
	}
	return false
}

// ds4Deliver posts one reply of the given class and returns both rendered
// surfaces joined.
func ds4Deliver(t *testing.T, class model.EffectClass, tr model.Transition,
	history situation.DeliveredHistory, now time.Time) (string, string) {
	t.Helper()
	fs := &fakeDelivererStore{transitions: map[string]model.Transition{tr.ID: tr},
		rootOK: true, rootChannel: "C", rootTS: "100.1", history: history}
	api := &fakeSlackAPI{}
	d := NewSituationDeliverer(fs, api, "C", func() time.Time { return now })
	if _, err := d.Deliver(context.Background(), sdThreadIntent(class, tr.ID, tr.Sequence, now)); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if len(api.posts) != 1 {
		t.Fatalf("want exactly one outbound PostMessage, got %d", len(api.posts))
	}
	return api.posts[0].Text, sdBlocksText(t, api.posts[0].Blocks)
}

// R1/1: the thread reply keeps the scope change and drops the overtaken
// assurance, on the fallback text and in the Block Kit body.
func TestSituationDelivererMixedRowOmitsTheOvertakenAssurance(t *testing.T) {
	now := sdMustTime(t, "2026-09-09T10:00:00Z")
	fallback, blocks := ds4Deliver(t, model.EffectThreadAppend, ds4MixedStart(now),
		situation.DeliveredHistory{AssuranceSuperseded: true}, now)
	for surface, text := range map[string]string{"fallback": fallback, "blocks": blocks} {
		t.Logf("%s:\n%s", surface, text)
		if !strings.Contains(text, "Affected scope changed from") {
			t.Errorf("%s lost the retained row's material scope change", surface)
		}
		if ds4AssuranceStated(text) {
			t.Errorf("%s published a start assurance the work had already moved past", surface)
		}
	}
}

// R1/2: the same rule on the broadcast class — one selection, both reply
// classes.
func TestSituationDelivererBroadcastMixedRowOmitsTheOvertakenAssurance(t *testing.T) {
	now := sdMustTime(t, "2026-09-09T10:00:00Z")
	fallback, blocks := ds4Deliver(t, model.EffectBroadcastHandoff, ds4MixedStart(now),
		situation.DeliveredHistory{AssuranceSuperseded: true}, now)
	for surface, text := range map[string]string{"fallback": fallback, "blocks": blocks} {
		t.Logf("%s:\n%s", surface, text)
		if !strings.Contains(text, "Affected scope changed from") {
			t.Errorf("%s lost the retained row's material scope change", surface)
		}
		if ds4AssuranceStated(text) {
			t.Errorf("%s published a start assurance the work had already moved past", surface)
		}
	}
}

// R1/3, positive control: nothing has overtaken it, so the assurance is
// delivered exactly as before beside the scope change.
func TestSituationDelivererMixedRowKeepsAnAssuranceNothingOvertook(t *testing.T) {
	now := sdMustTime(t, "2026-09-09T10:00:00Z")
	fallback, blocks := ds4Deliver(t, model.EffectThreadAppend, ds4MixedStart(now),
		situation.DeliveredHistory{}, now)
	for surface, text := range map[string]string{"fallback": fallback, "blocks": blocks} {
		t.Logf("%s:\n%s", surface, text)
		if !ds4AssuranceStated(text) {
			t.Errorf("%s suppressed a start assurance nothing had overtaken", surface)
		}
		if !strings.Contains(text, "Affected scope changed from") {
			t.Errorf("%s lost the row's material scope change", surface)
		}
	}
}
