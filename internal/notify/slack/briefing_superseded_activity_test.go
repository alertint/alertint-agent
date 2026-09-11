// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
	slacklib "github.com/slack-go/slack"
)

// ----------------------------------------------------------------------
// B5 round-5 renderer regressions (lead review round 4, 2026-09-10, R1).
//
// Suppressing the start assurance from the delta is only half the fact:
// the reply's own *AlertINT:* line reconstructs the SAME execution from
// this Transition's recorded contract and republishes its checkpoint, so
// the operator still reads a stale "Investigating …" after the work it
// describes has been overtaken (canonical slide 4 "Keep the attention cost
// bounded": "Never replay stale start messages after completion or
// closure"; slide 5 15:10:33: "Show the actual current contract and
// checkpoint"; "recovery-interrupted": "Use Investigating only if actual
// aggregate work supports it").
//
// The correction states what it knows and nothing else: no invented
// activity, no invented timing, and no completion, Monitoring or terminal
// claim inferred from a supersession boolean.
// ----------------------------------------------------------------------

// bsaMixedStart is the retained mixed row as the renderer actually receives
// it after selection: the material scope change survives, the start
// assurance candidate has already been dropped, and this Transition's own
// running-triage contract and checkpoint are still recorded on it.
func bsaMixedStart(t *testing.T) (model.Transition, time.Time) {
	t.Helper()
	now := rsMustTime(t, "2026-09-09T10:00:00Z")
	next := now.Add(time.Minute)
	tr := rsTransition(2, model.LifecycleActive, model.AttentionUrgent, rsRunningTriageContract(next),
		model.ReasonInvestigationStarted, model.JournalInvestigationStarted,
		model.JournalData{Headline: "Investigation started", OccurredAt: now},
		rsProjection(now.Add(-time.Hour), nil), now)
	tr.Projection.Briefing = &model.OperatorBriefing{Scope: "checkout + payments", Firing: 1, Total: 1,
		Work: model.WorkProjection{ExecutionStarted: true, Phase: model.WorkPhaseExecuting,
			InvestigatedAlertIDs: []string{"a"}, InvestigatedNames: []string{"AlertA"},
			InvestigatedCount: 1, InvestigatedCountKnown: true}}
	tr.Projection.OperatorDelta = &model.OperatorDelta{Candidates: []model.MaterialCandidate{
		{Kind: model.CandidateMembersChanged, Members: &model.MemberFacts{FiringCount: 1, Total: 1,
			PreviousScope: "checkout", Scope: "checkout + payments"}},
	}}
	return tr, next
}

// bsaMonitorContract records source monitoring rather than an
// investigation in flight.
func bsaMonitorContract(next time.Time) model.ActionContract {
	action := model.AlertINTActionMonitorSituation
	status := model.AlertINTStatusRunning
	return model.ActionContract{
		NextActor:      model.NextActorAlertINT,
		AlertINTAction: &action,
		AlertINTStatus: &status,
		NextUpdateAt:   rsTimePtr(next),
		NextUpdateOn:   []model.NextUpdateOn{model.NextUpdateOnSourceResolution},
	}
}

// bsaSurfaces renders one reply and returns both operator-visible surfaces.
func bsaSurfaces(t *testing.T, in SituationReplyInput) map[string]string {
	t.Helper()
	msg, err := RenderSituationReply(in)
	if err != nil {
		t.Fatalf("RenderSituationReply: %v", err)
	}
	return map[string]string{"fallback": msg.Text, "blocks": rsFallbackBlocksText(msg)}
}

// R1/1: the superseded execution and its checkpoint leave the reply, and
// every material fact the row carries stays.
func TestReplySupersededExecutionDropsTheStaleActivityAndCheckpoint(t *testing.T) {
	tr, next := bsaMixedStart(t)
	stale := SlackDateToken(next, "{time}")
	for surface, text := range bsaSurfaces(t, SituationReplyInput{Transition: tr, ExecutionSuperseded: true}) {
		t.Logf("%s:\n%s", surface, text)
		if !strings.Contains(text, "Affected scope changed from") {
			t.Errorf("%s lost the retained row's material scope change", surface)
		}
		if strings.Contains(text, "*Action:*") {
			t.Errorf("%s invented an operator action line", surface)
		}
		if strings.Contains(text, "*AlertINT:* Investigating") {
			t.Errorf("%s still presents the superseded execution as current activity", surface)
		}
		if strings.Contains(text, stale) || strings.Contains(text, "Next status check") {
			t.Errorf("%s still republishes the superseded checkpoint", surface)
		}
		if !strings.Contains(text, "superseded") {
			t.Errorf("%s dropped the activity line without saying why", surface)
		}
	}
}

// R1/2: nothing may be invented in its place. A supersession boolean is not
// evidence that work finished, that the Situation is monitoring, or that a
// new time was promised.
func TestReplySupersededExecutionInventsNoReplacementStateOrTiming(t *testing.T) {
	tr, _ := bsaMixedStart(t)
	for surface, text := range bsaSurfaces(t, SituationReplyInput{Transition: tr, ExecutionSuperseded: true}) {
		for _, bad := range []string{"Monitoring", "Watching", "work is complete", "Recovery confirmed",
			"tracking for this Situation has ended", "Next update by", "retry"} {
			if strings.Contains(text, bad) {
				t.Errorf("%s invented %q in place of the superseded activity: %s", surface, bad, text)
			}
		}
	}
}

// R1/3: a finding can coexist with work that is still running, so the reply
// must not read the supersession as an aggregate-work claim in EITHER
// direction — it neither ends the running work nor restates this row's own
// stale running-work sentence as current.
func TestReplySupersededExecutionMakesNoAggregateWorkClaim(t *testing.T) {
	tr, _ := bsaMixedStart(t)
	tr.Projection.Briefing.Work.RemainingIncidents = 2
	for surface, text := range bsaSurfaces(t, SituationReplyInput{Transition: tr, ExecutionSuperseded: true}) {
		for _, bad := range []string{"still running", "still outstanding", "have outstanding work", "no automatic retry"} {
			if strings.Contains(text, bad) {
				t.Errorf("%s claimed aggregate work state %q from stale recorded facts: %s", surface, bad, text)
			}
		}
	}
}

// R1/4, positive control: nothing overtook this row, so its recorded
// activity and checkpoint are delivered exactly as before.
func TestReplyActivityStandsWhenNothingSupersededIt(t *testing.T) {
	tr, next := bsaMixedStart(t)
	stale := SlackDateToken(next, "{time}")
	for surface, text := range bsaSurfaces(t, SituationReplyInput{Transition: tr}) {
		if !strings.Contains(text, "*AlertINT:* Investigating") {
			t.Errorf("%s suppressed activity nothing had superseded: %s", surface, text)
		}
		if !strings.Contains(text, stale) {
			t.Errorf("%s dropped a checkpoint that is still this reply's own: %s", surface, text)
		}
		if strings.Contains(text, "superseded") {
			t.Errorf("%s announced a supersession that did not happen: %s", surface, text)
		}
	}
}

// R1/5, bound: the correction removes a stale EXECUTION claim, not every
// activity line. A reply whose own recorded contract claims no investigation
// in flight is truthful whatever the earlier execution did, and keeps its
// line and its checkpoint.
func TestReplyNonExecutionActivitySurvivesASupersededExecution(t *testing.T) {
	tr, _ := bsaMixedStart(t)
	next := rsMustTime(t, "2026-09-09T10:05:00Z")
	tr.ActionContract = bsaMonitorContract(next)
	live := SlackDateToken(next, "{time}")
	for surface, text := range bsaSurfaces(t, SituationReplyInput{Transition: tr, ExecutionSuperseded: true}) {
		if !strings.Contains(text, "*AlertINT:* Monitoring alert changes.") {
			t.Errorf("%s suppressed a monitoring line the overtaken execution does not govern: %s", surface, text)
		}
		if !strings.Contains(text, live) {
			t.Errorf("%s dropped a checkpoint that is this reply's own: %s", surface, text)
		}
	}
}

// R1/6, bound: a terminal reply states the end of monitoring from its own
// lifecycle, never from a supersession boolean, and keeps saying so.
//
// The second shape reaches the lifecycle guard on its own: a terminal row
// whose contract still records the triage as running is a valid Transition
// (only its checkpoint must be gone), and its rendered line is the recorded
// terminal outcome. Replacing that with the supersession sentence would
// withdraw the one fact the operator most needs.
func TestReplyTerminalActivitySurvivesASupersededExecution(t *testing.T) {
	cleared, _ := bsaMixedStart(t)
	cleared.Lifecycle = model.LifecycleRecovered
	cleared.ActionContract = model.ActionContract{NextActor: model.NextActorNone}
	cleared.JournalKind = model.JournalRecovered

	staleContract, _ := bsaMixedStart(t)
	staleContract.Lifecycle = model.LifecycleRecovered
	staleContract.JournalKind = model.JournalRecovered
	action := model.AlertINTActionRunAcuteTriage
	status := model.AlertINTStatusRunning
	staleContract.ActionContract = model.ActionContract{NextActor: model.NextActorAlertINT,
		AlertINTAction: &action, AlertINTStatus: &status}

	for name, tr := range map[string]model.Transition{
		"cleared contract": cleared, "stale running contract": staleContract,
	} {
		t.Run(name, func(t *testing.T) {
			if err := tr.Validate(); err != nil {
				t.Fatalf("fixture: %v", err)
			}
			for surface, text := range bsaSurfaces(t, SituationReplyInput{Transition: tr, ExecutionSuperseded: true}) {
				if !strings.Contains(text, "monitoring for this episode has ended") {
					t.Errorf("%s lost the terminal reply's own recorded end: %s", surface, text)
				}
				if strings.Contains(text, "superseded") {
					t.Errorf("%s withdrew a terminal outcome on a supersession boolean: %s", surface, text)
				}
			}
		})
	}
}

// R1/7: the reply renderer is the journal renderer plus one delivery-time
// presentation fact. With that fact absent the two must stay identical, so
// the second entry point can never drift into a second rendering.
func TestRenderSituationReplyMatchesTheJournalRendererWithoutThePresentationFact(t *testing.T) {
	mixed, _ := bsaMixedStart(t)
	recovered, _ := bsaMixedStart(t)
	recovered.Lifecycle = model.LifecycleRecovered
	recovered.ActionContract = model.ActionContract{NextActor: model.NextActorNone}
	recovered.JournalKind = model.JournalRecovered
	note, _ := bsaMixedStart(t)
	note.Reason = model.ReasonOperatorArtifactRecorded
	note.JournalKind = model.JournalOperatorNote
	note.Journal.AttributedActor = "operator@example.com"
	note.Journal.Detail = "Rollback under review"
	id := "annotation-input"
	note.OperatorArtifactInputID = &id
	plain, _ := bsaMixedStart(t)
	plain.Projection.Briefing = nil
	plain.Projection.OperatorDelta = nil

	for name, tr := range map[string]model.Transition{
		"mixed": mixed, "recovered": recovered, "note": note, "plain": plain,
	} {
		t.Run(name, func(t *testing.T) {
			want, wantErr := RenderSituationJournal(tr)
			got, gotErr := RenderSituationReply(SituationReplyInput{Transition: tr})
			if (wantErr == nil) != (gotErr == nil) {
				t.Fatalf("error disagreement: journal %v, reply %v", wantErr, gotErr)
			}
			if !reflect.DeepEqual(want, got) {
				t.Fatalf("reply renderer drifted from the journal renderer:\njournal %#v\nreply   %#v", want, got)
			}
		})
	}
}

// R1/8: the correction is one sentence. Everything else the journal
// renderer produces — headline, block shape, every other line, the
// staleness markers and the recorded instant — must come through
// unchanged, so the second entry point cannot quietly become a second
// rendering of the same reply.
func TestRenderSituationReplyChangesOnlyTheActivitySentence(t *testing.T) {
	tr, _ := bsaMixedStart(t)
	tr.Journal.Delayed = true
	tr.Journal.NoLongerCurrent = true

	base, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatalf("RenderSituationJournal: %v", err)
	}
	corrected, err := RenderSituationReply(SituationReplyInput{Transition: tr, ExecutionSuperseded: true})
	if err != nil {
		t.Fatalf("RenderSituationReply: %v", err)
	}
	if len(base.Blocks) != len(corrected.Blocks) {
		t.Fatalf("block count changed: journal %d, reply %d", len(base.Blocks), len(corrected.Blocks))
	}
	for i := range base.Blocks {
		if reflect.TypeOf(base.Blocks[i]) != reflect.TypeOf(corrected.Blocks[i]) {
			t.Fatalf("block %d changed type: %T vs %T", i, base.Blocks[i], corrected.Blocks[i])
		}
	}
	changed := 0
	for i, want := range bsaBlockTexts(base) {
		got := bsaBlockTexts(corrected)[i]
		if want == got {
			continue
		}
		changed++
		if !strings.HasPrefix(want, "*AlertINT:*") || !strings.HasPrefix(got, "*AlertINT:*") {
			t.Fatalf("block %d changed outside the activity sentence:\njournal %q\nreply   %q", i, want, got)
		}
	}
	if changed != 1 {
		t.Fatalf("expected exactly one changed block, got %d", changed)
	}
	// The fallback surface changes by exactly the same substitution.
	if want, got := strings.Count(base.Text, "\n"), strings.Count(corrected.Text, "\n"); want != got {
		t.Fatalf("fallback line count changed: journal %d, reply %d", want, got)
	}
}

// bsaBlockTexts returns each block's text in order.
func bsaBlockTexts(msg RenderedMessage) []string {
	out := make([]string, 0, len(msg.Blocks))
	for _, blk := range msg.Blocks {
		switch v := blk.(type) {
		case *slacklib.SectionBlock:
			if v.Text != nil {
				out = append(out, v.Text.Text)
				continue
			}
			out = append(out, "")
		case *slacklib.ContextBlock:
			var parts []string
			for _, el := range v.ContextElements.Elements {
				if txt, ok := el.(*slacklib.TextBlockObject); ok {
					parts = append(parts, txt.Text)
				}
			}
			out = append(out, strings.Join(parts, " "))
		default:
			out = append(out, "")
		}
	}
	return out
}

// R1/9, bound: a schedule that has already reported its own end or its own
// obstacle is not an in-flight execution claim. Those sentences are the
// honest record and stay, checkpoint included.
func TestReplyEndedOrBlockedWorkSurvivesASupersededExecution(t *testing.T) {
	for name, status := range map[string]model.AlertINTStatus{
		"exhausted": model.AlertINTStatusExhausted,
		"blocked":   model.AlertINTStatusBlocked,
		"complete":  model.AlertINTStatusComplete,
	} {
		t.Run(name, func(t *testing.T) {
			tr, next := bsaMixedStart(t)
			s := status
			tr.ActionContract.AlertINTStatus = &s
			live := SlackDateToken(next, "{time}")
			for surface, text := range bsaSurfaces(t, SituationReplyInput{Transition: tr, ExecutionSuperseded: true}) {
				if strings.Contains(text, "superseded") {
					t.Errorf("%s suppressed a recorded end or obstacle the finding does not govern: %s", surface, text)
				}
				if !strings.Contains(text, live) {
					t.Errorf("%s dropped a checkpoint that is this reply's own: %s", surface, text)
				}
			}
		})
	}
}

// R1/10: a reply that carries no briefing has no activity sentence to
// correct, and the presentation fact must not reach a renderer with
// nothing to render from.
func TestReplyWithoutABriefingIsUntouchedByASupersededExecution(t *testing.T) {
	tr, _ := bsaMixedStart(t)
	tr.Projection.Briefing = nil
	tr.Projection.OperatorDelta = nil
	tr.Journal.Detail = "Investigation started for checkout"

	want, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatalf("RenderSituationJournal: %v", err)
	}
	got, err := RenderSituationReply(SituationReplyInput{Transition: tr, ExecutionSuperseded: true})
	if err != nil {
		t.Fatalf("RenderSituationReply: %v", err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("a briefing-less reply was rewritten:\njournal %#v\nreply   %#v", want, got)
	}
}
