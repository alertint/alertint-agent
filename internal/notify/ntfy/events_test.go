// SPDX-License-Identifier: FSL-1.1-ALv2

package ntfy

import (
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestSelectionCombinesMaterialCategories(t *testing.T) {
	prior := model.Transition{Attention: model.AttentionObserve, Lifecycle: model.LifecycleActive}
	action := model.OperatorAction("check_dependency")
	tr := model.Transition{ID: "tr-2", SituationID: "S-104", Attention: model.AttentionUrgent, Lifecycle: model.LifecycleActive,
		ActionContract: model.ActionContract{OperatorActionRequired: &action},
		Projection:     model.ProjectionFacts{OperatorDelta: &model.OperatorDelta{AttentionIncreased: true, HumanRequestChanged: true}}}
	got := Select(tr, &prior, true, Defaults())
	if !reflect.DeepEqual(got, []string{"priority_escalated", "operator_action_required"}) {
		t.Fatalf("events = %v", got)
	}
	if got := Select(tr, &prior, false, []string{}); len(got) != 0 {
		t.Fatalf("empty selection: %v", got)
	}
	tr.Projection.OperatorDelta = nil
	prior = tr
	if got := Select(tr, &prior, true, Defaults()); len(got) != 0 {
		t.Fatalf("unchanged events: %v", got)
	}
}

func TestLongMessagesRetainEssentialsAndSafeTitle(t *testing.T) {
	handle := strings.Repeat("\u754c", 100)
	tr := model.Transition{SituationID: "s", Lifecycle: model.LifecycleClosedUnknown, Projection: model.ProjectionFacts{
		PublicHandle: &handle,
		Briefing:     &model.OperatorBriefing{Symptoms: []string{strings.Repeat("x", 6000)}, Analyses: []model.IncidentAnalysis{{Summary: strings.Repeat("y", 6000), VerificationLimit: "cause unverified"}}},
	}}
	m := Render(tr, []string{"closed_uncertain"}, false)
	if strings.ContainsAny(m.Title, "\r\n") || len(m.Title) > 200 || !utf8.ValidString(m.Title) || !utf8.ValidString(m.Body) || len(m.Body) > 4000 || !strings.Contains(m.Body, "cause unverified") {
		t.Fatalf("lost essentials or invalid bounds: %q / %q", m.Title, m.Body)
	}
}

func TestRenderBoundedAndHonestRecovery(t *testing.T) {
	tr := model.Transition{ID: "tr", SituationID: "S-104", Lifecycle: model.LifecycleRecovered, Drill: true, CreatedAt: time.Now().UTC(), Journal: model.JournalData{Headline: strings.Repeat("\u754c", 2000)}}
	m := Render(tr, []string{"recovered"}, true)
	if len(m.Body) > 4000 || !strings.Contains(m.Body, "ntfy") || !strings.Contains(m.Title, "DRILL") || !strings.Contains(m.Title, "Recovered") {
		t.Fatalf("invalid message: %q (%d)", m.Title, len(m.Body))
	}
}

func TestQuietPriorityDoesNotGrantFirstPublication(t *testing.T) {
	low := model.InterruptionLow
	tr := model.Transition{Lifecycle: model.LifecycleActive, Attention: model.AttentionObserve, InterruptionPriority: &low}
	if got := Select(tr, nil, false, Defaults()); len(got) != 0 {
		t.Fatalf("quiet transition emitted %v", got)
	}
	tr.Attention = model.AttentionUrgent
	if got := Select(tr, nil, false, Defaults()); !reflect.DeepEqual(got, []string{"first_notification"}) {
		t.Fatalf("warranted transition emitted %v", got)
	}
}

func TestInvestigationStartsOnExecutionAndPriorityUsesState(t *testing.T) {
	high := model.InterruptionHigh
	prior := model.Transition{Attention: model.AttentionUrgent, Lifecycle: model.LifecycleActive}
	tr := prior
	tr.Reason = model.ReasonInvestigationStarted
	tr.InterruptionPriority = &high
	if got := Select(tr, &prior, true, Events); len(got) != 0 {
		t.Fatalf("planned work or unchanged urgency emitted %v", got)
	}
	tr.Projection.Briefing = &model.OperatorBriefing{Work: model.WorkProjection{ExecutionStarted: true}}
	if got := Select(tr, &prior, true, Events); !reflect.DeepEqual(got, []string{"investigation_started"}) {
		t.Fatalf("actual execution emitted %v", got)
	}
}
