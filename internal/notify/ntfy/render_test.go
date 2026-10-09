// SPDX-License-Identifier: FSL-1.1-ALv2

package ntfy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestRenderLeadsWithServiceAndKeepsFullReference(t *testing.T) {
	id := "1f8f9707-ed1f-44ad-bd3b-429f13e8332e"
	tr := model.Transition{ID: "transition", SituationID: id, Lifecycle: model.LifecycleActive,
		CreatedAt: time.Date(2026, 10, 9, 9, 30, 0, 0, time.UTC),
		Projection: model.ProjectionFacts{Briefing: &model.OperatorBriefing{
			DisplayScope: "payment", Symptoms: []string{"ServiceErrorRateHigh"}, Total: 1, Firing: 1,
		}}}
	m := Render(tr, []string{"first_notification"}, false)
	if !strings.Contains(m.Title, "payment") || strings.Contains(m.Title, id) {
		t.Fatalf("title should orient by service, not UUID: %q", m.Title)
	}
	if !strings.Contains(m.Body, id) || !strings.Contains(m.Body, "Service Error Rate High") || strings.Contains(m.Body, "first_notification") {
		t.Fatalf("missing reference/symptom or raw event enum: %q", m.Body)
	}
	if m.ID != "ntfy:transition" {
		t.Fatalf("changed retry identity: %q", m.ID)
	}
}

func TestRenderTerminalNeverRequestsStaleAction(t *testing.T) {
	action := model.OperatorActionInvestigateSituation
	for _, lifecycle := range []model.Lifecycle{model.LifecycleRecovered, model.LifecycleClosedUnknown} {
		tr := model.Transition{SituationID: "S-104", Lifecycle: lifecycle,
			ActionContract: model.ActionContract{OperatorActionRequired: &action},
			Journal:        model.JournalData{Headline: "Operator action required", Detail: "Investigate this Situation."}}
		m := RenderCatchup(tr, []string{"operator_action_required"}, true)
		if strings.Contains(m.Body, "Investigate this Situation") || strings.Contains(m.Title, "Action required") || m.Priority != 3 {
			t.Fatalf("stale terminal action: %+v", m)
		}
		if !strings.Contains(m.Body, "ntfy") {
			t.Fatalf("missing delivery recap: %q", m.Body)
		}
	}
}

func TestRenderUntrustedTextCannotInjectMarkdown(t *testing.T) {
	tr := model.Transition{SituationID: "S-104", Lifecycle: model.LifecycleActive,
		Projection: model.ProjectionFacts{Briefing: &model.OperatorBriefing{
			DisplayScope: "payment\nFORGED STATUS", Symptoms: []string{"[approve](https://example.org)"},
			Analyses: []model.IncidentAnalysis{{Summary: "**Confirmed**\n# Forged heading", Observations: []string{"![beacon](https://example.org/image)"}}},
		}}}
	m := Render(tr, []string{"first_notification"}, false)
	for _, injected := range []string{"[approve](", "**Confirmed**", "\n# Forged", "![beacon]("} {
		if strings.Contains(m.Body, injected) {
			t.Fatalf("unescaped Markdown %q in %q", injected, m.Body)
		}
	}
	if strings.ContainsAny(m.Title, "\r\n") {
		t.Fatalf("unsafe title %q", m.Title)
	}
}

func TestRenderLongEvidenceKeepsActionUncertaintyAndReference(t *testing.T) {
	action := model.OperatorActionInvestigateSituation
	tr := model.Transition{SituationID: "S-104", Lifecycle: model.LifecycleActive,
		ActionContract: model.ActionContract{OperatorActionRequired: &action},
		Projection: model.ProjectionFacts{Briefing: &model.OperatorBriefing{
			DisplayScope: strings.Repeat("\u754c", 300), Symptoms: []string{strings.Repeat("*", 6000)},
			Analyses: []model.IncidentAnalysis{{Summary: strings.Repeat("\u754c", 6000), VerificationLimit: "cause unverified", Observations: []string{strings.Repeat("`", 6000)}}},
		}}}
	m := Render(tr, []string{"operator_action_required"}, false)
	for _, essential := range []string{"Investigate this Situation", "cause unverified", "S-104"} {
		if !strings.Contains(m.Body, essential) {
			t.Fatalf("lost essential %q in %q", essential, m.Body)
		}
	}
	if len(m.Body) > 4000 || !utf8.ValidString(m.Body) || !utf8.ValidString(m.Title) {
		t.Fatalf("invalid bounds: %d bytes", len(m.Body))
	}
	if !strings.Contains(m.Body, "MCP") {
		t.Fatalf("omitted detail must be acknowledged: %q", m.Body)
	}
}

func TestRenderActivityDistinguishesPlannedFromExecuting(t *testing.T) {
	action := model.AlertINTActionRunAcuteTriage
	for _, tc := range []struct {
		status model.AlertINTStatus
		want   string
	}{
		{model.AlertINTStatusPlanned, "planned"},
		{model.AlertINTStatusRunning, "Investigating"},
		{model.AlertINTStatusBlocked, "blocked"},
	} {
		tr := model.Transition{Lifecycle: model.LifecycleActive, ActionContract: model.ActionContract{AlertINTAction: &action, AlertINTStatus: &tc.status}}
		m := Render(tr, []string{"first_notification"}, false)
		if !strings.Contains(m.Body, tc.want) || strings.Contains(m.Body, "run acute triage") {
			t.Fatalf("unreadable or incorrect activity for %s: %q", tc.status, m.Body)
		}
		if tc.status != model.AlertINTStatusRunning && strings.Contains(m.Body, "Investigating") {
			t.Fatalf("not-yet-running work claims execution: %q", m.Body)
		}
	}
}

func TestRenderExternalScopeCannotBreakHTTPDelivery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(r.Header.Get("Title"), "\x00\x1b\x7f\r\n") {
			t.Error("invalid control reached HTTP title")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	tr := model.Transition{ID: "transition", SituationID: "S-104", Lifecycle: model.LifecycleActive,
		Projection: model.ProjectionFacts{Briefing: &model.OperatorBriefing{DisplayScope: "payment\x00\x1b\x7f\r\nservice"}}}
	m := Render(tr, []string{"first_notification"}, false)
	if err := NewClient("").Send(context.Background(), srv.URL, m); err != nil {
		t.Fatalf("untrusted scope prevented delivery: %v (title %q)", err, m.Title)
	}
}

func TestRenderOrderedActivityIsExplicitlyScopedToUpdateTime(t *testing.T) {
	action, status := model.AlertINTActionRunAcuteTriage, model.AlertINTStatusRunning
	at := time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC)
	checkpoint := at.Add(time.Minute)
	tr := model.Transition{SituationID: "S-104", Lifecycle: model.LifecycleActive, CreatedAt: at,
		ActionContract: model.ActionContract{AlertINTAction: &action, AlertINTStatus: &status, NextUpdateAt: &checkpoint}}
	m := Render(tr, []string{"investigation_started"}, false)
	activity := strings.Index(m.Body, "Investigating this Situation")
	context := strings.Index(m.Body, "At this update")
	if context < 0 || activity < context || !strings.Contains(m.Body, "As of") || !strings.Contains(m.Body, "Checkpoint:** 09 Oct 2026") {
		t.Fatalf("queued activity is not explicitly historical: %q", m.Body)
	}
}
