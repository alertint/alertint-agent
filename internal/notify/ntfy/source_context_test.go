// SPDX-License-Identifier: FSL-1.1-ALv2

package ntfy

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// Source identity must remain visible before analysis completes, even when the
// source uses a Windows service name in its annotation rather than service=.
func TestRenderSourceContextIndependentOfAnalysis(t *testing.T) {
	for _, tc := range []struct {
		name      string
		lifecycle model.Lifecycle
		state     string
		analyses  []model.IncidentAnalysis
	}{
		{"before analysis", model.LifecycleActive, "firing", nil},
		{"generic analysis", model.LifecycleActive, "firing", []model.IncidentAnalysis{{Summary: "A critical alert is active."}}},
		{"recovery", model.LifecycleRecovered, "resolved", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := model.Transition{SituationID: "S-138", Lifecycle: tc.lifecycle,
				Projection: model.ProjectionFacts{Briefing: &model.OperatorBriefing{
					Symptoms: []string{"WindowsNodeServiceStatus"}, Total: 1,
					Analyses: tc.analyses, Historical: tc.lifecycle.Terminal(),
					Alerts: []model.BriefingAlert{{Name: "WindowsNodeServiceStatus", State: tc.state,
						Context: "KIT-RDSHP01", SourceSummary: "Service 'AutomateDesktop2025' on 'KIT-RDSHP01' is in a failed state."}},
				}}}
			for _, catchup := range []bool{false, true} {
				m := Render(tr, []string{"first_notification"}, false)
				if catchup {
					m = RenderCatchup(tr, []string{"first_notification"}, true)
				}
				for _, want := range []string{"AutomateDesktop2025", "KIT\\-RDSHP01", tc.state, "source report"} {
					if !strings.Contains(strings.ToLower(m.Body), strings.ToLower(want)) {
						t.Fatalf("missing source context %q (catchup=%v): %s", want, catchup, m.Body)
					}
				}
				if tc.state == "resolved" && (!strings.Contains(m.Body, "Historical source report") || !strings.Contains(m.Body, "not a current measurement")) {
					t.Fatalf("recovery presents retained failure annotation as current: %s", m.Body)
				}
			}
		})
	}
}

func TestRenderSourceContextWithoutAnnotation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alert model.BriefingAlert
		want  string
	}{
		{"host and service", model.BriefingAlert{Context: "server-a · checkout"}, "server\\-a · checkout"},
		{"service fallback", model.BriefingAlert{Service: "checkout"}, "checkout"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := model.Transition{Projection: model.ProjectionFacts{Briefing: &model.OperatorBriefing{Alerts: []model.BriefingAlert{tc.alert}}}}
			if m := Render(tr, nil, false); !strings.Contains(m.Body, tc.want) {
				t.Fatalf("missing affected context %q: %s", tc.want, m.Body)
			}
		})
	}
}

func TestRenderSourceContextEscapesAndBoundsWithoutLosingAction(t *testing.T) {
	action := model.OperatorActionInvestigateSituation
	b := &model.OperatorBriefing{AlertsOmitted: 1}
	for i := 0; i < 6; i++ {
		b.Alerts = append(b.Alerts, model.BriefingAlert{Name: "WindowsNodeServiceStatus", State: "firing",
			Context: "[server](https://example.org)\n# forged", SourceSummary: "![beacon](https://example.org/image) " + strings.Repeat("\u754c*", 1000)})
	}
	b.Analyses = []model.IncidentAnalysis{{Summary: strings.Repeat("x", 6000), VerificationLimit: "cause unverified"}}
	tr := model.Transition{SituationID: "S-138", Lifecycle: model.LifecycleActive,
		ActionContract: model.ActionContract{OperatorActionRequired: &action}, Projection: model.ProjectionFacts{Briefing: b}}
	m := Render(tr, []string{"operator_action_required"}, false)
	for _, want := range []string{"Source report", "Investigate this Situation", "cause unverified", "S-138", "More detail"} {
		if !strings.Contains(m.Body, want) {
			t.Fatalf("lost %q in bounded message: %s", want, m.Body)
		}
	}
	for _, unsafe := range []string{"[server](", "![beacon](", "\n# forged"} {
		if strings.Contains(m.Body, unsafe) {
			t.Fatalf("unescaped external source text %q: %s", unsafe, m.Body)
		}
	}
	if len(m.Body) > 4000 || !utf8.ValidString(m.Body) {
		t.Fatalf("invalid message bounds: %d bytes", len(m.Body))
	}
}

func TestRenderMultipleSourceAlertsKeepIdentityAndState(t *testing.T) {
	b := &model.OperatorBriefing{Alerts: []model.BriefingAlert{
		{Name: "ServiceStatus", State: "firing", Context: "host-a · checkout", SourceSummary: "Checkout unavailable"},
		{Name: "ServiceStatus", State: "resolved", Context: "host-b · payment", SourceSummary: "Payment unavailable"},
		{Name: "ServiceStatus", State: "firing", Context: "host-c · shipping"},
		{Name: "ServiceStatus", State: "firing", Context: "host-d · email"},
	}}
	m := Render(model.Transition{Projection: model.ProjectionFacts{Briefing: b}}, nil, false)
	for _, want := range []string{"host\\-a · checkout", "host\\-b · payment", "host\\-c · shipping", "Checkout unavailable", "Payment unavailable", "firing", "resolved", "Historical source report", "More detail"} {
		if !strings.Contains(m.Body, want) {
			t.Fatalf("missing distinct source context %q: %s", want, m.Body)
		}
	}
	if strings.Contains(m.Body, "host\\-d") {
		t.Fatalf("source section exceeds the three-alert display bound: %s", m.Body)
	}
}

func TestRenderMissingSourceContextDoesNotInventIdentity(t *testing.T) {
	b := &model.OperatorBriefing{Alerts: []model.BriefingAlert{{Name: "ServiceStatus", State: "firing"}}}
	m := Render(model.Transition{Projection: model.ProjectionFacts{Briefing: b}}, nil, false)
	if strings.Contains(m.Body, "Affected:") || strings.Contains(m.Body, "Source report") {
		t.Fatalf("empty source context must not produce a fabricated affected service: %s", m.Body)
	}
}

func TestRenderEscapedSourcePreservesIdentityBeforeOmittingDetail(t *testing.T) {
	b := &model.OperatorBriefing{Alerts: []model.BriefingAlert{{Name: "ServiceStatus", State: "firing",
		Context: strings.Repeat("_", 237) + "…", SourceSummary: "Service 'AutomateDesktop2025' failed. " + strings.Repeat("*", 460)}}}
	m := Render(model.Transition{SituationID: "S-138", Projection: model.ProjectionFacts{Briefing: b}}, nil, false)
	for _, want := range []string{"Source report", "Affected:", "AutomateDesktop2025", "More detail", "S-138"} {
		if !strings.Contains(m.Body, want) {
			t.Fatalf("escaped source loses identity %q: %s", want, m.Body)
		}
	}
}

func TestRenderEmptyAlertsDoNotHideLaterSourceContext(t *testing.T) {
	b := &model.OperatorBriefing{Alerts: []model.BriefingAlert{
		{Name: "Empty1"}, {Name: "Empty2"}, {Name: "Empty3"},
		{Name: "ServiceStatus", State: "firing", Context: "checkout", SourceSummary: "Checkout unavailable"},
	}}
	m := Render(model.Transition{Projection: model.ProjectionFacts{Briefing: b}}, nil, false)
	if !strings.Contains(m.Body, "checkout") || !strings.Contains(m.Body, "Checkout unavailable") {
		t.Fatalf("empty alerts hid available source context: %s", m.Body)
	}
}
