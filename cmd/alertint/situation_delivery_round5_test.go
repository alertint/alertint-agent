// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// B5 round-5 delivery regressions (lead review round 4, 2026-09-10, R1),
// on the outbound payload itself.
//
// Round 4 stopped the retained mixed row from SELECTING a superseded start
// assurance. The lead's fresh overlay showed the same execution still
// reaching the operator through the reply's own *AlertINT:* line, rebuilt
// from this Transition's recorded contract and checkpoint. Both reply
// classes, both rendered surfaces.
// ----------------------------------------------------------------------

// ds5MonitoringContract records source monitoring rather than an
// investigation in flight.
func ds5MonitoringContract(next time.Time) model.ActionContract {
	action := model.AlertINTActionMonitorSituation
	status := model.AlertINTStatusRunning
	return model.ActionContract{
		NextActor:      model.NextActorAlertINT,
		AlertINTAction: &action,
		AlertINTStatus: &status,
		NextUpdateAt:   sdTimePtr(next),
		NextUpdateOn:   []model.NextUpdateOn{model.NextUpdateOnSourceResolution},
	}
}

// ds5ScopeOnly is the same row without any start assurance to suppress: the
// execution it reports as current is superseded all the same.
func ds5ScopeOnly(now time.Time) model.Transition {
	tr := ds4MixedStart(now)
	tr.Projection.OperatorDelta = &model.OperatorDelta{Candidates: []model.MaterialCandidate{
		{Kind: model.CandidateMembersChanged, Members: &model.MemberFacts{FiringCount: 1, Total: 1,
			PreviousScope: "checkout", Scope: "checkout + payments"}},
	}}
	return tr
}

// ds5StaleActivityStated reports whether the reply's own status line still
// presents the overtaken investigation as what is happening now.
func ds5StaleActivityStated(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "*AlertINT:* Investigating") {
			return true
		}
	}
	return false
}

// R1/1: on both reply classes and both surfaces, the delivered payload
// keeps the material scope change and carries neither the superseded
// execution nor its checkpoint.
func TestB5DeliveredReplyDropsTheSupersededExecutionOnBothClasses(t *testing.T) {
	now := sdMustTime(t, "2026-09-10T10:00:00Z")
	for _, class := range []model.EffectClass{model.EffectThreadAppend, model.EffectBroadcastHandoff} {
		t.Run(string(class), func(t *testing.T) {
			fallback, blocks := ds4Deliver(t, class, ds4MixedStart(now),
				situation.DeliveredHistory{AssuranceSuperseded: true}, now)
			for surface, text := range map[string]string{"fallback": fallback, "blocks": blocks} {
				t.Logf("%s:\n%s", surface, text)
				if !strings.Contains(text, "Affected scope changed from") {
					t.Errorf("%s lost the retained row's material scope change", surface)
				}
				if ds4AssuranceStated(text) {
					t.Errorf("%s published a start assurance the work had moved past", surface)
				}
				if ds5StaleActivityStated(text) {
					t.Errorf("%s presents the superseded execution as current activity", surface)
				}
				if strings.Contains(text, "Next status check") {
					t.Errorf("%s republishes the superseded checkpoint", surface)
				}
			}
		})
	}
}

// R1/2: the correction follows the superseded EXECUTION, not the assurance
// candidate. A row that never carried an assurance still rebuilds the same
// stale investigation from its own contract.
func TestB5DeliveredReplyWithoutAnAssuranceStillDropsTheSupersededExecution(t *testing.T) {
	now := sdMustTime(t, "2026-09-10T10:00:00Z")
	fallback, blocks := ds4Deliver(t, model.EffectThreadAppend, ds5ScopeOnly(now),
		situation.DeliveredHistory{AssuranceSuperseded: true}, now)
	for surface, text := range map[string]string{"fallback": fallback, "blocks": blocks} {
		if !strings.Contains(text, "Affected scope changed from") {
			t.Errorf("%s lost the row's material scope change", surface)
		}
		if ds5StaleActivityStated(text) {
			t.Errorf("%s presents the superseded execution as current activity: %s", surface, text)
		}
	}
}

// R1/3: an assurance the operator has already SEEN is a different question
// from one the work has moved past. Nothing overtook this execution, so the
// reply still reports it and its checkpoint.
func TestB5DeliveredReplyKeepsItsStatusWhenTheAssuranceWasOnlyAlreadyConveyed(t *testing.T) {
	now := sdMustTime(t, "2026-09-10T10:00:00Z")
	fallback, blocks := ds4Deliver(t, model.EffectThreadAppend, ds4MixedStart(now),
		situation.DeliveredHistory{AssuranceConveyed: true}, now)
	for surface, text := range map[string]string{"fallback": fallback, "blocks": blocks} {
		if ds4AssuranceStated(text) {
			t.Errorf("%s repeated an assurance the operator already has: %s", surface, text)
		}
		if !ds5StaleActivityStated(text) {
			t.Errorf("%s suppressed a running investigation nothing had overtaken: %s", surface, text)
		}
		if !strings.Contains(text, "Next status check") {
			t.Errorf("%s dropped a checkpoint that is still this reply's own: %s", surface, text)
		}
	}
}

// R1/4, positive control: an untouched history changes nothing at all.
func TestB5DeliveredReplyIsUnchangedWhenNothingWasSuperseded(t *testing.T) {
	now := sdMustTime(t, "2026-09-10T10:00:00Z")
	fallback, blocks := ds4Deliver(t, model.EffectThreadAppend, ds4MixedStart(now),
		situation.DeliveredHistory{}, now)
	for surface, text := range map[string]string{"fallback": fallback, "blocks": blocks} {
		if !ds4AssuranceStated(text) || !ds5StaleActivityStated(text) {
			t.Errorf("%s lost a fact nothing had superseded: %s", surface, text)
		}
	}
}

// R1/5, bound: the correction removes a stale investigation claim, not
// every activity line. Source monitoring recorded on this reply's own
// contract is not what the finding overtook.
func TestB5DeliveredMonitoringReplySurvivesASupersededExecution(t *testing.T) {
	now := sdMustTime(t, "2026-09-10T10:00:00Z")
	tr := ds5ScopeOnly(now)
	tr.ActionContract = ds5MonitoringContract(now.Add(5 * time.Minute))
	fallback, blocks := ds4Deliver(t, model.EffectThreadAppend, tr,
		situation.DeliveredHistory{AssuranceSuperseded: true}, now)
	for surface, text := range map[string]string{"fallback": fallback, "blocks": blocks} {
		if !strings.Contains(text, "*AlertINT:* Monitoring alert changes.") {
			t.Errorf("%s suppressed a monitoring line the overtaken execution does not govern: %s", surface, text)
		}
		if !strings.Contains(text, "Next status check") {
			t.Errorf("%s dropped a checkpoint that is this reply's own: %s", surface, text)
		}
	}
}
