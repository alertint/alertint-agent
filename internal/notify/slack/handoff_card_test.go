// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"strings"
	"testing"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestBroadcastHandoffIdentifiesExistingThreadAndNewAlert(t *testing.T) {
	tr := bcJournal(t, bcObserveMonitorContract(bcNow(t)), canonicalFixture(t), &model.OperatorDelta{
		NewFiringAlerts: []string{"DatabaseUnavailable"}, AttentionIncreased: true,
	})
	msg, err := RenderSituationHandoff(SituationReplyInput{Transition: tr})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Update in existing Situation thread", "*Why:* New alerts: 1 (urgency)."} {
		if !strings.Contains(msg.Text, want) {
			t.Fatalf("handoff missing %q: %s", want, msg.Text)
		}
	}
	for _, unwanted := range []string{"Open the thread", "*Action now:*"} {
		if strings.Contains(msg.Text, unwanted) {
			t.Fatalf("handoff has %q: %s", unwanted, msg.Text)
		}
	}
	action := model.OperatorActionInvestigateSituation
	tr.ActionContract.OperatorActionRequired = &action
	tr.ActionContract.NextActor = model.NextActorOperator
	tr.ActionContract.AlertINTAction = nil
	msg, err = RenderSituationHandoff(SituationReplyInput{Transition: tr})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg.Text, "*Action now:* Investigate this Situation.") {
		t.Fatal(msg.Text)
	}
}
