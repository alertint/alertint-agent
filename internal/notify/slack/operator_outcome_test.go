// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestOperatorOutcomeNoRequestIsNotNoActionNeeded(t *testing.T) {
	b := bcBriefing()
	msg, err := RenderSituationRoot(bcRoot(t, model.LifecycleActive, model.AttentionUrgent, bcObserveMonitorContract(bcNow(t).Add(time.Minute)), b))
	if err != nil {
		t.Fatal(err)
	}
	bcBothSurfaces(t, msg, "No operator action is recorded")
	if strings.Contains(msg.Text, "None required") {
		t.Fatalf("unrecorded request became reassurance:\n%s", msg.Text)
	}
}

func TestOperatorOutcomeSkippedWorkExplainsWhy(t *testing.T) {
	for _, tc := range []struct{ reason, want string }{
		{"prior_coverage", "assessment already covered these alert inputs"},
		{"eligibility_policy", "eligibility policy"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			b := bcBriefing()
			b.Analyses = nil
			b.Pending = 0
			b.Unavailable = 1
			b.Work = model.WorkProjection{Phase: model.WorkPhaseSettled, SkipReason: tc.reason}
			msg, err := RenderSituationRoot(bcRoot(t, model.LifecycleActive, model.AttentionUrgent, bcObserveMonitorContract(bcNow(t).Add(time.Minute)), b))
			if err != nil {
				t.Fatal(err)
			}
			bcBothSurfaces(t, msg, tc.want, "No investigation retry is scheduled")
		})
	}
}
