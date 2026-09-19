// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestExpectedBehaviorReviewIsStandaloneAndActionable(t *testing.T) {
	due := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	msg, err := RenderExpectedBehaviorReview(situation.ExpectedBehaviorReviewIntent{
		ID: "review-1", EnvelopeID: "env-1", EnvelopeVersion: 2, MatchCount: 7,
		Head: model.ExpectedBehaviorHead{Policy: &model.ExpectedBehaviorPolicy{
			Scope:      model.ExpectedBehaviorScope{Source: "zabbix", SourceInstanceID: "prod-zbx", Host: "db-prod-1", PrimaryTriggerID: "18422"},
			Conditions: model.ExpectedBehaviorConditions{Workload: "Nightly reconciliation"}, ReviewDueAt: due,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Expected schedule review", "Nightly reconciliation", "prod-zbx", "db-prod-1", "trigger 18422", "7 Situation(s)", "env-1", "alertint_get_expected_behavior", "stays active until an operator changes it", "<!date^"} {
		if !strings.Contains(msg.Text, want) {
			t.Fatalf("missing %q:\n%s", want, msg.Text)
		}
	}
}
