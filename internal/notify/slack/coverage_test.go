// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestSlackRootPreservesCoverageCauseAndObservationReference(t *testing.T) {
	now := rsMustTime(t, "2026-10-14T09:00:00Z")
	contract := rsObserveContract(now.Add(time.Minute))
	tr := rsTransition(1, model.LifecycleActive, model.AttentionObserve, contract, model.ReasonFirstAuthoritativeState, model.JournalNone, model.JournalData{OccurredAt: now}, model.ProjectionFacts{EffectiveStartedAt: now, EffectiveStartedAtBasis: model.SourceTimeBasisSourcePayload}, now)
	tr.Projection.CoverageLimitations = []model.CoverageLimitation{{RunID: "run:limited", Capability: "prometheus_query", Codes: []string{"fact_bytes_capped"}, Returned: 76, Omitted: 124}}
	summary := rsSummary(1, "Exchange replication", model.AttentionObserve, contract, now, now)
	msg, err := RenderSituationRoot(SituationRootInput{Summary: summary, SourceTransition: tr, ContractDeadlineAt: contract.NextUpdateAt, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(msg.Blocks)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"summary size limit", "76", "124", "run:limited"} {
		if !strings.Contains(msg.Text, want) || !strings.Contains(string(encoded), want) {
			t.Errorf("missing %q in Slack text/blocks: %s %s", want, msg.Text, encoded)
		}
	}
}
