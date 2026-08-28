// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/llmhealth"
	"github.com/alertint/alertint-agent/internal/store"
)

// newRepairHealth returns a real tracker on an in-memory store so the repair
// call's health observation is asserted against the durable capability
// model, not a mock.
func newRepairHealth(t *testing.T) *llmhealth.Tracker {
	t.Helper()
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	tr, err := llmhealth.New(context.Background(), st, llmhealth.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func repairCap(t *testing.T, tr *llmhealth.Tracker) llmhealth.CapabilitySnapshot {
	t.Helper()
	snap := tr.Snapshot()
	if snap.InFlight != 0 {
		t.Fatalf("in_flight = %d after the repair call returned", snap.InFlight)
	}
	for _, c := range snap.Capabilities {
		if c.Capability == llmhealth.CapabilityQueryRepair {
			return c
		}
	}
	t.Fatalf("query_repair capability was never observed: %+v", snap)
	return llmhealth.CapabilitySnapshot{}
}

var invalidRepairInput = []VerificationQuery{{Kind: kindPromQL, Source: "model", Expr: `increase(metric_name[1h]) by (type)`, Why: "rate by type"}}

func repairSkill(tr *llmhealth.Tracker, fake *repairLLM) *Skill {
	return &Skill{llm: fake, cfg: Config{Health: tr}, logger: slog.Default()}
}

// TestRepairModelPromQL_ObservesLLMHealth pins ADR-0046's "final outcome of
// every real call" for the repair call, which is a real generation against
// the same provider: a dependency failure makes the installation degraded
// (the draft still ships, verification is just thinner), a reply that cannot
// be decoded or offers nothing usable is a content-class failure (needing the
// usual two-Incident corroboration), and a success clears the capability.
func TestRepairModelPromQL_ObservesLLMHealth(t *testing.T) {
	t.Run("dependency failure degrades", func(t *testing.T) {
		tr := newRepairHealth(t)
		repairSkill(tr, &repairLLM{err: &llm.RetryableError{StatusCode: 503}}).repairModelPromQL(context.Background(), "inc-1", invalidRepairInput)
		c := repairCap(t, tr)
		if c.Healthy || c.Reason != llmhealth.ReasonProviderUnavailable {
			t.Fatalf("%+v", c)
		}
		if st := tr.Snapshot().State; st != llmhealth.StateDegraded {
			t.Fatalf("state = %s, want degraded", st)
		}
	})
	t.Run("malformed reply is content-class", func(t *testing.T) {
		tr := newRepairHealth(t)
		s := repairSkill(tr, &repairLLM{raw: json.RawMessage(`not json`)})
		s.repairModelPromQL(context.Background(), "inc-1", invalidRepairInput)
		c := repairCap(t, tr)
		if !c.Healthy || c.Reason != llmhealth.ReasonResponseMalformed || c.LastFailureAt == nil {
			t.Fatalf("one malformed reply must record a content failure without declaring the capability unhealthy: %+v", c)
		}
		s.repairModelPromQL(context.Background(), "inc-2", invalidRepairInput)
		if c := repairCap(t, tr); c.Healthy {
			t.Fatalf("two Incidents corroborate: %+v", c)
		}
	})
	t.Run("rejected replacement is content-class", func(t *testing.T) {
		tr := newRepairHealth(t)
		repairSkill(tr, &repairLLM{raw: json.RawMessage(`{"queries":[{"index":0,"expr":"still(bad"}]}`)}).repairModelPromQL(context.Background(), "inc-1", invalidRepairInput)
		if c := repairCap(t, tr); c.Reason != llmhealth.ReasonResponseMalformed || c.LastFailureAt == nil {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("success clears", func(t *testing.T) {
		tr := newRepairHealth(t)
		repairSkill(tr, &repairLLM{err: &llm.RetryableError{StatusCode: 503}}).repairModelPromQL(context.Background(), "inc-1", invalidRepairInput)
		repairSkill(tr, &repairLLM{raw: json.RawMessage(`{"queries":[{"index":0,"expr":"sum by (type) (increase(metric_name[1h]))"}]}`)}).repairModelPromQL(context.Background(), "inc-2", invalidRepairInput)
		if c := repairCap(t, tr); !c.Healthy || c.LastSuccessAt == nil {
			t.Fatalf("%+v", c)
		}
		if st := tr.Snapshot().State; st != llmhealth.StateHealthy {
			t.Fatalf("state = %s", st)
		}
	})
	t.Run("no invalid queries means no observation", func(t *testing.T) {
		tr := newRepairHealth(t)
		repairSkill(tr, &repairLLM{}).repairModelPromQL(context.Background(), "inc-1", []VerificationQuery{{Kind: kindPromQL, Source: "model", Expr: `sum(up)`}})
		if caps := tr.Snapshot().Capabilities; len(caps) != 0 {
			t.Fatalf("no call was made, nothing to observe: %+v", caps)
		}
	})
}
