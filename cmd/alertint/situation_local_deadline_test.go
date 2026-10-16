// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/observation"
	"github.com/alertint/alertint-agent/internal/observation/connectors"
	model "github.com/alertint/alertint-agent/internal/observation/model"
)

func TestProductionPreparerPersistsLocalReadAfterIOWallExpires(t *testing.T) {
	st := newTestFoundationStore(t)
	now := time.Now().UTC()
	_, sitID := seedDeliveredSituation(t, st, "local-deadline", "service=checkout-local-deadline", now.Add(-time.Minute))
	req := preparationRequestFor(t, st, sitID, "local-deadline-owner", model.PhaseAssessment, now)
	// Input assembly already spent the external I/O wall. The claim and
	// controller context are still live; a local SQL read must still work.
	req.Now = now.Add(-21 * time.Second)
	p := &productionPreparer{
		st: st,
		runner: observation.NewRunner(st, map[model.Capability]observation.Executor{
			model.CapabilityChangeEvents: &connectors.ChangesExecutor{Store: st},
		}, nil),
		capabilities: []observation.CapabilityDescriptor{{Capability: model.CapabilityChangeEvents, DefaultWindow: time.Hour, DefaultLimit: 10}},
		configDigest: "local-deadline-regression",
		prepCfg:      config.SituationPreparationConfig{MaxSourceCallsPerCycle: 5, MaxWallSeconds: 20, RefreshSeconds: 60},
		selectorKeys: []string{"service"}, logger: slog.New(slog.DiscardHandler),
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := p.Prepare(ctx, req); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	var status string
	var complete, requests int
	if err := st.DB().QueryRowContext(ctx, `
		SELECT r.status, r.coverage_complete
		FROM situation_observation_runs r
		JOIN situation_observation_plans p ON p.id = r.plan_id
		JOIN situation_preparation_cycles c ON c.id = r.cycle_id
		WHERE c.situation_id = ? AND p.capability = 'change_events'`, sitID).Scan(&status, &complete); err != nil {
		t.Fatal(err)
	}
	if status != "confirmed_empty" || complete != 1 {
		t.Fatalf("persisted status = %q, complete = %d, want complete confirmed_empty local read", status, complete)
	}
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_observation_requests`).Scan(&requests); err != nil {
		t.Fatal(err)
	}
	if requests != 0 {
		t.Fatalf("physical requests = %d, want zero for local SQL", requests)
	}
}
