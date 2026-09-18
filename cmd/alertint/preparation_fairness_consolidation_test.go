// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/observation"
	om "github.com/alertint/alertint-agent/internal/observation/model"
	pm "github.com/alertint/alertint-agent/internal/semanticprofile/model"
	"github.com/alertint/alertint-agent/internal/situation"
	sm "github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

// The executor substitutes only the remote API. Planning, reservations,
// cadence, profiles, cycle sealing, and restart recovery use the real store.
type fairnessConsolidationExecutor struct {
	now   *time.Time
	calls []om.Plan
}

func (e *fairnessConsolidationExecutor) Execute(ctx context.Context, p om.Plan, recorder observation.RequestRecorder) (om.Run, error) {
	reservation, err := recorder.BeforeRequest(ctx)
	if err != nil {
		return om.Run{}, err
	}
	if err := recorder.AfterRequest(ctx, om.RequestOutcome{ReservationID: reservation.ID, RequestStarted: om.RequestStartedTrue, Code: "ok", CompletedAt: *e.now}); err != nil {
		return om.Run{}, err
	}
	e.calls = append(e.calls, p)
	return om.Run{ID: "run:" + p.ID, CycleID: p.CycleID, PlanID: p.ID, Status: om.ResultConfirmedEmpty, Coverage: om.Coverage{Start: p.Start, End: p.End, Complete: true}, ObservedAt: *e.now, CompletedAt: *e.now, ExpiresAt: e.now.Add(time.Hour)}, nil
}

func TestProductionPreparerFairnessAcrossRoundsAndRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "fairness.db")
	st, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	now := time.Now().UTC()
	var sitID string
	for i := 0; i < 8; i++ {
		_, sitID = seedDeliveredSituation(t, st, fmt.Sprintf("fairness-%d", i), "fairness-group", now)
	}
	signatures, err := st.ListSituationSemanticSignatures(ctx, sitID)
	if err != nil {
		t.Fatal(err)
	}
	if len(signatures) == 0 {
		t.Fatal("fixture has no semantic signatures")
	}
	for _, sig := range signatures {
		_, err := st.CorrectSemanticProfile(ctx, pm.Correction{Signature: sig, Confirm: true, AssertedBy: "fairness-test", Profile: pm.Profile{SubjectKind: "service", EventKind: "availability", PossibleRole: "symptom", CandidateScope: []string{"service"}, HorizonTier: "hours", UsefulCapabilities: []string{"prometheus_query"}}}, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	exec := &fairnessConsolidationExecutor{now: &now}
	makePreparer := func() *productionPreparer {
		return &productionPreparer{
			st: st, runner: observation.NewRunner(st, map[om.Capability]observation.Executor{om.CapabilityZabbixProblemHist: exec, om.CapabilityPrometheusQuery: exec}, func() time.Time { return now }),
			capabilities: []observation.CapabilityDescriptor{{Capability: om.CapabilityZabbixProblemHist, DefaultWindow: time.Hour, DefaultLimit: 10, MaxRequestsHint: 1}, {Capability: om.CapabilityPrometheusQuery, DefaultWindow: time.Hour, DefaultLimit: 10, MaxRequestsHint: 1}},
			configDigest: "fairness-consolidation", prepCfg: config.SituationPreparationConfig{MaxSourceCallsPerCycle: 6, MaxWallSeconds: 20, RefreshSeconds: 60}, selectorKeys: []string{"service"}, logger: slog.New(slog.DiscardHandler),
		}
	}
	p := makePreparer()
	served := map[string]bool{}
	for round := 0; round < 3; round++ {
		req := preparationRequestFor(t, st, sitID, "fairness-owner", om.PhaseLifecycle, now)
		before := len(exec.calls)
		receipt, err := p.Prepare(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		req.Phase = om.PhaseAssessment
		if _, err := p.Prepare(ctx, req); err != nil {
			t.Fatal(err)
		}
		calls := exec.calls[before:]
		if len(calls) != 6 {
			t.Fatalf("round%d physical calls=%d want6 with available work", round, len(calls))
		}
		optional := 0
		for _, plan := range calls {
			if plan.Capability == om.CapabilityZabbixProblemHist {
				served[plan.Scope.SubjectID] = true
			} else if plan.Tier == om.TierOptional {
				optional++
			}
		}
		if optional != 1 {
			t.Fatalf("round%d optional admissions=%d want1", round, optional)
		}
		assertFairnessDeferred(t, ctx, st, receipt.CycleID, round)
		var creditBefore int
		if err := st.DB().QueryRowContext(ctx, `SELECT investigation_credit FROM situations WHERE id=?`, sitID).Scan(&creditBefore); err != nil {
			t.Fatal(err)
		}
		if want := 3 * (round + 1); creditBefore != want {
			t.Fatalf("round%d credit=%d want%d: one grant of6 less one optional request costing3", round, creditBefore, want)
		}
		if round == 0 {
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			st, err = store.Open(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			p = makePreparer()
		}
		// Repeating both phases after restart must reuse the same frozen cycle,
		// without creating requests or minting another cadence-credit award.
		for _, phase := range []om.Phase{om.PhaseLifecycle, om.PhaseAssessment} {
			req.Phase = phase
			repeated, err := p.Prepare(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			if repeated.CycleID != receipt.CycleID {
				t.Fatal("retry changed frozen cycle")
			}
		}
		creditAfter, err := st.AccrueInvestigationCredit(ctx, sitID, now.Add(30*time.Second), time.Minute, 6)
		if err != nil {
			t.Fatal(err)
		}
		if creditAfter != creditBefore || len(exec.calls) != before+6 {
			t.Fatalf("retry minted credit or requests: credit%d->%d calls%d", creditBefore, creditAfter, len(exec.calls)-before)
		}
		next := now.Add(time.Minute)
		if err := st.CommitController(ctx, req.Claim, situation.ControllerCommit{Lifecycle: sm.LifecycleActive, Attention: sm.AttentionObserve, NextAssessmentAt: next, PreparationCycleID: receipt.CycleID, PreparationGeneration: receipt.Generation}); err != nil {
			t.Fatal(err)
		}
		now = next
	}
	if len(served) != 8 {
		t.Fatalf("lifecycle subjects served=%d want8 across bounded rounds", len(served))
	}
}

func assertFairnessDeferred(t *testing.T, ctx context.Context, st *store.Store, cycleID string, round int) {
	t.Helper()
	var allocationJSON string
	if err := st.DB().QueryRowContext(ctx, `SELECT allocation_json FROM situation_preparation_cycles WHERE id=?`, cycleID).Scan(&allocationJSON); err != nil {
		t.Fatal(err)
	}
	var allocation om.PhaseAllocation
	if err := json.Unmarshal([]byte(allocationJSON), &allocation); err != nil {
		t.Fatal(err)
	}
	if len(allocation.Deferred) == 0 {
		t.Fatalf("round%d must explicitly defer excess reads", round)
	}
}
