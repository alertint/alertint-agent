// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/config"
	model "github.com/alertint/alertint-agent/internal/observation/model"
)

func TestProductionPreparerFreezesEmptyAssessmentCycle(t *testing.T) {
	st := newTestFoundationStore(t)
	now := time.Now().UTC()
	_, id := seedDeliveredSituation(t, st, "empty-cycle", "service=checkout", now)
	req := preparationRequestFor(t, st, id, "empty-cycle", model.PhaseAssessment, now.Add(time.Minute))
	preparer := testProductionPreparer(st, &ctxCapturingExecutor{}, config.SituationPreparationConfig{MaxWallSeconds: 30, RefreshSeconds: 300, MaxSourceCallsPerCycle: 4})
	preparer.capabilities = nil
	if _, err := preparer.Prepare(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	in, err := st.LoadReconciliationInput(context.Background(), req.Claim, req.Now)
	if err != nil {
		t.Fatal(err)
	}
	if in.Prepared.CycleID == "" {
		t.Fatal("no reads due skipped freezing the input/config fence")
	}
	if len(in.Prepared.Runs) != 0 {
		t.Fatal("empty cycle unexpectedly has evidence")
	}
}
