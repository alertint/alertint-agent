// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/observation/connectors"
	model "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/prometheus"
)

func TestProductionPreparationPersistsPriorityEvidenceAndCoverage(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	st := newTestFoundationStore(t)
	_, sitID := seedDeliveredSituation(t, st, "priority", "service=checkout", now)
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/rules" {
			_, _ = fmt.Fprint(w, `{"status":"success","data":{"groups":[{"name":"app","rules":[{"type":"alerting","name":"test","query":"z_errors > 0","alerts":[{"state":"firing","labels":{"service":"checkout"}}]}]}]}}`)
			return
		}
		q := r.URL.Query().Get("query")
		if !strings.Contains(q, `service="checkout"`) {
			t.Errorf("scope missing: %s", q)
		}
		var rows []any
		if strings.Contains(q, `__name__=~`) {
			rows = []any{map[string]any{"metric": map[string]string{"__name__": "z_errors", "service": "checkout"}, "values": [][2]any{{1, "1"}}}}
		} else {
			for i := 0; i < 200; i++ {
				rows = append(rows, map[string]any{"metric": map[string]string{"__name__": "a_cpu", "core": fmt.Sprint(i), "pad": strings.Repeat("p", 200)}, "values": [][2]any{{1, "1"}}})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "matrix", "result": rows}})
	}))
	defer srv.Close()
	cfg := &config.Config{}
	cfg.Prometheus.BaseURL = srv.URL
	p := testProductionPreparer(st, &connectors.PrometheusExecutor{Client: prometheus.NewClient(prometheus.Config{BaseURL: srv.URL})}, config.SituationPreparationConfig{MaxSourceCallsPerCycle: 5, MaxWallSeconds: 20, RefreshSeconds: 300})
	p.capabilities = capabilityDescriptorsFromConfig(cfg)
	req := preparationRequestFor(t, st, sitID, "priority-owner", model.PhaseAssessment, now)
	receipt, err := p.Prepare(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	runs, _, err := st.ListObservationRuns(ctx, sitID, receipt.CycleID, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 {
		t.Fatalf("runs=%v", runs)
	}
	run := runs[0]
	if run.Run.Status != model.ResultTruncated || run.Run.Coverage.Complete || run.RequestsCompleted != 3 || len(paths) != 3 {
		t.Fatalf("run=%+v paths=%v", run, paths)
	}
	if len(run.Run.Facts) != 1 || !strings.Contains(string(run.Run.Facts[0].Value), "z_errors") {
		t.Fatal("stored run lost priority evidence")
	}
	loaded, err := st.LoadReconciliationInput(ctx, req.Claim, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Prepared.Runs) != 1 || loaded.Prepared.Runs[0].ID != run.Run.ID || loaded.Prepared.Runs[0].Coverage.Omitted == 0 {
		t.Fatalf("coherent reconciliation lost coverage: %+v", loaded.Prepared)
	}
}
