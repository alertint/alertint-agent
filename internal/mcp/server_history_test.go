// SPDX-License-Identifier: FSL-1.1-ALv2

package mcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/store"
)

// callGetIncident runs handleGetIncident and decodes the JSON payload into a
// generic map, so a test can assert on individual top-level keys the way an
// MCP client would see them.
func callGetIncident(t *testing.T, s *Server, incidentID string) map[string]any {
	t.Helper()
	res, err := s.handleGetIncident(context.Background(), reqWith(map[string]any{"incident_id": incidentID}))
	if err != nil || res.IsError {
		t.Fatalf("handler: %v %s", err, resultText(t, res))
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(resultText(t, res)), &out); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	return out
}

// TestGetIncident_OperatorHistoryFromSiblingIncident proves operator_history
// is GROUP-scoped: a verdict captured on one incident must be visible via
// operator_history when reading a sibling incident on the same group key —
// the week-1 correction is reachable from the week-2 incident (R13). The
// existing incident-scoped verdict field must stay incident-scoped: inc-2
// carries no verdict of its own, so that field must be absent for it.
func TestGetIncident_OperatorHistoryFromSiblingIncident(t *testing.T) {
	st := newMCPStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	key := "cluster=prod,namespace=web,service=api"

	seedAnalyzedPrior(t, st, "inc-1", key, "root cause one", 0.7, now.AddDate(0, 0, -7), false)
	seedAnalyzedPrior(t, st, "inc-2", key, "root cause two", 0.7, now, false)

	if _, _, err := st.PersistVerdictCapture(ctx, store.VerdictCapture{
		IncidentID: "inc-1", Verdict: "correction",
		Source: store.VerdictSourceHuman, LabelConfidence: 1,
		ExpectationJSON: `{"must_not_conclude":["x"]}`, AnnotationNote: "not an AZ outage",
	}); err != nil {
		t.Fatal(err)
	}

	s := &Server{cfg: Config{}, st: st, auditor: audit.New(st.DB())}
	out := callGetIncident(t, s, "inc-2")

	oh, ok := out["operator_history"].(map[string]any)
	if !ok {
		t.Fatalf("operator_history missing: %v", out)
	}
	if oh["state"] != "history" {
		t.Fatalf("want state history, got %v", oh["state"])
	}
	v, _ := oh["verdict"].(map[string]any)
	if v == nil || v["kind"] != "correction" {
		t.Fatalf("governing verdict missing: %v", oh)
	}

	// The incident-scoped verdict field stays incident-scoped: inc-2 has none
	// of its own, so it must not be overloaded with the group's history.
	if _, present := out["verdict"]; present {
		t.Fatal("incident-scoped verdict field must not be overloaded with group history")
	}
}
