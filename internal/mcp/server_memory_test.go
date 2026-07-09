// SPDX-License-Identifier: FSL-1.1-ALv2

package mcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/google/uuid"
)

// seedAnalyzedPrior inserts a judged incident carrying a finding, optionally with
// a drill member alert, so memoryView can recall it.
func seedAnalyzedPrior(t *testing.T, st *store.Store, id, key, rootCause string, confidence float64, at time.Time, drill bool) {
	t.Helper()
	ctx := context.Background()
	if err := st.InsertIncident(ctx, store.Incident{ID: id, GroupKey: key, FirstAlertAt: at, LastAlertAt: at, ReadyAt: at}); err != nil {
		t.Fatalf("insert prior %s: %v", id, err)
	}
	if err := st.MarkIncidentReady(ctx, id); err != nil {
		t.Fatalf("ready %s: %v", id, err)
	}
	if err := st.SaveIncidentOutput(ctx, id, `{"overall_issue":"x"}`, "summary", rootCause, confidence, ""); err != nil {
		t.Fatalf("save output %s: %v", id, err)
	}
	labels := map[string]string{"alertname": "DiskFull"}
	if drill {
		labels[store.DrillMarkerLabel] = store.DrillMarkerValue
	}
	a := store.Alert{ID: uuid.NewString(), Fingerprint: "fp-" + id, Status: "firing", Labels: labels, StartsAt: at, ReceivedAt: at}
	if _, err := st.UpsertAlertByFingerprint(ctx, a); err != nil {
		t.Fatalf("alert %s: %v", id, err)
	}
	if err := st.AddAlertToIncident(ctx, id, a.ID, at); err != nil {
		t.Fatalf("attach %s: %v", id, err)
	}
}

type detailMemory struct {
	Memory *struct {
		GroupKey      string `json:"group_key"`
		Episodes      int    `json:"episodes"`
		LookbackDays  int    `json:"lookback_days"`
		DrillFiltered bool   `json:"drill_filtered"`
		PriorFindings []struct {
			IncidentID string  `json:"incident_id"`
			Confidence float64 `json:"confidence"`
			RootCause  string  `json:"root_cause"`
			Episodes   int     `json:"episodes"`
		} `json:"prior_findings"`
	} `json:"memory"`
}

func getIncidentMemory(t *testing.T, s *Server, id string) *detailMemory {
	t.Helper()
	res, err := s.handleGetIncident(context.Background(), reqWith(map[string]any{"incident_id": id}))
	if err != nil || res.IsError {
		t.Fatalf("detail errored: %v %s", err, resultText(t, res))
	}
	var d detailMemory
	if err := json.Unmarshal([]byte(resultText(t, res)), &d); err != nil {
		t.Fatalf("detail payload not JSON: %v", err)
	}
	return &d
}

// The incident-detail memory block is computed from the same memoryView the LLM
// saw, so the operator's view cannot drift from the prompt (R26).
func TestGetIncident_MemoryBlockMatchesMemoryView(t *testing.T) {
	st := newMCPStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	key := "cluster=prod,namespace=web,service=api"

	// Current incident + one analyzed prior on the same key, with two occurrences.
	if err := st.InsertIncident(ctx, store.Incident{ID: "inc-current", GroupKey: key, FirstAlertAt: now, LastAlertAt: now, ReadyAt: now}); err != nil {
		t.Fatal(err)
	}
	seedAnalyzedPrior(t, st, "inc-prior", key, "backup rotation misconfigured", 0.70, now.AddDate(0, 0, -3), false)
	for i := 1; i <= 2; i++ {
		at := now.AddDate(0, 0, -3).Add(time.Duration(i) * 24 * time.Hour)
		if _, err := st.InsertOccurrence(ctx, store.Occurrence{IncidentID: "inc-prior", OccurredAt: at, LastSeen: at, Fingerprints: []string{"fp"}}); err != nil {
			t.Fatalf("occurrence: %v", err)
		}
	}

	s := NewServer(Config{MemoryLookbackDays: 90}, st, audit.New(st.DB()))
	d := getIncidentMemory(t, s, "inc-current")
	if d.Memory == nil {
		t.Fatal("expected a memory block on the incident detail")
	}

	// Compare to a directly-computed view (same method → no drift by construction).
	view, err := st.MemoryView(ctx, key, "inc-current", false, now.AddDate(0, 0, -90))
	if err != nil {
		t.Fatalf("MemoryView: %v", err)
	}
	if d.Memory.GroupKey != view.GroupKey || d.Memory.Episodes != view.Episodes {
		t.Errorf("memory block group/episodes = %s/%d, view = %s/%d", d.Memory.GroupKey, d.Memory.Episodes, view.GroupKey, view.Episodes)
	}
	if d.Memory.LookbackDays != 90 {
		t.Errorf("lookback_days = %d, want 90", d.Memory.LookbackDays)
	}
	if len(d.Memory.PriorFindings) != len(view.PriorFindings) || len(d.Memory.PriorFindings) != 1 {
		t.Fatalf("prior_findings = %d, want 1 (matching view)", len(d.Memory.PriorFindings))
	}
	pf := d.Memory.PriorFindings[0]
	if pf.IncidentID != "inc-prior" || pf.Confidence != 0.70 || pf.RootCause != "backup rotation misconfigured" {
		t.Errorf("prior finding fields wrong: %+v", pf)
	}
	if pf.Episodes != 3 { // first fire + 2 occurrences
		t.Errorf("prior episodes = %d, want 3", pf.Episodes)
	}
}

func TestGetIncident_NoMemoryOmitsBlock(t *testing.T) {
	st := newMCPStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := st.InsertIncident(ctx, store.Incident{ID: "inc-lonely", GroupKey: "cluster=x,namespace=y,service=z", FirstAlertAt: now, LastAlertAt: now, ReadyAt: now}); err != nil {
		t.Fatal(err)
	}
	s := NewServer(Config{MemoryLookbackDays: 90}, st, audit.New(st.DB()))
	if d := getIncidentMemory(t, s, "inc-lonely"); d.Memory != nil {
		t.Errorf("an incident with no recalled history must omit the memory block, got %+v", d.Memory)
	}
}

// A MemoryView error must omit the memory block, not fail the whole incident
// detail — the operator read stays available even if recall computation errors.
func TestGetIncident_MemoryErrorOmitsBlockNotWholeResponse(t *testing.T) {
	st := newMCPStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	key := "cluster=prod,namespace=web,service=api"

	// Current incident (valid) + a same-key prior with a corrupt first_alert_at,
	// so scanning the candidate for the memory view fails to parse.
	if err := st.InsertIncident(ctx, store.Incident{ID: "inc-cur", GroupKey: key, FirstAlertAt: now, LastAlertAt: now, ReadyAt: now}); err != nil {
		t.Fatal(err)
	}
	ts := now.Format(time.RFC3339Nano)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO incidents (id, group_key, status, first_alert_at, last_alert_at, ready_at, alert_count,
			summary, root_cause, confidence, output_json, created_at, updated_at, memory_refute_marks)
		VALUES ('inc-corrupt', ?, 'analyzed', 'not-a-timestamp', ?, ?, 1, 's', 'rc', 0.6, '{}', ?, ?, 0)
	`, key, ts, ts, ts, ts); err != nil {
		t.Fatalf("seed corrupt prior: %v", err)
	}

	s := NewServer(Config{MemoryLookbackDays: 90}, st, audit.New(st.DB()))
	res, err := s.handleGetIncident(ctx, reqWith(map[string]any{"incident_id": "inc-cur"}))
	if err != nil || res.IsError {
		t.Fatalf("incident detail must still render when recall errors: %v %s", err, resultText(t, res))
	}
	var core struct {
		ID     string `json:"id"`
		Memory *any   `json:"memory"`
	}
	if err := json.Unmarshal([]byte(resultText(t, res)), &core); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	if core.ID != "inc-cur" {
		t.Errorf("core incident fields must render, got id=%q", core.ID)
	}
	if core.Memory != nil {
		t.Errorf("memory block should be omitted on a recall error, got %v", *core.Memory)
	}
}

// A drill incident's detail recalls only drill-side priors, and vice versa (R27).
func TestGetIncident_MemoryRespectsDrillParity(t *testing.T) {
	st := newMCPStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	key := "cluster=prod,namespace=web,service=api"

	seedAnalyzedPrior(t, st, "inc-real-prior", key, "real cause", 0.6, now.AddDate(0, 0, -2), false)
	seedAnalyzedPrior(t, st, "inc-drill-prior", key, "drill cause", 0.6, now.AddDate(0, 0, -2), true)

	// A drill current incident (its member alert carries the marker).
	if err := st.InsertIncident(ctx, store.Incident{ID: "inc-drill-cur", GroupKey: key, FirstAlertAt: now, LastAlertAt: now, ReadyAt: now}); err != nil {
		t.Fatal(err)
	}
	da := store.Alert{ID: uuid.NewString(), Fingerprint: "fp-cur", Status: "firing",
		Labels: map[string]string{"alertname": "DiskFull", store.DrillMarkerLabel: store.DrillMarkerValue}, StartsAt: now, ReceivedAt: now}
	if _, err := st.UpsertAlertByFingerprint(ctx, da); err != nil {
		t.Fatal(err)
	}
	if err := st.AddAlertToIncident(ctx, "inc-drill-cur", da.ID, now); err != nil {
		t.Fatal(err)
	}

	s := NewServer(Config{MemoryLookbackDays: 90}, st, audit.New(st.DB()))
	d := getIncidentMemory(t, s, "inc-drill-cur")
	if d.Memory == nil || len(d.Memory.PriorFindings) != 1 {
		t.Fatalf("drill incident should recall exactly its drill prior, got %+v", d.Memory)
	}
	if d.Memory.PriorFindings[0].IncidentID != "inc-drill-prior" {
		t.Errorf("drill detail recalled %s, want inc-drill-prior", d.Memory.PriorFindings[0].IncidentID)
	}
	if !d.Memory.DrillFiltered {
		t.Error("a real prior was filtered out, drill_filtered should be true")
	}
}
