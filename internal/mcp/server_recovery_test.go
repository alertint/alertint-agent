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

// addMember upserts an alert with the given status and links it to the incident.
func addMember(t *testing.T, st *store.Store, incID, fp, status string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	a := store.Alert{ID: fp + "-id", Fingerprint: fp, Status: status,
		Labels: map[string]string{}, Annotations: map[string]string{}, StartsAt: now, ReceivedAt: now}
	if _, err := st.UpsertAlertByFingerprint(ctx, a); err != nil {
		t.Fatalf("upsert %s: %v", fp, err)
	}
	if err := st.AddAlertToIncident(ctx, incID, a.ID, now); err != nil {
		t.Fatalf("add %s: %v", fp, err)
	}
}

func recoveryOf(t *testing.T, out string) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("payload not JSON: %v\n%s", err, out)
	}
	rec, ok := payload["recovery"].(map[string]any)
	if !ok {
		t.Fatalf("payload missing recovery object: %s", out)
	}
	return rec
}

// TestGetIncident_RecoverySignalPartial: a still-active incident with mixed
// member statuses reports firing/resolved counts, fully_resolved=false, and no
// resolved_at.
func TestGetIncident_RecoverySignalPartial(t *testing.T) {
	st := newMCPStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	id := "inc-partial"
	if err := st.InsertIncident(ctx, store.Incident{ID: id, GroupKey: "g=1", FirstAlertAt: now, LastAlertAt: now, ReadyAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkIncidentReady(ctx, id); err != nil {
		t.Fatal(err)
	}
	addMember(t, st, id, "m1", "firing")
	addMember(t, st, id, "m2", "firing")
	addMember(t, st, id, "m3", "resolved")

	s := NewServer(Config{}, st, audit.New(st.DB()))
	res, err := s.handleGetIncident(ctx, reqWith(map[string]any{"incident_id": id}))
	if err != nil || res.IsError {
		t.Fatalf("get incident errored: %v %s", err, resultText(t, res))
	}
	rec := recoveryOf(t, resultText(t, res))
	if rec["firing_alerts"] != float64(2) || rec["resolved_alerts"] != float64(1) || rec["total_alerts"] != float64(3) {
		t.Errorf("recovery counts wrong: %v", rec)
	}
	if rec["fully_resolved"] != false {
		t.Errorf("fully_resolved should be false with a firing member: %v", rec)
	}
	if _, ok := rec["resolved_at"]; ok {
		t.Errorf("resolved_at must be absent while not resolved: %v", rec)
	}
}

// TestGetIncident_RecoveryFullyResolved: once every member is resolved and the
// incident lifecycle status is "resolved", fully_resolved is true and
// resolved_at is present.
func TestGetIncident_RecoveryFullyResolved(t *testing.T) {
	st := newMCPStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	id := "inc-recovered"
	if err := st.InsertIncident(ctx, store.Incident{ID: id, GroupKey: "g=2", FirstAlertAt: now, LastAlertAt: now, ReadyAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkIncidentReady(ctx, id); err != nil {
		t.Fatal(err)
	}
	addMember(t, st, id, "r1", "resolved")
	addMember(t, st, id, "r2", "resolved")
	if err := st.MarkIncidentResolved(ctx, id); err != nil {
		t.Fatal(err)
	}

	s := NewServer(Config{}, st, audit.New(st.DB()))
	res, err := s.handleGetIncident(ctx, reqWith(map[string]any{"incident_id": id}))
	if err != nil || res.IsError {
		t.Fatalf("get incident errored: %v %s", err, resultText(t, res))
	}
	rec := recoveryOf(t, resultText(t, res))
	if rec["firing_alerts"] != float64(0) || rec["resolved_alerts"] != float64(2) {
		t.Errorf("recovery counts wrong: %v", rec)
	}
	if rec["fully_resolved"] != true {
		t.Errorf("fully_resolved should be true: %v", rec)
	}
	if _, ok := rec["resolved_at"]; !ok {
		t.Errorf("resolved_at must be present once resolved: %v", rec)
	}
}

// TestListIncidents_RecoverySignal: the list payload carries a recovery object
// per incident, derived in one batch query.
func TestListIncidents_RecoverySignal(t *testing.T) {
	st := newMCPStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	id := "inc-list"
	if err := st.InsertIncident(ctx, store.Incident{ID: id, GroupKey: "g=3", FirstAlertAt: now, LastAlertAt: now, ReadyAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkIncidentReady(ctx, id); err != nil {
		t.Fatal(err)
	}
	addMember(t, st, id, "l1", "firing")
	addMember(t, st, id, "l2", "resolved")

	s := NewServer(Config{}, st, audit.New(st.DB()))
	res, err := s.handleListIncidents(ctx, reqWith(map[string]any{}))
	if err != nil || res.IsError {
		t.Fatalf("list incidents errored: %v %s", err, resultText(t, res))
	}
	var payload struct {
		Incidents []struct {
			ID       string       `json:"id"`
			Recovery recoveryView `json:"recovery"`
		} `json:"incidents"`
	}
	if err := json.Unmarshal([]byte(resultText(t, res)), &payload); err != nil {
		t.Fatalf("list payload not JSON: %v", err)
	}
	if len(payload.Incidents) != 1 {
		t.Fatalf("want 1 incident, got %d", len(payload.Incidents))
	}
	got := payload.Incidents[0].Recovery
	if got.FiringAlerts != 1 || got.ResolvedAlerts != 1 || got.TotalAlerts != 2 || got.FullyResolved {
		t.Errorf("list recovery wrong: %+v", got)
	}
}
