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

// addLabeledMember upserts an alert with the given labels and links it to the
// incident (addMember variant for drill-detection fixtures).
func addLabeledMember(t *testing.T, st *store.Store, incID, fp string, labels map[string]string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	a := store.Alert{ID: fp + "-id", Fingerprint: fp, Status: "firing",
		Labels: labels, Annotations: map[string]string{}, StartsAt: now, ReceivedAt: now}
	if _, err := st.UpsertAlertByFingerprint(ctx, a); err != nil {
		t.Fatalf("upsert %s: %v", fp, err)
	}
	if err := st.AddAlertToIncident(ctx, incID, a.ID, now); err != nil {
		t.Fatalf("add %s: %v", fp, err)
	}
}

// TestListIncidents_DrillFlag: list rows carry drill=true only for incidents
// containing a Demo alert (ADR-0013), derived in one batch query.
func TestListIncidents_DrillFlag(t *testing.T) {
	st := newMCPStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	for _, id := range []string{"inc-drill", "inc-real"} {
		if err := st.InsertIncident(ctx, store.Incident{ID: id, GroupKey: "g=" + id, FirstAlertAt: now, LastAlertAt: now, ReadyAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	addLabeledMember(t, st, "inc-drill", "d1", map[string]string{
		store.DemoMarkerLabel: store.DemoMarkerValue, "service": "demo-checkout"})
	addLabeledMember(t, st, "inc-real", "r1", map[string]string{"service": "checkout"})

	s := NewServer(Config{}, st, audit.New(st.DB()))
	res, err := s.handleListIncidents(ctx, reqWith(map[string]any{}))
	if err != nil || res.IsError {
		t.Fatalf("list incidents errored: %v %s", err, resultText(t, res))
	}
	var payload struct {
		Incidents []struct {
			ID    string `json:"id"`
			Drill bool   `json:"drill"`
		} `json:"incidents"`
	}
	if err := json.Unmarshal([]byte(resultText(t, res)), &payload); err != nil {
		t.Fatalf("list payload not JSON: %v", err)
	}
	if len(payload.Incidents) != 2 {
		t.Fatalf("want 2 incidents, got %d", len(payload.Incidents))
	}
	want := map[string]bool{"inc-drill": true, "inc-real": false}
	for _, row := range payload.Incidents {
		if row.Drill != want[row.ID] {
			t.Errorf("%s drill = %v, want %v", row.ID, row.Drill, want[row.ID])
		}
	}
}

// TestGetIncident_DrillFlag: the single-incident payload carries the same
// derived drill boolean the list rows do.
func TestGetIncident_DrillFlag(t *testing.T) {
	st := newMCPStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	for _, id := range []string{"gi-drill", "gi-real"} {
		if err := st.InsertIncident(ctx, store.Incident{ID: id, GroupKey: "g=" + id, FirstAlertAt: now, LastAlertAt: now, ReadyAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	addLabeledMember(t, st, "gi-drill", "gd1", map[string]string{store.DemoMarkerLabel: store.DemoMarkerValue})
	addLabeledMember(t, st, "gi-real", "gr1", map[string]string{"service": "checkout"})

	s := NewServer(Config{}, st, audit.New(st.DB()))
	for id, want := range map[string]bool{"gi-drill": true, "gi-real": false} {
		res, err := s.handleGetIncident(ctx, reqWith(map[string]any{"incident_id": id}))
		if err != nil || res.IsError {
			t.Fatalf("get incident errored: %v %s", err, resultText(t, res))
		}
		var payload struct {
			Drill bool `json:"drill"`
		}
		if err := json.Unmarshal([]byte(resultText(t, res)), &payload); err != nil {
			t.Fatalf("payload not JSON: %v", err)
		}
		if payload.Drill != want {
			t.Errorf("%s drill = %v, want %v", id, payload.Drill, want)
		}
	}
}
