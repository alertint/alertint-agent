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

// TestIncidentPayloads_OccurrenceCount: both the list rows and the single-incident
// payload expose the recurrence-collapse occurrence count from the same ledger.
func TestIncidentPayloads_OccurrenceCount(t *testing.T) {
	st := newMCPStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	for _, id := range []string{"inc-recurring", "inc-fresh"} {
		if err := st.InsertIncident(ctx, store.Incident{ID: id, GroupKey: "g=" + id, FirstAlertAt: now, LastAlertAt: now, ReadyAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	// Two re-fire episodes collapsed into inc-recurring; none for inc-fresh.
	for i := 1; i <= 2; i++ {
		at := now.Add(time.Duration(i) * time.Minute)
		if _, err := st.InsertOccurrence(ctx, store.Occurrence{IncidentID: "inc-recurring", OccurredAt: at, LastSeen: at, Fingerprints: []string{"fp"}}); err != nil {
			t.Fatalf("insert occurrence %d: %v", i, err)
		}
	}

	s := NewServer(Config{}, st, audit.New(st.DB()))

	// List rows.
	res, err := s.handleListIncidents(ctx, reqWith(map[string]any{}))
	if err != nil || res.IsError {
		t.Fatalf("list errored: %v %s", err, resultText(t, res))
	}
	var list struct {
		Incidents []struct {
			ID          string `json:"id"`
			Occurrences int    `json:"occurrences"`
		} `json:"incidents"`
	}
	if err := json.Unmarshal([]byte(resultText(t, res)), &list); err != nil {
		t.Fatalf("list payload not JSON: %v", err)
	}
	want := map[string]int{"inc-recurring": 2, "inc-fresh": 0}
	for _, row := range list.Incidents {
		if row.Occurrences != want[row.ID] {
			t.Errorf("list %s occurrences = %d, want %d", row.ID, row.Occurrences, want[row.ID])
		}
	}

	// Detail payload.
	res, err = s.handleGetIncident(ctx, reqWith(map[string]any{"incident_id": "inc-recurring"}))
	if err != nil || res.IsError {
		t.Fatalf("get errored: %v %s", err, resultText(t, res))
	}
	var detail struct {
		Occurrences      int        `json:"occurrences"`
		LastOccurrenceAt *time.Time `json:"last_occurrence_at"`
	}
	if err := json.Unmarshal([]byte(resultText(t, res)), &detail); err != nil {
		t.Fatalf("detail payload not JSON: %v", err)
	}
	if detail.Occurrences != 2 {
		t.Errorf("detail occurrences = %d, want 2", detail.Occurrences)
	}
	if detail.LastOccurrenceAt == nil {
		t.Error("detail missing last_occurrence_at for a recurring incident")
	}
}
