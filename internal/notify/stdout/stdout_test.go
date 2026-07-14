// SPDX-License-Identifier: FSL-1.1-ALv2

package stdout

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/store"
)

func TestOnOccurrenceAttached_WritesLineAlways(t *testing.T) {
	var buf bytes.Buffer
	// verbose=false: the occurrence line is written regardless (it is the visible
	// collapse signal), unlike the verbose-gated finding line.
	n := New(&buf, nil, false)

	err := n.OnOccurrenceAttached(context.Background(), notify.RecurrenceEvent{
		Incident: store.Incident{ID: "i1", GroupKey: "k"},
		Stats:    store.OccurrenceStats{Count: 7, LastSeen: time.Now().UTC()},
		Trigger:  "cadence",
		Drill:    true,
	})
	if err != nil {
		t.Fatalf("OnOccurrenceAttached: %v", err)
	}

	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("occurrence line not valid JSON: %v (%q)", err, buf.String())
	}
	if line["kind"] != "occurrence" {
		t.Errorf("kind = %v, want occurrence", line["kind"])
	}
	if line["incident_id"] != "i1" {
		t.Errorf("incident_id = %v, want i1", line["incident_id"])
	}
	got, ok := line["occurrences"].(float64)
	if !ok || got != 8 {
		t.Errorf("occurrences = %v, want 8 (count 7 + 1)", line["occurrences"])
	}
	if line["drill"] != true {
		t.Errorf("drill = %v, want true", line["drill"])
	}
	if line["trigger"] != "cadence" {
		t.Errorf("trigger = %v, want cadence", line["trigger"])
	}
}

func TestNotify_UnverifiedCaveat(t *testing.T) {
	// Test with Unverified: true
	var buf bytes.Buffer
	n := New(&buf, nil, true)
	f := notify.Finding{
		IncidentID:   "test-incident",
		GroupKey:     "test=group",
		AnalysisName: "Test Analysis",
		Severity:     "high",
		Confidence:   0.85,
		Unverified:   true,
	}

	if err := n.Notify(context.Background(), f); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("line not valid JSON: %v (%q)", err, buf.String())
	}
	if line["caveat"] != "⚠ unverified — checks unavailable" {
		t.Errorf("caveat = %v, want '⚠ unverified — checks unavailable'", line["caveat"])
	}

	// Test with Unverified: false
	buf.Reset()
	f.Unverified = false
	if err := n.Notify(context.Background(), f); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	line = make(map[string]any) // create a new map for the second test
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("line not valid JSON: %v (%q)", err, buf.String())
	}
	if caveat, exists := line["caveat"]; exists && caveat != nil && caveat != "" {
		t.Errorf("caveat = %v, want empty/nil for verified finding", caveat)
	}
}
