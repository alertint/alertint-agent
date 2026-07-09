// SPDX-License-Identifier: FSL-1.1-ALv2

package stdout

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

func TestOnOccurrenceAttached_WritesLineAlways(t *testing.T) {
	var buf bytes.Buffer
	// verbose=false: the occurrence line is written regardless (it is the visible
	// collapse signal), unlike the verbose-gated finding line.
	n := New(&buf, nil, false)

	err := n.OnOccurrenceAttached(context.Background(),
		store.Incident{ID: "i1", GroupKey: "k"},
		store.OccurrenceStats{Count: 7, LastSeen: time.Now().UTC()}, true)
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
}
