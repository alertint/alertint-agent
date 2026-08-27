// SPDX-License-Identifier: FSL-1.1-ALv2

package stdout

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
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

func TestOnAnnotation_WritesJSONLine(t *testing.T) {
	var buf bytes.Buffer
	n := New(&buf, nil, false) // NOT verbose-gated: annotation lines always write
	err := n.OnAnnotation(context.Background(), notify.AnnotationEvent{
		IncidentID: "inc1", GroupKey: "service=api", Kind: "correction", Note: "not AZ outage", VerdictVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("not a JSON line: %v", err)
	}
	if got["kind"] != "annotation" || got["annotation_kind"] != "correction" {
		t.Fatalf("line: %v", got)
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

// TestNotify_InvalidQueryCaveat (Task 6): the invalid-query caveat is
// structurally distinct from the Unverified/"checks unavailable" caveat —
// it must render on its own when only queries are invalid, combine with the
// unavailable caveat (joined by "; ") when both conditions hold, and the
// structured VerificationInvalidQueries field must always survive in the
// embedded Finding JSON regardless of which caveat text is produced.
func TestNotify_InvalidQueryCaveat(t *testing.T) {
	baseFinding := func() notify.Finding {
		return notify.Finding{
			IncidentID:   "test-incident",
			GroupKey:     "test=group",
			AnalysisName: "Test Analysis",
			Severity:     "high",
			Confidence:   0.85,
		}
	}

	cases := []struct {
		name           string
		f              notify.Finding
		wantSubstrings []string
		wantAbsent     []string
	}{
		{
			name: "invalid-only",
			f: func() notify.Finding {
				f := baseFinding()
				f.VerificationInvalidQueries = 1
				return f
			}(),
			wantSubstrings: []string{"1 metrics query invalid", "not used as evidence"},
			wantAbsent:     []string{"checks unavailable"},
		},
		{
			name: "plural invalid-only",
			f: func() notify.Finding {
				f := baseFinding()
				f.VerificationInvalidQueries = 3
				return f
			}(),
			wantSubstrings: []string{"3 metrics queries invalid"},
			wantAbsent:     []string{"checks unavailable"},
		},
		{
			name: "unavailable-only",
			f: func() notify.Finding {
				f := baseFinding()
				f.Unverified = true
				return f
			}(),
			wantSubstrings: []string{"unverified — checks unavailable"},
			wantAbsent:     []string{"metrics query invalid", "metrics queries invalid"},
		},
		{
			name: "combined",
			f: func() notify.Finding {
				f := baseFinding()
				f.VerificationInvalidQueries = 2
				f.Unverified = true
				return f
			}(),
			wantSubstrings: []string{"2 metrics queries invalid", "unverified — checks unavailable"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			n := New(&buf, nil, true)
			if err := n.Notify(context.Background(), tc.f); err != nil {
				t.Fatalf("Notify: %v", err)
			}

			var l map[string]any
			if err := json.Unmarshal(buf.Bytes(), &l); err != nil {
				t.Fatalf("line not valid JSON: %v (%q)", err, buf.String())
			}
			caveat, _ := l["caveat"].(string)
			for _, want := range tc.wantSubstrings {
				if !strings.Contains(caveat, want) {
					t.Errorf("caveat = %q, missing %q", caveat, want)
				}
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(caveat, absent) {
					t.Errorf("caveat = %q, must not contain %q", caveat, absent)
				}
			}

			// Combined case must join with "; ".
			if tc.name == "combined" && !strings.Contains(caveat, "; ") {
				t.Errorf("combined caveat = %q, expected \"; \" join", caveat)
			}

			// The structured Finding field must always survive in the embedded
			// JSON, regardless of which caveat text was produced.
			finding, ok := l["finding"].(map[string]any)
			if !ok {
				t.Fatalf("finding not an object: %v", l["finding"])
			}
			gotCount, _ := finding["verification_invalid_queries"].(float64)
			if int(gotCount) != tc.f.VerificationInvalidQueries {
				t.Errorf("finding.verification_invalid_queries = %v, want %d", finding["verification_invalid_queries"], tc.f.VerificationInvalidQueries)
			}
		})
	}
}

func TestOnTriageExhausted_WritesLineAlways(t *testing.T) {
	var buf bytes.Buffer
	// verbose=false: the line is written regardless — it is the visible
	// failure signal on stdout.
	n := New(&buf, nil, false)

	err := n.OnTriageExhausted(context.Background(), notify.TriageExhaustedEvent{
		IncidentID: "i1", GroupKey: "k", AlertCount: 3, Attempts: 5,
		Error: "acutetriage: llm: connection refused",
	})
	if err != nil {
		t.Fatalf("OnTriageExhausted: %v", err)
	}

	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("triage_exhausted line not valid JSON: %v (%q)", err, buf.String())
	}
	if line["kind"] != "triage_exhausted" {
		t.Errorf("kind = %v, want triage_exhausted", line["kind"])
	}
	if line["incident_id"] != "i1" || line["group_key"] != "k" {
		t.Errorf("identity = %v/%v, want i1/k", line["incident_id"], line["group_key"])
	}
	if got, _ := line["attempts"].(float64); got != 5 {
		t.Errorf("attempts = %v, want 5", line["attempts"])
	}
	if got, _ := line["alert_count"].(float64); got != 3 {
		t.Errorf("alert_count = %v, want 3", line["alert_count"])
	}
	if line["error"] != "acutetriage: llm: connection refused" {
		t.Errorf("error = %v", line["error"])
	}
}
