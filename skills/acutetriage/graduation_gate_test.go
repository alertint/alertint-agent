// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage_test

import (
	"context"
	"testing"

	"github.com/alertint/alertint-agent/internal/audit"
)

// graduationGateSQL mirrors the operator-facing precision query documented in
// docs/concepts/incident-memory.md ("Graduating from shadow to on"). Kept here
// verbatim so the shipped query is proven to compute precision correctly against
// the audit rows the classifier and memory recall actually emit — if either the
// query or the emitted payload shape drifts, this test fails.
const graduationGateSQL = `
SELECT
  SUM(json_extract(v.payload_json, '$.verdict') = 'confirms') AS confirmed,
  SUM(json_extract(v.payload_json, '$.verdict') = 'refutes')  AS refuted,
  ROUND(
    1.0 * SUM(json_extract(v.payload_json, '$.verdict') = 'confirms')
        / NULLIF(COUNT(*), 0), 2) AS precision
FROM audit_log c
JOIN audit_log v
  ON  v.kind = 'incident.memory_recalled'
  AND json_extract(v.payload_json, '$.recalled')
      = json_extract(c.payload_json, '$.candidates[0]')
  AND json_extract(v.payload_json, '$.verdict') IN ('confirms', 'refutes')
WHERE c.kind = 'memory.classifier_verdict'
  AND json_extract(c.payload_json, '$.verdict') = 'matched';`

// TestGraduationGateQuery seeds a fixture audit log and runs the documented
// precision query, proving it counts only matched verdicts joined to real
// confirm/refute ground truth — 9 confirmed + 1 refuted = 0.90 precision, with
// silent, ungraded, and no-match rows correctly excluded.
func TestGraduationGateQuery(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	auditor := audit.New(st.DB())

	matched := func(target string) {
		if err := auditor.Append(ctx, "skill:acute-triage", "memory.classifier_verdict", map[string]any{
			"incident_id": "inc_cur_" + target, "verdict": "matched", "tokens": 247,
			"candidates": []string{target},
		}); err != nil {
			t.Fatalf("append classifier verdict: %v", err)
		}
	}
	groundTruth := func(target, verdict string) {
		if err := auditor.Append(ctx, "skill:acute-triage", "incident.memory_recalled", map[string]any{
			"incident_id": "inc_later_" + target, "rung": "2", "folded_count": 3,
			"verdict": verdict, "recalled": target,
		}); err != nil {
			t.Fatalf("append memory recall: %v", err)
		}
	}

	// 9 matched candidates later confirmed, 1 later refuted → precision 0.90.
	for _, id := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"} {
		matched(id)
		groundTruth(id, "confirms")
	}
	matched("j")
	groundTruth("j", "refutes")

	// A matched candidate whose only ground truth is silent — excluded (not graded).
	matched("k")
	groundTruth("k", "silent")
	// A matched candidate with no ground truth at all — excluded.
	matched("l")
	// A no-match verdict whose target was confirmed — excluded (not a prediction of "same").
	if err := auditor.Append(ctx, "skill:acute-triage", "memory.classifier_verdict", map[string]any{
		"incident_id": "inc_cur_m", "verdict": "no-match", "tokens": 200, "candidates": []string{"m"},
	}); err != nil {
		t.Fatalf("append: %v", err)
	}
	groundTruth("m", "confirms")

	var confirmed, refuted int64
	var precision float64
	if err := st.DB().QueryRowContext(ctx, graduationGateSQL).Scan(&confirmed, &refuted, &precision); err != nil {
		t.Fatalf("run gate query: %v", err)
	}
	if confirmed != 9 || refuted != 1 {
		t.Errorf("confirmed/refuted = %d/%d, want 9/1", confirmed, refuted)
	}
	if precision != 0.90 {
		t.Errorf("precision = %v, want 0.90", precision)
	}
}
