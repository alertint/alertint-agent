// SPDX-License-Identifier: FSL-1.1-ALv2

package situation_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// ewrTransitionIDs lists sitID's committed Transition ids in sequence order.
// The cursor is fully drained and closed here, before any store read: the
// store's own reads must never nest inside an open result set on the same
// single-writer SQLite handle.
func ewrTransitionIDs(t *testing.T, f *replayFixture, sitID string) []string {
	t.Helper()
	rows, err := f.st.DB().QueryContext(f.ctx, `SELECT id FROM situation_transitions WHERE situation_id = ? ORDER BY sequence ASC`, sitID)
	if err != nil {
		t.Fatalf("list transitions: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return ids
}

// ewrCandidates collects every candidate of kind across ALL of sitID's
// committed Transitions, in sequence order, read back through the store.
func ewrCandidates(t *testing.T, f *replayFixture, sitID string, kind situationmodel.CandidateKind) []situationmodel.MaterialCandidate {
	t.Helper()
	var out []situationmodel.MaterialCandidate
	for _, id := range ewrTransitionIDs(t, f, sitID) {
		tr, err := f.st.GetSituationTransition(f.ctx, id)
		if err != nil {
			t.Fatalf("get transition %s: %v", id, err)
		}
		if tr.Projection.OperatorDelta == nil {
			continue
		}
		for _, c := range tr.Projection.OperatorDelta.Candidates {
			if c.Kind == kind {
				out = append(out, c)
			}
		}
	}
	return out
}

// Lead decision D (round 2, 2026-09-09), end to end: a real Triage worker
// completes an ACCEPTED analysis that recorded checks but no root cause; the
// real controller's next cycle commits a Transition whose candidates carry
// exactly one inconclusive completion keyed on that attempt, with the
// attempt's own observations and unknowns; and neither a further
// convergence nor a restart/replay repeats it.
func TestReplayAcceptedCompletionWithoutHypothesisCommitsOneInconclusiveCandidate(t *testing.T) {
	f := newReplayFixture(t, "ew")
	incID := f.setupReadyIncidentWithRequestedTriage("ended-work-group", "HighLatency", "fp-ew")
	sitID := f.soleSituationID()

	f.clock.Advance(advanceMargin)
	analyzer := &scriptedAnalyzer{fn: func(_ context.Context, claim situation.TriageAttemptClaim) (situation.AcuteResult, error) {
		r := acceptedAcuteResult(claim.IncidentID)
		r.RootCause = ""
		r.Summary = "Checkout analysis"
		r.OutputJSON = json.RawMessage(`{"analysis_name":"Checkout analysis","correlation_findings":["Pod events checked","Application errors checked"]}`)
		r.EnrichmentJSON = `{"verification":{"outcome":"degraded","degradation_reason":"logs_source_unavailable"}}`
		return r, nil
	}}
	f.convergeAll(newAcceptingL2Client(), analyzer, &countingAfterCommitter{}, nil)
	if got := analyzer.callCount(); got != 1 {
		t.Fatalf("Analyze calls = %d, want 1", got)
	}
	if status := scalarString(t, f.st, `SELECT status FROM incidents WHERE id = ?`, incID); status != "analyzed" {
		t.Fatalf("incident status = %q, want analyzed (an accepted completion)", status)
	}
	attemptID := scalarString(t, f.st, `SELECT id FROM incident_triage_attempts WHERE incident_id = ? AND result_code = 'success'`, incID)

	inconclusive := ewrCandidates(t, f, sitID, situationmodel.CandidateInconclusiveCompletion)
	if len(inconclusive) != 1 {
		t.Fatalf("inconclusive completions across committed history = %d, want exactly 1", len(inconclusive))
	}
	c := inconclusive[0]
	if c.Outcome == nil || c.Outcome.IncidentID != incID || c.Outcome.AttemptID != attemptID || c.Outcome.ResultCode != "success" || !c.Outcome.EvidenceKnown {
		t.Fatalf("candidate provenance must name the real attempt: %+v", c.Outcome)
	}
	if c.Finding == nil || strings.Join(c.Finding.Observations, ";") != "Pod events checked;Application errors checked" || strings.Join(c.Finding.Unknowns, ";") != "logs_source_unavailable" || c.Finding.Hypothesis != "" {
		t.Fatalf("candidate must carry the attempt's own recorded checks and unknowns: %+v", c.Finding)
	}
	if c.Next.Kind == situationmodel.NextStepRetryEligible {
		t.Fatalf("no retry is scheduled after an accepted completion: %+v", c.Next)
	}
	if got := ewrCandidates(t, f, sitID, situationmodel.CandidateUsefulFinding); len(got) != 0 {
		t.Fatalf("a title without a root cause is not a useful finding: %+v", got)
	}
	assurance := ewrCandidates(t, f, sitID, situationmodel.CandidateFirstExecutionAssurance)
	if len(assurance) != 1 || assurance[0].Members == nil || assurance[0].Members.FiringCount != 1 || !assurance[0].Members.CountKnown {
		t.Fatalf("the first-execution assurance must state the known single frozen input: %+v", assurance)
	}

	// A further convergence and a restart/replay must not repeat it.
	f.clock.Advance(slowCadenceCheckpointMargin)
	f.convergeAll(newAcceptingL2Client(), newAcceptingAnalyzer(), &countingAfterCommitter{}, nil)
	f.restart()
	f.bootReplay()
	f.clock.Advance(slowCadenceCheckpointMargin)
	f.convergeAll(newAcceptingL2Client(), newAcceptingAnalyzer(), &countingAfterCommitter{}, nil)
	if got := ewrCandidates(t, f, sitID, situationmodel.CandidateInconclusiveCompletion); len(got) != 1 {
		t.Fatalf("inconclusive completions after reconverge and restart = %d, want still exactly 1", len(got))
	}
}
