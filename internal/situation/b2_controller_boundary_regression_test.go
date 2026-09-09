// SPDX-License-Identifier: FSL-1.1-ALv2

// package situation_test — see controller_replay_test.go's own header for
// the import-cycle constraint that forces every real-Store replay fixture in
// this package to live here rather than in an internal (package situation)
// test file.
//
// R6 repair (lead review round 2, 2026-09-09) and its round-3 follow-up
// requested this coverage be retained as a repository regression rather
// than only exist as the lead's own saved review overlay
// (evaluation/lead-b2-round2-2026-09-09/boundary_test.go): the real
// controller's backoff/scope persistence, an assessment-retry boundary that
// must not fabricate acute-triage execution, and a same-commit crash-split
// skip's truthful WorkProjection. Equivalent in intent and fixture usage to
// the lead's saved probes; renamed to this file's own convention rather than
// the lead's "TestLeadB2Round2..." names, which name the review round that
// authored them, not this repository's own regression suite.

package situation_test

import (
	"errors"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// TestB2ControllerBackoffRetainsScopeAndDue proves a real controller-driven
// backoff persists BOTH the actual due instant and the actual investigated
// scope (never guessed from display text, B0 integration contract §3), and
// that the durable schedule phase agrees.
func TestB2ControllerBackoffRetainsScopeAndDue(t *testing.T) {
	f := newReplayFixture(t, "b2-controller-backoff")
	defer f.close()
	iid := f.setupReadyIncidentWithRequestedTriage("b2-controller-backoff", "HighLatency", "b2-controller-backoff-fp")
	sid := f.soleSituationID()
	claim, err := f.st.ClaimIncidentTriageAttempt(f.ctx, iid, "b2-regression", f.clock.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	due := f.clock.Now().Add(time.Hour)
	if err := f.st.BackoffIncidentTriageAttempt(f.ctx, claim.AttemptID, iid, due, "timeout", "local fixture", f.clock.Now()); err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(time.Second)
	f.oneControllerDrainPass(newAcceptingL2Client())

	v, err := f.st.GetSituationEpisodeView(f.ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	if v.Summary.Briefing == nil {
		t.Fatal("no persisted briefing")
	}
	work := v.Summary.Briefing.Work
	if work.Phase != model.WorkPhaseRetryWait || work.RetryEligibleAt == nil || !work.RetryEligibleAt.Equal(due) {
		t.Fatalf("wrong persisted retry: %+v", work)
	}
	if !work.ExecutionStarted || len(work.InvestigatedNames) != 1 || work.InvestigatedNames[0] != "HighLatency" {
		t.Fatalf("lost actual input scope: %+v", work)
	}
	if phase := scalarString(t, f.st, `SELECT phase FROM incident_triage WHERE incident_id=?`, iid); phase != "backoff" {
		t.Fatalf("persisted phase=%s", phase)
	}
}

// TestB2AssessmentRetryDoesNotFabricateExecution proves a Situation-level
// Assessment retry boundary (a transport failure re-arming
// situations.retry_at) persists that retry without ExecutionStarted ever
// reading true — an Assessment attempt is not an acute-triage execution.
func TestB2AssessmentRetryDoesNotFabricateExecution(t *testing.T) {
	f := newReplayFixture(t, "b2-assessment-retry")
	defer f.close()
	sid := f.setupDueSituation("b2-assessment-retry", "HighLatency", "b2-assessment-retry-fp")
	client := &scriptedL2Client{fn: func(int) (llm.OneShotCompletion, error) {
		return llm.OneShotCompletion{RequestStarted: llm.RequestStartStatusUnknown}, errors.New("local simulated transport failure")
	}}
	f.clock.Advance(advanceMargin)
	cw := situation.NewControllerWorker(f.st, f.st, client, situation.ControllerConfig{}, situation.ControllerWorkerConfig{Owner: "b2-regression", Now: f.clock.Now}, f.clock.Now, nil, nil)
	if _, err := cw.Drain(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := scalarNullableString(t, f.st, `SELECT last_error_class FROM situations WHERE id=?`, sid); got != "transport_failure" {
		t.Fatalf("unexpected outcome: %s", got)
	}
	raw := scalarNullableString(t, f.st, `SELECT retry_at FROM situations WHERE id=?`, sid)
	if raw == "" {
		t.Fatal("no persisted assessment retry")
	}
	due, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.st.GetSituationEpisodeView(f.ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	if v.Summary.Briefing == nil {
		t.Fatal("no persisted briefing")
	}
	work := v.Summary.Briefing.Work
	if work.RetryEligibleAt == nil || !work.RetryEligibleAt.Equal(due) {
		t.Fatalf("lost assessment retry: %+v", work)
	}
	if work.ExecutionStarted {
		t.Fatal("assessment attempt fabricated acute investigation execution")
	}
}

// TestB2SameCommitCrashSkipProjectionIsTruthful proves a controller crash
// strictly after commit, replayed against the "investigation" history
// scenario, settles into a truthful coverage-reuse skip: no remaining work,
// the actual "prior_coverage" reason, and ExecutionStarted false (a
// pre-claim clean skip consumes no attempt).
func TestB2SameCommitCrashSkipProjectionIsTruthful(t *testing.T) {
	f := newHistoryFixture(t, "b2-same-commit-skip", crashPointCommitControllerAfterCommit, false)
	defer f.close()
	scenarioInvestigation().run(f)
	sid := scalarString(t, f.st, `SELECT id FROM situations WHERE group_key='group=hist-investigation' ORDER BY created_at DESC,id DESC LIMIT 1`)
	v, err := f.st.GetSituationEpisodeView(f.ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	if v.Summary.Briefing == nil {
		t.Fatal("no persisted briefing")
	}
	work := v.Summary.Briefing.Work
	if work.Phase != model.WorkPhaseSettled || work.RemainingIncidents != 0 || work.SkipReason != "prior_coverage" || work.ExecutionStarted {
		t.Fatalf("untruthful skipped projection: %+v", work)
	}
}
