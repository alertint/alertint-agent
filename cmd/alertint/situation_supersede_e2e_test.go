// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"bytes"
	"context"
	"database/sql"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/correlator"
	"github.com/alertint/alertint-agent/internal/llm"
	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/situation"
)

// supersedeE2ELLM holds each armed L2 call until the test has applied an
// input. The baseline call is ungated so it can establish an assessment.
type supersedeE2ELLM struct {
	base    e2eAssessmentClient
	armed   bool
	inCall  chan struct{}
	release chan struct{}
}

func (c *supersedeE2ELLM) CompleteOnce(ctx context.Context, systemPrompt string, prompt llm.Prompt, stop []string) (llm.OneShotCompletion, error) {
	if c.armed {
		select {
		case c.inCall <- struct{}{}:
		case <-ctx.Done():
			return llm.OneShotCompletion{}, ctx.Err()
		}
		select {
		case <-c.release:
		case <-ctx.Done():
			return llm.OneShotCompletion{}, ctx.Err()
		}
	}
	return c.base.CompleteOnce(ctx, systemPrompt, prompt, stop)
}

func supersedeAssessmentID(t *testing.T, f *prepE2EFixture) sql.NullString {
	t.Helper()
	var id sql.NullString
	if err := f.st.DB().QueryRowContext(f.ctx, `SELECT current_assessment_id FROM situations WHERE id = ?`, f.soleSituationID()).Scan(&id); err != nil {
		t.Fatalf("read current assessment: %v", err)
	}
	return id
}

func drainSupersedeFoundation(f *prepE2EFixture) {
	drainSupersedeFoundationWithPreempter(f, nil)
}

func drainSupersedeFoundationWithPreempter(f *prepE2EFixture, preempter situation.Preempter) {
	f.t.Helper()
	cor := correlator.New(correlator.Config{WindowSeconds: 60}, f.st, nil, nil)
	dispatch := correlator.NewDispatchWorker(f.st, cor, correlator.WorkerConfig{Owner: f.owner + ":dispatch"}, nil)
	inputs := situation.NewInputWorker(f.st, situation.WorkerConfig{Owner: f.owner + ":input", Now: f.clock.Now}, nil)
	inputs.SetPreempter(preempter)
	if _, err := dispatch.Drain(f.ctx); err != nil {
		f.t.Fatalf("dispatch drain: %v", err)
	}
	if _, err := inputs.Drain(f.ctx); err != nil {
		f.t.Fatalf("input drain: %v", err)
	}
}

type supersedeE2EPreparer struct {
	armed   bool
	entered chan struct{}
	release chan struct{}
}

func (p *supersedeE2EPreparer) Prepare(ctx context.Context, req situation.PreparationRequest) (situation.PreparedState, error) {
	if !p.armed || req.Phase != observationmodel.PhaseLifecycle {
		return situation.PreparedState{}, nil
	}
	select {
	case p.entered <- struct{}{}:
	case <-ctx.Done():
		return situation.PreparedState{}, ctx.Err()
	}
	select {
	case <-p.release:
		return situation.PreparedState{}, nil
	case <-ctx.Done():
		return situation.PreparedState{}, ctx.Err()
	}
}

func TestControllerInputDuringPreparationPreemptsRun(t *testing.T) {
	f := newPrepE2EFixture(t)
	client := &supersedeE2ELLM{inCall: make(chan struct{}), release: make(chan struct{})}
	preparer := &supersedeE2EPreparer{entered: make(chan struct{}), release: make(chan struct{})}
	cw := situation.NewControllerWorker(f.st, f.st, client,
		situation.ControllerConfig{}, situation.ControllerWorkerConfig{Owner: f.owner + ":controller", Now: f.clock.Now},
		f.clock.Now, audit.New(f.st.DB()), slog.New(slog.DiscardHandler))
	cw.SetEvidencePreparer(preparer)

	f.postAlert("preempt-e2e", "HighErrorRate", "fp-0")
	drainSupersedeFoundation(f)
	f.markReady(f.soleIncidentID())
	if _, err := cw.Drain(f.ctx); err != nil {
		t.Fatalf("baseline controller drain: %v", err)
	}
	baseline := supersedeAssessmentID(t, f)
	if !baseline.Valid {
		t.Fatal("baseline assessment was not committed")
	}
	preparer.armed = true
	f.postAlert("preempt-e2e", "HighErrorRate", "fp-1")
	drainSupersedeFoundation(f)
	f.clock.advance(time.Second)
	beforeCalls := client.base.callCount()
	done := make(chan error, 1)
	go func() {
		_, err := cw.RunOnce(f.ctx)
		done <- err
	}()
	select {
	case <-preparer.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("controller run did not reach preparation")
	}

	f.postAlert("preempt-e2e", "HighErrorRate", "fp-2")
	drainSupersedeFoundationWithPreempter(f, cw)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("superseded RunOnce: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("preparation was not preempted promptly")
	}
	preparer.armed = false
	if calls := client.base.callCount(); calls != beforeCalls {
		t.Fatalf("preempted preparation spent %d L2 calls, want 0", calls-beforeCalls)
	}
	if current := supersedeAssessmentID(t, f); current != baseline {
		t.Fatalf("superseded run changed assessment from %v to %v", baseline, current)
	}
	f.clock.advance(time.Second)
	if _, err := cw.RunOnce(f.ctx); err != nil {
		t.Fatalf("next claim: %v", err)
	}
	if current := supersedeAssessmentID(t, f); !current.Valid || current == baseline {
		t.Fatalf("next claim did not commit: baseline=%v current=%v", baseline, current)
	}
}

func TestControllerInputDuringL2IsHeldUntilCommit(t *testing.T) {
	f := newPrepE2EFixture(t)
	client := &supersedeE2ELLM{inCall: make(chan struct{}), release: make(chan struct{})}
	cw := situation.NewControllerWorker(f.st, f.st, client,
		situation.ControllerConfig{}, situation.ControllerWorkerConfig{Owner: f.owner + ":controller", Now: f.clock.Now},
		f.clock.Now, audit.New(f.st.DB()), slog.New(slog.DiscardHandler))

	f.postAlert("supersede-e2e", "HighErrorRate", "fp-0")
	drainSupersedeFoundation(f)
	f.markReady(f.soleIncidentID())
	if _, err := cw.Drain(f.ctx); err != nil {
		t.Fatalf("baseline controller drain: %v", err)
	}
	baseline := supersedeAssessmentID(t, f)
	if !baseline.Valid || client.base.callCount() == 0 {
		t.Fatalf("baseline assessment = %v, L2 calls = %d; want committed L2 baseline", baseline, client.base.callCount())
	}
	client.armed = true

	// The baseline is no longer due. A fresh input makes round one claimable.
	f.postAlert("supersede-e2e", "HighErrorRate", "fp-1")
	drainSupersedeFoundation(f)
	f.clock.advance(time.Second)
	beforeCalls := client.base.callCount()
	result := make(chan error, 1)
	go func() { _, err := cw.RunOnce(f.ctx); result <- err }()
	select {
	case <-client.inCall:
	case <-time.After(10 * time.Second):
		t.Fatal("controller round 2 did not reach L2")
	}
	before, err := f.st.GetSituation(f.ctx, f.soleSituationID())
	if err != nil {
		t.Fatal(err)
	}
	f.postAlert("supersede-e2e", "HighErrorRate", "fp-2")
	drainSupersedeFoundationWithPreempter(f, cw)
	during, err := f.st.GetSituation(f.ctx, f.soleSituationID())
	if err != nil {
		t.Fatal(err)
	}
	if during.InputVersion != before.InputVersion || !during.LeaseProtected {
		t.Fatalf("during L2: version=%d protected=%v, want version %d protected", during.InputVersion, during.LeaseProtected, before.InputVersion)
	}
	var pending int
	if err := f.st.DB().QueryRowContext(f.ctx, `SELECT COUNT(*) FROM situation_input_outbox WHERE status = 'pending'`).Scan(&pending); err != nil || pending != 1 {
		t.Fatalf("held pending inputs = (%d, %v), want 1", pending, err)
	}
	select {
	case client.release <- struct{}{}:
	case <-time.After(10 * time.Second):
		t.Fatal("controller did not accept L2 release")
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("controller round 2: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("controller round 2 did not finish")
	}
	current := supersedeAssessmentID(t, f)
	if !current.Valid || current == baseline {
		t.Fatalf("round 2 did not commit: baseline=%v current=%v", baseline, current)
	}
	if calls := client.base.callCount(); calls != beforeCalls+1 {
		t.Fatalf("round 2 L2 calls = %d, want 1", calls-beforeCalls)
	}
	f.clock.advance(time.Second)
	drainSupersedeFoundation(f)
	after, err := f.st.GetSituation(f.ctx, f.soleSituationID())
	if err != nil {
		t.Fatal(err)
	}
	if after.InputVersion != before.InputVersion+1 {
		t.Fatalf("held input version after drain = %d, want %d", after.InputVersion, before.InputVersion+1)
	}
	if len(after.DueReasons) == 0 {
		t.Fatal("held input did not make Situation due again")
	}
}

func TestControllerGuardStillProtectsFromClaim(t *testing.T) {
	f := newPrepE2EFixture(t)
	client := &supersedeE2ELLM{inCall: make(chan struct{}), release: make(chan struct{})}
	preparer := &supersedeE2EPreparer{armed: true, entered: make(chan struct{}), release: make(chan struct{})}
	var logs bytes.Buffer
	cw := situation.NewControllerWorker(f.st, f.st, client,
		situation.ControllerConfig{}, situation.ControllerWorkerConfig{Owner: f.owner + ":controller", Now: f.clock.Now},
		f.clock.Now, audit.New(f.st.DB()), slog.New(slog.NewJSONHandler(&logs, nil)))
	cw.SetEvidencePreparer(preparer)

	f.postAlert("guard-e2e", "HighErrorRate", "fp-0")
	drainSupersedeFoundation(f)
	f.markReady(f.soleIncidentID())
	// Let the initial call establish a baseline without a gated preparation.
	preparer.armed = false
	if _, err := cw.Drain(f.ctx); err != nil {
		t.Fatalf("baseline drain: %v", err)
	}
	baselineCalls := client.base.callCount()
	preparer.armed = true
	f.postAlert("guard-e2e", "HighErrorRate", "fp-1")
	drainSupersedeFoundation(f)
	f.clock.advance(time.Second)
	for round := 1; round <= 2; round++ {
		done := make(chan error, 1)
		go func() { _, err := cw.RunOnce(f.ctx); done <- err }()
		select {
		case <-preparer.entered:
		case <-time.After(10 * time.Second):
			t.Fatalf("round %d did not reach preparation", round)
		}
		f.postAlert("guard-e2e", "HighErrorRate", "fp-"+strconv.Itoa(round+1))
		drainSupersedeFoundationWithPreempter(f, cw)
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("round %d was not preempted", round)
		}
		f.clock.advance(time.Second)
	}
	before, err := f.st.GetSituation(f.ctx, f.soleSituationID())
	if err != nil {
		t.Fatal(err)
	}
	if before.SupersedeStreak != 2 {
		t.Fatalf("supersede streak = %d, want 2", before.SupersedeStreak)
	}
	beforeAssessment := supersedeAssessmentID(t, f)
	done := make(chan error, 1)
	go func() { _, err := cw.RunOnce(f.ctx); done <- err }()
	select {
	case <-preparer.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("guarded round did not reach preparation")
	}
	f.postAlert("guard-e2e", "HighErrorRate", "fp-4")
	drainSupersedeFoundationWithPreempter(f, cw)
	during, err := f.st.GetSituation(f.ctx, f.soleSituationID())
	if err != nil {
		t.Fatal(err)
	}
	if during.InputVersion != before.InputVersion || !during.LeaseProtected {
		t.Fatalf("claim guard during preparation: version=%d protected=%v, want %d true", during.InputVersion, during.LeaseProtected, before.InputVersion)
	}
	select {
	case preparer.release <- struct{}{}:
	case <-time.After(10 * time.Second):
		t.Fatal("guarded preparation did not accept release")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("guarded round: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("guarded round did not finish")
	}
	if calls := client.base.callCount(); calls != baselineCalls+1 {
		t.Fatalf("guarded L2 calls = %d, want 1", calls-baselineCalls)
	}
	guardedAssessment := supersedeAssessmentID(t, f)
	if !guardedAssessment.Valid || guardedAssessment == beforeAssessment {
		t.Fatalf("guarded run did not commit: before=%v after=%v", beforeAssessment, guardedAssessment)
	}
	if !strings.Contains(logs.String(), `"protected_from":"claim"`) {
		t.Fatal("guarded run did not log protected_from=claim")
	}
	f.clock.advance(time.Second)
	drainSupersedeFoundation(f)
	after, err := f.st.GetSituation(f.ctx, f.soleSituationID())
	if err != nil {
		t.Fatal(err)
	}
	if after.InputVersion != before.InputVersion+1 {
		t.Fatalf("held input version = %d, want %d", after.InputVersion, before.InputVersion+1)
	}
}
