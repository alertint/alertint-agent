// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"database/sql"
	"log/slog"
	"strconv"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/correlator"
	"github.com/alertint/alertint-agent/internal/llm"
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
	f.t.Helper()
	cor := correlator.New(correlator.Config{WindowSeconds: 60}, f.st, nil, nil)
	dispatch := correlator.NewDispatchWorker(f.st, cor, correlator.WorkerConfig{Owner: f.owner + ":dispatch"}, nil)
	inputs := situation.NewInputWorker(f.st, situation.WorkerConfig{Owner: f.owner + ":input", Now: f.clock.Now}, nil)
	if _, err := dispatch.Drain(f.ctx); err != nil {
		f.t.Fatalf("dispatch drain: %v", err)
	}
	if _, err := inputs.Drain(f.ctx); err != nil {
		f.t.Fatalf("input drain: %v", err)
	}
}

func TestControllerSupersedeStreakStillCommits(t *testing.T) {
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
	committedRound := 0
	for round := 2; round <= 5; round++ {
		result := make(chan error, 1)
		go func() {
			_, err := cw.RunOnce(f.ctx)
			result <- err
		}()
		select {
		case <-client.inCall:
		case <-time.After(10 * time.Second):
			t.Fatal("controller round did not reach L2")
		}
		f.postAlert("supersede-e2e", "HighErrorRate", "fp-"+strconv.Itoa(round))
		drainSupersedeFoundation(f)
		f.clock.advance(time.Second)
		select {
		case client.release <- struct{}{}:
		case <-time.After(10 * time.Second):
			t.Fatal("controller round did not accept L2 release")
		}
		select {
		case err := <-result:
			if err != nil {
				t.Fatalf("controller round %d: %v", round, err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("controller round did not finish")
		}
		current := supersedeAssessmentID(t, f)
		if current.Valid && current.String != baseline.String {
			committedRound = round
			break
		}
	}
	if committedRound != 4 {
		t.Fatalf("first protected commit after two supersedes: round = %d, want 4", committedRound)
	}
	before, err := f.st.GetSituation(f.ctx, f.soleSituationID())
	if err != nil {
		t.Fatal(err)
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
}
