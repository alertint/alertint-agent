// SPDX-License-Identifier: FSL-1.1-ALv2

package situation_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/situation"
)

// TestControllerRealStoreSemaphoreWaitExpiryRecordsRequestNotStarted is the
// real-store regression for a known pre-request cancellation: two due
// Situations, one L2 semaphore slot, and a first call that holds the slot
// past the second cycle's attempt wall. The second call is canceled while
// still WAITING for the slot — no request was ever attempted — and its
// consumed dispatch slot must still land durably as a "failed" outcome row
// with provider_request_started = 'false' (the store's CHECK admits only
// true/false/unknown; the zero value "" used to be rejected, and with a
// canceled context the row used to be lost entirely). The audit event for
// that outcome follows the durable write and carries the same value.
func TestControllerRealStoreSemaphoreWaitExpiryRecordsRequestNotStarted(t *testing.T) {
	f := newReplayFixture(t, "sem-owner")
	defer f.close()

	f.postGroup("sem-a", "HighLatency", "fp-sem-a")
	f.postGroup("sem-b", "HighLatency", "fp-sem-b")
	f.drainFoundation()
	if n := scalarInt(t, f.st, `SELECT COUNT(*) FROM situations`); n != 2 {
		t.Fatalf("situations = %d, want 2", n)
	}

	held := make(chan struct{}, 1)
	release := make(chan struct{})
	var mu sync.Mutex
	calls := 0
	client := &fakeAssessmentClient{ctxFn: func(ctx context.Context) (llm.OneShotCompletion, error) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n == 1 {
			held <- struct{}{}
			<-release // hold the only slot, ignoring ctx, until the test lets go
		}
		return llm.OneShotCompletion{RequestStarted: llm.RequestStartStatusUnknown}, errors.New("dial tcp: connection refused")
	}}

	// Same one-minute step convergeAll takes before every controller round:
	// a fresh Situation's first checkpoint is strictly after the "now" its
	// input was applied at.
	f.clock.Advance(advanceMargin)
	auditor := audit.New(f.st.DB())
	cw := situation.NewControllerWorker(f.st, f.st, client,
		situation.ControllerConfig{AttemptWall: time.Second},
		situation.ControllerWorkerConfig{Owner: "sem-owner:controller", Now: f.clock.Now, Workers: 2, Batch: 2, L2Concurrency: 1},
		f.clock.Now, auditor, nil)

	drainDone := make(chan error, 1)
	go func() {
		_, err := cw.Drain(f.ctx)
		drainDone <- err
	}()

	select {
	case <-held:
	case err := <-drainDone:
		t.Fatalf("Drain finished before any call reached the provider client (err=%v; situations due=%d)", err,
			scalarInt(t, f.st, `SELECT COUNT(*) FROM situations WHERE lease_owner IS NULL`))
	case <-time.After(10 * time.Second):
		t.Fatal("the first call never reached the provider client")
	}

	// The second cycle's own attempt wall (1s) expires while its call is
	// still waiting for the slot the first call holds.
	const q = `SELECT COUNT(*) FROM situation_assessment_attempts WHERE status = 'failed' AND provider_request_started = 'false'`
	deadline := time.Now().Add(15 * time.Second)
	for scalarInt(t, f.st, q) == 0 {
		if time.Now().After(deadline) {
			close(release)
			t.Fatal("no failed outcome row with provider_request_started='false' appeared for the semaphore-wait expiry")
		}
		time.Sleep(20 * time.Millisecond)
	}
	close(release)
	select {
	case err := <-drainDone:
		if err != nil {
			t.Fatalf("Drain: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Drain did not finish")
	}

	mu.Lock()
	gotCalls := calls
	mu.Unlock()
	if gotCalls != 1 {
		t.Fatalf("provider client calls = %d, want exactly 1 — the semaphore-canceled call must never reach the provider", gotCalls)
	}
	if n := scalarInt(t, f.st, q); n != 1 {
		t.Fatalf("failed rows with provider_request_started='false' = %d, want 1", n)
	}
	if n := scalarInt(t, f.st, `SELECT COUNT(*) FROM situation_assessment_attempts WHERE status = 'failed' AND provider_request_started = 'unknown'`); n != 1 {
		t.Fatalf("failed rows with provider_request_started='unknown' (the held call's own real outcome) = %d, want 1", n)
	}
	if n := scalarInt(t, f.st, `SELECT COUNT(*) FROM situation_assessment_calls`); n != 2 {
		t.Fatalf("dispatched call rows = %d, want 2 (one consumed slot per Situation)", n)
	}
	// Every call row has its outcome recorded — nothing left for crash
	// recovery to misread as an interrupted call.
	if n := scalarInt(t, f.st, `SELECT COUNT(*) FROM situation_assessment_calls c WHERE NOT EXISTS (SELECT 1 FROM situation_assessment_attempts a WHERE a.call_id = c.id)`); n != 0 {
		t.Fatalf("call rows without an outcome row = %d, want 0", n)
	}
	failedAudits := scalarInt(t, f.st, `SELECT COUNT(*) FROM audit_log WHERE kind = 'situation.assessment_failed' AND payload_json LIKE '%"provider_request_started":"false"%'`)
	if failedAudits != 1 {
		t.Fatalf("situation.assessment_failed audit rows carrying provider_request_started=false = %d, want 1", failedAudits)
	}
}
