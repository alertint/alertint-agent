// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/semanticprofile"
	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
)

type budgetProfileClient struct {
	started llm.RequestStartStatus
	retryAt *time.Time
	denied  bool
	calls   int
}

func (c *budgetProfileClient) CompleteOnce(context.Context, string, llm.Prompt, []string) (llm.OneShotCompletion, error) {
	c.calls++
	if c.denied {
		return llm.OneShotCompletion{RequestStarted: c.started}, errors.Join(llm.ErrRequestNotSent, &llm.BudgetDeferredError{RetryAt: c.retryAt})
	}
	raw, err := json.Marshal(profilemodel.Profile{SubjectKind: "service", EventKind: "availability", PossibleRole: "symptom", CandidateScope: []string{"service"}, HorizonTier: "hours"})
	if err != nil {
		return llm.OneShotCompletion{}, err
	}
	return llm.OneShotCompletion{RequestStarted: llm.RequestStartStatusTrue, Completion: llm.Completion{Raw: raw}}, nil
}

func TestProfileBudgetDenialPreservesAttemptAndResumesWithoutHealthRecovery(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	// A one-nanosecond fractional retry makes the just-before-boundary poll
	// deterministic; RFC3339Nano text ordering used to admit it early.
	now := time.Date(2026, 9, 7, 9, 0, 0, 1, time.UTC)
	seedPendingInferenceJob(t, st, "budget-job", "budget-signature", 1, nil, now)
	retry := now.Add(time.Hour)
	client := &budgetProfileClient{started: llm.RequestStartStatusFalse, retryAt: &retry, denied: true}
	worker := semanticprofile.NewWorker(st, client, llm.NewInferenceLimiter(1), semanticprofile.WorkerConfig{Owner: "budget-worker"}, func() time.Time { return now }, nil)
	for i := 0; i < 2; i++ {
		if n, err := worker.RunOnce(ctx); err != nil || n != 1 {
			t.Fatalf("denial handled=%d err=%v", n, err)
		}
		h, err := st.GetSemanticProfile(ctx, "budget-signature", "", 20)
		if err != nil {
			t.Fatal(err)
		}
		if h.Job == nil || h.Job.Status != "pending" || h.Job.Attempt != 0 || h.Job.RetryAt == nil || !h.Job.RetryAt.Equal(retry) || h.Job.ErrorClass == nil || *h.Job.ErrorClass != "budget_deferred" {
			t.Fatalf("denial consumed attempt or lost retry: %+v", h.Job)
		}
		if h.DispatchCount != i+1 || h.Dispatches[0].RequestStarted != "false" {
			t.Fatalf("denial ledger lost: %+v", h)
		}
		now = retry.Add(-time.Nanosecond)
		if n, err := worker.RunOnce(ctx); err != nil || n != 0 {
			t.Fatalf("retried before budget admission: %d %v", n, err)
		}
		now = retry
		retry = now.Add(time.Hour)
	}
	client.denied = false
	if n, err := worker.RunOnce(ctx); err != nil || n != 1 {
		t.Fatalf("resume handled=%d err=%v", n, err)
	}
	h, err := st.GetSemanticProfile(ctx, "budget-signature", "", 20)
	if err != nil {
		t.Fatal(err)
	}
	if h.Job.Status != "complete" || h.Job.Attempt != 1 || h.Current == nil || h.DispatchCount != 3 {
		t.Fatalf("budget expiry did not resume: %+v job=%+v", h, h.Job)
	}
	var minOrdinal, maxOrdinal, distinct, rearmed int
	if err := st.db.QueryRowContext(ctx, `SELECT MIN(attempt),MAX(attempt),COUNT(DISTINCT attempt) FROM semantic_profile_calls WHERE job_id='budget-job'`).Scan(&minOrdinal, &maxOrdinal, &distinct); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRowContext(ctx, `SELECT rearmed_generation FROM semantic_profile_inference_jobs WHERE id='budget-job'`).Scan(&rearmed); err != nil {
		t.Fatal(err)
	}
	if minOrdinal != 1 || maxOrdinal != 3 || distinct != 3 || rearmed != 0 {
		t.Fatalf("ordinals=%d..%d distinct=%d recovery=%d", minOrdinal, maxOrdinal, distinct, rearmed)
	}
}

func TestProfileBudgetWithoutRetryWaitsForOperator(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedPendingInferenceJob(t, st, "budget-hold", "budget-hold", 1, nil, now)
	client := &budgetProfileClient{started: llm.RequestStartStatusFalse, denied: true}
	worker := semanticprofile.NewWorker(st, client, llm.NewInferenceLimiter(1), semanticprofile.WorkerConfig{Owner: "budget-worker"}, func() time.Time { return now }, nil)
	if n, err := worker.RunOnce(ctx); err != nil || n != 1 {
		t.Fatalf("defer=%d %v", n, err)
	}
	now = now.Add(24 * time.Hour)
	if n, err := worker.RunOnce(ctx); err != nil || n != 0 {
		t.Fatalf("indefinite deferral spun: %d %v", n, err)
	}
	h, err := st.GetSemanticProfile(ctx, "budget-hold", "", 20)
	if err != nil {
		t.Fatal(err)
	}
	if h.Job.Status != "pending" || h.Job.Attempt != 0 || h.Job.RetryAt != nil || client.calls != 1 {
		t.Fatalf("indefinite denial: %+v calls=%d", h.Job, client.calls)
	}
}

func TestProfileBudgetSentOrUnknownDenialIsNotRefunded(t *testing.T) {
	for _, started := range []llm.RequestStartStatus{llm.RequestStartStatusTrue, llm.RequestStartStatusUnknown} {
		t.Run(string(started), func(t *testing.T) {
			st := newTestStore(t)
			ctx := context.Background()
			now := time.Now().UTC()
			seedPendingInferenceJob(t, st, "budget-ambiguous", "budget-ambiguous", 1, nil, now)
			client := &budgetProfileClient{started: started, denied: true}
			worker := semanticprofile.NewWorker(st, client, llm.NewInferenceLimiter(1), semanticprofile.WorkerConfig{Owner: "budget-worker"}, func() time.Time { return now }, nil)
			if _, err := worker.RunOnce(ctx); err != nil {
				t.Fatal(err)
			}
			h, err := st.GetSemanticProfile(ctx, "budget-ambiguous", "", 20)
			if err != nil {
				t.Fatal(err)
			}
			if h.Job.Status != "exhausted" || h.Job.Attempt != 1 {
				t.Fatalf("ambiguous request refunded: %+v", h.Job)
			}
		})
	}
}

func TestProfileBudgetRefundPreservesEarlierFailureAndCrashAccounting(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedPendingInferenceJob(t, st, "prior-failure", "prior-failure", 3, nil, now)
	claim, _, err := st.ClaimSemanticInferenceJob(ctx, "first", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	callID, _, err := st.ReserveSemanticInferenceCall(ctx, claim.JobID, claim.Owner, claim.Token, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CompleteSemanticInference(ctx, callID, claim.Owner, claim.Token, profilemodel.InferenceResult{Outcome: "failed", RequestStarted: "true"}, now, &now); err != nil {
		t.Fatal(err)
	}
	retry := now.Add(time.Hour)
	client := &budgetProfileClient{started: llm.RequestStartStatusFalse, retryAt: &retry, denied: true}
	worker := semanticprofile.NewWorker(st, client, llm.NewInferenceLimiter(1), semanticprofile.WorkerConfig{Owner: "budget-worker"}, func() time.Time { return now }, nil)
	if _, err := worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	h, err := st.GetSemanticProfile(ctx, "prior-failure", "", 20)
	if err != nil {
		t.Fatal(err)
	}
	if h.Job.Attempt != 1 {
		t.Fatalf("budget denial erased prior real failure: %+v", h.Job)
	}
	// Resume admission, then crash after the next reservation. The earlier
	// budget class must not turn crash recovery into an indefinite budget park.
	claim, found, err := st.ClaimSemanticInferenceJob(ctx, "crashing-worker", retry, time.Minute)
	if err != nil || !found {
		t.Fatalf("resume claim=%v %v", found, err)
	}
	if _, attempt, err := st.ReserveSemanticInferenceCall(ctx, claim.JobID, claim.Owner, claim.Token, retry); err != nil || attempt != 2 {
		t.Fatalf("crash reservation attempt=%d err=%v", attempt, err)
	}
	next, found, err := st.ClaimSemanticInferenceJob(ctx, "recovering-worker", retry.Add(2*time.Minute), time.Minute)
	if err != nil || !found || next.Attempt != 2 {
		t.Fatalf("crash retained stale budget park: found=%v claim=%+v err=%v", found, next, err)
	}
}

func TestProfileBudgetRefundRejectsUnprovedUsageAndOlderCalls(t *testing.T) {
	for _, mode := range []string{"usage", "older", "sent"} {
		t.Run(mode, func(t *testing.T) {
			st := newTestStore(t)
			ctx := context.Background()
			now := time.Now().UTC()
			seedPendingInferenceJob(t, st, "guarded-refund", "guarded-refund", 3, nil, now)
			claim, _, err := st.ClaimSemanticInferenceJob(ctx, "worker", now, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			callID, _, err := st.ReserveSemanticInferenceCall(ctx, claim.JobID, claim.Owner, claim.Token, now)
			if err != nil {
				t.Fatal(err)
			}
			result := profilemodel.InferenceResult{Outcome: "failed", RequestStarted: "false", BudgetDeferred: true}
			switch mode {
			case "usage":
				result.UsageInputTokens = 1
			case "sent":
				result.RequestStarted = "true"
			case "older":
				if _, _, err := st.ReserveSemanticInferenceCall(ctx, claim.JobID, claim.Owner, claim.Token, now); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := st.CompleteSemanticInference(ctx, callID, claim.Owner, claim.Token, result, now, nil); err == nil {
				t.Fatal("unproved budget refund accepted")
			}
			var outcomes int
			if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM semantic_profile_call_outcomes`).Scan(&outcomes); err != nil {
				t.Fatal(err)
			}
			if outcomes != 0 {
				t.Fatal("rejected refund left a partial outcome")
			}
		})
	}
}
