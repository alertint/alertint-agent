// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/llm/openaicompat"
	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

func TestControllerBudgetDeferralResumesWithoutSpendingAttempts(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "budget-resume.db")
	st, err := openTestStoreWithMigrations(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	id := seedReconcileSituation(t, st, "budget-resume", now.Add(-2*time.Hour))
	denied := func() (llm.OneShotCompletion, error) {
		retryAt := now.Add(time.Hour)
		return llm.OneShotCompletion{RequestStarted: llm.RequestStartStatusFalse}, fmt.Errorf("%w: %w", llm.ErrRequestNotSent, &llm.BudgetDeferredError{RetryAt: &retryAt, Message: "rolling-hour ceiling"})
	}
	client := &scriptedAssessmentClient{responses: []func() (llm.OneShotCompletion, error){denied, denied, denied, denied, denied, acceptedProposalResponse(t)}}
	controller := situation.NewController(st, client, situation.ControllerConfig{}, func() time.Time { return now }, nil, nil)
	for i := range 5 {
		claim := claimSituation(t, st, id, "budget-resume", now)
		if err := controller.Reconcile(ctx, claim); err != nil {
			t.Fatal(err)
		}
		assertBudgetWorkAttempts(t, st, id, 0)
		deadline := now.Add(time.Hour)
		sit := getSituationByID(t, st, id)
		if sit.RetryAt == nil || !sit.RetryAt.Equal(deadline) {
			t.Fatalf("retry at = %v, want %v", sit.RetryAt, deadline)
		}
		// Forced early checkpoints must preserve the deadline and never
		// invoke inference just to rediscover the same admission denial.
		now = now.Add(2 * time.Minute)
		forceBudgetCheckpoint(t, st, id, now)
		claim = claimSituation(t, st, id, "budget-early", now)
		if err := controller.Reconcile(ctx, claim); err != nil {
			t.Fatal(err)
		}
		if client.calls != i+1 {
			t.Fatalf("early checkpoint called inference: calls=%d, want %d", client.calls, i+1)
		}
		assertBudgetWorkAttempts(t, st, id, 0)
		if i == 0 {
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			st, err = openTestStoreWithMigrations(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := st.RecoverInterruptedAssessmentCalls(ctx, now); err != nil {
				t.Fatal(err)
			}
			controller = situation.NewController(st, client, situation.ControllerConfig{}, func() time.Time { return now }, nil, nil)
		}
		now = deadline
	}
	claim := claimSituation(t, st, id, "budget-available", now)
	if err := controller.Reconcile(ctx, claim); err != nil {
		t.Fatal(err)
	}
	if client.calls != 6 {
		t.Fatalf("expired budget stayed parked: calls=%d, want 6", client.calls)
	}
	assertBudgetWorkAttempts(t, st, id, 1)
	if sit := getSituationByID(t, st, id); sit.RetryAt != nil || sit.LastErrorClass != nil {
		t.Fatalf("successful resumption retained deferral: %+v", sit)
	}
}

func forceBudgetCheckpoint(t *testing.T, st *Store, id string, now time.Time) {
	t.Helper()
	if _, err := st.db.ExecContext(context.Background(), `UPDATE situations SET next_assessment_at = ? WHERE id = ?`, canonicalTime(now), id); err != nil {
		t.Fatal(err)
	}
}

func assertBudgetWorkAttempts(t *testing.T, st *Store, id string, want int) {
	t.Helper()
	var got int
	if err := st.db.QueryRowContext(context.Background(), `SELECT controller_work_attempts FROM situations WHERE id = ?`, id).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("controller work attempts = %d, want %d", got, want)
	}
}

type assessmentBudgetTransport func(*http.Request) (*http.Response, error)

func (f assessmentBudgetTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type budgetGuardAssessmentClient struct {
	transport http.RoundTripper
	calls     int
}

func (c *budgetGuardAssessmentClient) CompleteOnce(ctx context.Context, _ string, _ llm.Prompt, _ []string) (llm.OneShotCompletion, error) {
	c.calls++
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://provider.invalid", strings.NewReader(`{"max_tokens":100}`))
	if err != nil {
		return llm.OneShotCompletion{}, err
	}
	resp, err := c.transport.RoundTrip(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	return llm.OneShotCompletion{RequestStarted: llm.ClassifyRequestStart(err)}, err
}

func TestControllerBudgetUnknownUsageRequiresManualRecovery(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "budget-unknown.db")
	st, err := openTestStoreWithMigrations(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	id := seedReconcileSituation(t, st, "budget-unknown", now.Add(-2*time.Hour))
	providerCalls := 0
	provider := assessmentBudgetTransport(func(r *http.Request) (*http.Response, error) {
		providerCalls++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})
	client := &budgetGuardAssessmentClient{transport: llm.NewBudget(st, llm.BudgetLimits{TotalTokens: 10000}).Transport(provider)}
	// An earlier workload receives no usage; the real shared guard latches
	// unknown durably before the Situation tries to infer anything.
	if _, err := client.CompleteOnce(ctx, "", llm.Prompt{}, nil); !errors.Is(err, llm.ErrBudgetUsageUnknown) {
		t.Fatalf("seed unknown usage: %v", err)
	}
	controller := situation.NewController(st, client, situation.ControllerConfig{}, func() time.Time { return now }, nil, nil)
	claim := claimSituation(t, st, id, "budget-unknown", now)
	if err := controller.Reconcile(ctx, claim); err != nil {
		t.Fatal(err)
	}
	assertBudgetWorkAttempts(t, st, id, 0)
	if sit := getSituationByID(t, st, id); sit.RetryAt != nil {
		t.Fatalf("manual block has automatic retry: %v", sit.RetryAt)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = openTestStoreWithMigrations(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.RecoverInterruptedAssessmentCalls(ctx, now); err != nil {
		t.Fatal(err)
	}
	client.transport = llm.NewBudget(st, llm.BudgetLimits{TotalTokens: 20000}).Transport(provider)
	controller = situation.NewController(st, client, situation.ControllerConfig{}, func() time.Time { return now }, nil, nil)
	for i := range 6 {
		now = now.Add(time.Hour)
		if n, err := st.WakeDependencyRecoveredSituations(ctx, int64(i+1), now); err != nil || n != 0 {
			t.Fatalf("dependency recovery woke manual budget park: n=%d err=%v", n, err)
		}
		forceBudgetCheckpoint(t, st, id, now)
		claim = claimSituation(t, st, id, "budget-still-unknown", now)
		if err := controller.Reconcile(ctx, claim); err != nil {
			t.Fatal(err)
		}
		assertBudgetWorkAttempts(t, st, id, 0)
		if sit := getSituationByID(t, st, id); sit.RetryAt != nil {
			t.Fatalf("manual block gained retry at %v", sit.RetryAt)
		}
	}
	if client.calls != 2 || providerCalls != 1 {
		t.Fatalf("manual block auto-retried: client=%d provider=%d", client.calls, providerCalls)
	}
}

func TestControllerBudget429RetriesWithoutCorrectionOrPark(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	id := seedReconcileSituation(t, st, "budget-429", now.Add(-2*time.Hour))
	proposal, err := acceptedProposalResponse(t)()
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{
		"choices": []map[string]any{{"message": map[string]any{"content": string(proposal.Raw)}, "finish_reason": "stop"}},
		"usage":   map[string]int{"prompt_tokens": 2, "completion_tokens": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	providerCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalls++
		if providerCalls == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":{"message":"rate limited"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	client := openaicompat.New(openaicompat.Config{BaseURL: srv.URL, Budget: llm.NewBudget(st, llm.BudgetLimits{TotalTokens: 100000})}, nil, nil)
	controller := situation.NewController(st, client, situation.ControllerConfig{}, func() time.Time { return now }, nil, nil)
	if err := controller.Reconcile(ctx, claimSituation(t, st, id, "budget-429-first", now)); err != nil {
		t.Fatal(err)
	}
	var calls int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_assessment_calls WHERE situation_id = ?`, id).Scan(&calls); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || providerCalls != 1 {
		t.Fatalf("first reconcile calls: ledger=%d provider=%d, want 1 each", calls, providerCalls)
	}
	sit := getSituationByID(t, st, id)
	if sit.LastErrorClass == nil || *sit.LastErrorClass != "rate_limited" || sit.RetryAt == nil {
		t.Fatalf("first reconcile status: class=%v retry=%v", sit.LastErrorClass, sit.RetryAt)
	}
	var raw []byte
	if err := st.db.QueryRowContext(ctx, `SELECT value FROM connector_state WHERE name = 'llm.budget.v1'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var budget struct {
		Unknown bool `json:"unknown"`
	}
	if err := json.Unmarshal(raw, &budget); err != nil {
		t.Fatal(err)
	}
	if budget.Unknown {
		t.Fatalf("429 latched budget: %s", raw)
	}
	now = sit.RetryAt.Add(time.Second)
	if err := controller.Reconcile(ctx, claimSituation(t, st, id, "budget-429-retry", now)); err != nil {
		t.Fatal(err)
	}
	if providerCalls != 2 {
		t.Fatalf("provider calls after retry = %d, want 2", providerCalls)
	}
	current := currentAssessmentID(t, st, id)
	var derivation string
	if err := st.db.QueryRowContext(ctx, `SELECT derivation FROM situation_assessment_attempts WHERE id = ?`, current).Scan(&derivation); err != nil {
		t.Fatal(err)
	}
	if derivation != string(situationmodel.DerivationModelValidated) {
		t.Fatalf("retry derivation = %q", derivation)
	}
}

func TestControllerBudgetDeferralPreservesGenuineAttemptCount(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	id := seedReconcileSituation(t, st, "budget-after-failure", now.Add(-2*time.Hour))
	deadline := now.Add(time.Hour)
	failed := func() (llm.OneShotCompletion, error) {
		return llm.OneShotCompletion{RequestStarted: llm.RequestStartStatusTrue}, &llm.RetryableError{StatusCode: http.StatusTooManyRequests}
	}
	denied := func() (llm.OneShotCompletion, error) {
		return llm.OneShotCompletion{RequestStarted: llm.RequestStartStatusFalse}, fmt.Errorf("%w: %w", llm.ErrRequestNotSent, &llm.BudgetDeferredError{RetryAt: &deadline, Message: "rolling-hour ceiling"})
	}
	client := &scriptedAssessmentClient{responses: []func() (llm.OneShotCompletion, error){failed, failed, failed, failed, denied, acceptedProposalResponse(t)}}
	controller := situation.NewController(st, client, situation.ControllerConfig{}, func() time.Time { return now }, nil, nil)
	for i := range 5 {
		forceBudgetCheckpoint(t, st, id, now)
		claim := claimSituation(t, st, id, "budget-after-failure", now)
		if err := controller.Reconcile(ctx, claim); err != nil {
			t.Fatal(err)
		}
		assertBudgetWorkAttempts(t, st, id, min(i+1, 4))
	}
	now = deadline
	claim := claimSituation(t, st, id, "budget-fifth-inference", now)
	if err := controller.Reconcile(ctx, claim); err != nil {
		t.Fatal(err)
	}
	assertBudgetWorkAttempts(t, st, id, 5)
	if client.calls != 6 {
		t.Fatalf("fifth genuine inference never resumed: %d calls", client.calls)
	}
}
