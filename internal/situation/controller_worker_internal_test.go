// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"errors"
	"testing"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

type neverCalledAssessmentClient struct{ calls int }

func (c *neverCalledAssessmentClient) CompleteOnce(context.Context, string, llm.Prompt, []string) (llm.OneShotCompletion, error) {
	c.calls++
	return llm.OneShotCompletion{RequestStarted: llm.RequestStartStatusTrue}, nil
}

// TestSemaphoreAssessmentClientCancelledWhileWaitingReportsRequestNotStarted
// pins the worker's L2 semaphore contract for a cancellation that lands
// while a call is still waiting for a slot: the inner client is never
// reached, and the completion reports RequestStartStatusFalse — the
// deliberate, store-valid classification (never the zero value "") the
// controller records on that call's durable outcome row.
func TestSemaphoreAssessmentClientCancelledWhileWaitingReportsRequestNotStarted(t *testing.T) {
	inner := &neverCalledAssessmentClient{}
	c := newSemaphoreAssessmentClient(inner, 1)
	c.sem <- struct{}{} // another Situation's call holds the only slot

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := c.CompleteOnce(ctx, "", llm.Prompt{}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if inner.calls != 0 {
		t.Fatalf("inner CompleteOnce calls = %d, want 0 — the request must never be attempted", inner.calls)
	}
	if got.RequestStarted != llm.RequestStartStatusFalse {
		t.Fatalf("RequestStarted = %q, want %q", got.RequestStarted, llm.RequestStartStatusFalse)
	}
	if err := model.ProviderRequestStarted(got.RequestStarted).Validate(); err != nil {
		t.Fatalf("classification is not store-valid: %v", err)
	}
}
