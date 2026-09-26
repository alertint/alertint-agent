// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

type neverCalledAssessmentClient struct{ calls int }

type assessmentClientFunc func(context.Context, string, llm.Prompt, []string) (llm.OneShotCompletion, error)

func (f assessmentClientFunc) CompleteOnce(ctx context.Context, system string, prompt llm.Prompt, keys []string) (llm.OneShotCompletion, error) {
	return f(ctx, system, prompt, keys)
}

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

func TestStartedProviderCallSettlesAfterLeaseLoss(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(map[bool]string{false: "private", true: "shared"}[shared], func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			var calls atomic.Int32
			inner := assessmentClientFunc(func(ctx context.Context, _ string, _ llm.Prompt, _ []string) (llm.OneShotCompletion, error) {
				if calls.Add(1) > 1 {
					return llm.OneShotCompletion{RequestStarted: llm.RequestStartStatusTrue}, nil
				}
				close(entered)
				select {
				case <-ctx.Done():
					return llm.OneShotCompletion{RequestStarted: llm.RequestStartStatusUnknown}, ctx.Err()
				case <-release:
					return llm.OneShotCompletion{Completion: llm.Completion{InputTokens: 23, OutputTokens: 5}, RequestStarted: llm.RequestStartStatusTrue}, nil
				}
			})
			client := newSemaphoreAssessmentClient(inner, 1)
			if shared {
				client.setInferenceLimiter(llm.NewInferenceLimiter(1))
			}
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			type result struct {
				completion llm.OneShotCompletion
				err        error
			}
			done := make(chan result, 1)
			go func() { got, err := client.CompleteOnce(ctx, "", llm.Prompt{}, nil); done <- result{got, err} }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("provider call did not start")
			}
			cancel(model.ErrSituationLeaseLost)
			select {
			case got := <-done:
				t.Fatalf("started call returned before settlement: %+v", got)
			case <-time.After(200 * time.Millisecond):
			}
			close(release)
			select {
			case got := <-done:
				if got.err != nil || got.completion.RequestStarted != llm.RequestStartStatusTrue || got.completion.InputTokens != 23 || got.completion.OutputTokens != 5 {
					t.Fatalf("settled call = %+v, want true with usage 23/5", got)
				}
			case <-time.After(time.Second):
				t.Fatal("settled call did not return")
			}
			// A second call must acquire the released slot immediately.
			ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
			defer cancel2()
			if _, err := client.CompleteOnce(ctx2, "", llm.Prompt{}, nil); err != nil {
				t.Fatalf("slot still held: %v", err)
			}
		})
	}
}

func TestStartedProviderCallAbortsOnShutdown(t *testing.T) {
	entered := make(chan struct{})
	inner := assessmentClientFunc(func(ctx context.Context, _ string, _ llm.Prompt, _ []string) (llm.OneShotCompletion, error) {
		close(entered)
		<-ctx.Done()
		return llm.OneShotCompletion{RequestStarted: llm.RequestStartStatusUnknown}, ctx.Err()
	})
	client := newSemaphoreAssessmentClient(inner, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := client.CompleteOnce(ctx, "", llm.Prompt{}, nil); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("provider call did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel call")
	}
}

func TestStartedProviderCallKeepsAttemptDeadline(t *testing.T) {
	inner := assessmentClientFunc(func(ctx context.Context, _ string, _ llm.Prompt, _ []string) (llm.OneShotCompletion, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > time.Second {
			t.Errorf("provider deadline = %v, present=%v", deadline, ok)
		}
		<-ctx.Done()
		return llm.OneShotCompletion{}, ctx.Err()
	})
	client := newSemaphoreAssessmentClient(inner, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := client.CompleteOnce(ctx, "", llm.Prompt{}, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline err = %v", err)
	}
}
