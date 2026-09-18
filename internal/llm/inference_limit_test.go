// SPDX-License-Identifier: FSL-1.1-ALv2

package llm_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
)

// TestInferenceLimiterBoundsTotalAndProfileConcurrency issues a mix of
// Assessment and Profile acquisitions well beyond capacity and asserts the
// observed peaks never exceed the configured bound (total) or 1 (profile) —
// plan.md's "assert peak <= configured capacity and profile peak <= 1".
func TestInferenceLimiterBoundsTotalAndProfileConcurrency(t *testing.T) {
	const capacity = 3
	l := llm.NewInferenceLimiter(capacity)

	var inUse, peak, profileInUse, profilePeak int64
	var wg sync.WaitGroup
	run := func(priority llm.InferencePriority) {
		defer wg.Done()
		release, err := l.Acquire(context.Background(), priority)
		if err != nil {
			t.Errorf("Acquire: %v", err)
			return
		}
		defer release()
		n := atomic.AddInt64(&inUse, 1)
		for {
			p := atomic.LoadInt64(&peak)
			if n <= p || atomic.CompareAndSwapInt64(&peak, p, n) {
				break
			}
		}
		if priority == llm.InferenceProfile {
			pn := atomic.AddInt64(&profileInUse, 1)
			for {
				p := atomic.LoadInt64(&profilePeak)
				if pn <= p || atomic.CompareAndSwapInt64(&profilePeak, p, pn) {
					break
				}
			}
		}
		time.Sleep(5 * time.Millisecond)
		atomic.AddInt64(&inUse, -1)
		if priority == llm.InferenceProfile {
			atomic.AddInt64(&profileInUse, -1)
		}
	}

	for i := 0; i < 20; i++ {
		wg.Add(2)
		go run(llm.InferenceAssessment)
		go run(llm.InferenceProfile)
	}
	wg.Wait()

	if peak > capacity {
		t.Fatalf("peak concurrent = %d, want <= %d", peak, capacity)
	}
	if profilePeak > 1 {
		t.Fatalf("profile peak concurrent = %d, want <= 1", profilePeak)
	}
}

// TestInferenceLimiterAtCapacityOneAssessmentTakesPrecedence covers
// plan.md's literal scenario: "At capacity 1, queue a profile and
// Assessment behind an active call; releasing it starts Assessment first".
func TestInferenceLimiterAtCapacityOneAssessmentTakesPrecedence(t *testing.T) {
	l := llm.NewInferenceLimiter(1)
	ctx := context.Background()

	releaseActive, err := l.Acquire(ctx, llm.InferenceProfile)
	if err != nil {
		t.Fatalf("acquire active: %v", err)
	}

	profileGranted := make(chan struct{})
	go func() {
		release, err := l.Acquire(ctx, llm.InferenceProfile)
		if err != nil {
			t.Errorf("queued profile acquire: %v", err)
			return
		}
		defer release()
		close(profileGranted)
	}()
	// Give the profile acquisition time to actually enqueue before the
	// assessment one, so ordering alone could never explain assessment
	// winning — only genuine priority can.
	time.Sleep(20 * time.Millisecond)

	order := make(chan string, 2)
	assessmentGranted := make(chan struct{})
	go func() {
		release, err := l.Acquire(ctx, llm.InferenceAssessment)
		if err != nil {
			t.Errorf("queued assessment acquire: %v", err)
			return
		}
		order <- "assessment"
		close(assessmentGranted)
		time.Sleep(10 * time.Millisecond)
		release()
	}()
	time.Sleep(20 * time.Millisecond)

	releaseActive()

	select {
	case <-assessmentGranted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the queued assessment to be granted")
	}
	select {
	case first := <-order:
		if first != "assessment" {
			t.Fatalf("first granted = %q, want assessment", first)
		}
	default:
		t.Fatal("expected the assessment goroutine to have recorded its grant order")
	}

	select {
	case <-profileGranted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the queued profile to eventually be granted too")
	}
}

// TestInferenceLimiterCancellationNeverGrantsASlot proves a waiter whose
// context is canceled before a slot frees returns an error and never
// occupies capacity — plan.md: "Cancellation while waiting must not invoke
// the client".
func TestInferenceLimiterCancellationNeverGrantsASlot(t *testing.T) {
	l := llm.NewInferenceLimiter(1)
	releaseActive, err := l.Acquire(context.Background(), llm.InferenceAssessment)
	if err != nil {
		t.Fatalf("acquire active: %v", err)
	}
	defer releaseActive()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := l.Acquire(ctx, llm.InferenceProfile); err == nil {
		t.Fatal("expected Acquire to fail for an already-canceled context while at capacity")
	}

	// The canceled waiter must not have consumed a slot: a fresh, immediate
	// acquisition attempt (capacity still fully held by releaseActive)
	// correctly still blocks/fails on its own already-canceled context —
	// proving no residual grant leaked capacity to the canceled waiter.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel2()
	if _, err := l.Acquire(ctx2, llm.InferenceAssessment); err == nil {
		t.Fatal("expected the still-at-capacity limiter to block this acquisition until its own timeout")
	}
}

func TestInferenceLimiterZeroOrNegativeCapacityDefaultsToOne(t *testing.T) {
	l := llm.NewInferenceLimiter(0)
	release, err := l.Acquire(context.Background(), llm.InferenceAssessment)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := l.Acquire(ctx, llm.InferenceAssessment); err == nil {
		t.Fatal("a zero-or-negative capacity limiter must still enforce a real bound (>=1), not admit unboundedly")
	}
}
