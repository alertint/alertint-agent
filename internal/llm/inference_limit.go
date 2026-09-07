// SPDX-License-Identifier: FSL-1.1-ALv2

package llm

import (
	"context"
	"sync"
)

// InferencePriority distinguishes the two provider-call classes an
// InferenceLimiter shares one bounded capacity between — spec.md: "At the
// prepared head situations.llm_concurrency limits L2 only; this slice
// extends that limiter to L0+L2 and documents the scope honestly".
type InferencePriority int

const (
	// InferenceAssessment is a Situation controller L2 dispatch
	// (situation.AssessmentClient.CompleteOnce).
	InferenceAssessment InferencePriority = iota
	// InferenceProfile is a semantic-profile L0 inference dispatch.
	InferenceProfile
)

// inferenceWaiter is one blocked Acquire call's grant channel — closed
// exactly once, under InferenceLimiter.mu, the instant a slot is handed to
// it.
type inferenceWaiter struct {
	grant chan struct{}
}

// InferenceLimiter bounds concurrent provider calls across BOTH Situation
// Assessment (L2) and semantic-profile inference (L0) to one shared
// capacity. Two rules beyond a plain counting semaphore: at most one
// concurrently-held slot may be a Profile acquisition regardless of total
// capacity (spec.md: "At most one slot may be used by profiles"), and when
// a slot frees with both an Assessment and a Profile waiting, the
// Assessment is granted first (spec.md: "when only one slot is configured,
// queued Assessments take precedence" — the general priority rule this
// limiter applies at every capacity, not only capacity 1). Acquire never
// invokes a caller-provided client itself: it only ever hands back a
// release func, so a caller whose ctx is canceled while waiting is
// guaranteed to have made no physical request.
type InferenceLimiter struct {
	mu       sync.Mutex
	capacity int
	inUse    int

	profileHeld       bool
	assessmentWaiters []*inferenceWaiter
	profileWaiters    []*inferenceWaiter
}

// NewInferenceLimiter constructs an InferenceLimiter with the given total
// capacity, clamped to a minimum of 1 (a non-positive capacity still
// enforces a real bound rather than admitting unboundedly).
func NewInferenceLimiter(capacity int) *InferenceLimiter {
	if capacity < 1 {
		capacity = 1
	}
	return &InferenceLimiter{capacity: capacity}
}

// Acquire blocks until a slot is granted or ctx is done, whichever comes
// first. On success it returns a release func that MUST be called exactly
// once (calling it more than once is a safe no-op); on failure it returns
// ctx.Err() and is guaranteed to hold no slot.
func (l *InferenceLimiter) Acquire(ctx context.Context, priority InferencePriority) (func(), error) {
	l.mu.Lock()
	if l.tryGrantLocked(priority) {
		l.mu.Unlock()
		return l.releaseFunc(priority), nil
	}
	w := &inferenceWaiter{grant: make(chan struct{})}
	l.enqueueLocked(priority, w)
	l.mu.Unlock()

	select {
	case <-w.grant:
		return l.releaseFunc(priority), nil
	case <-ctx.Done():
		l.mu.Lock()
		stillWaiting := l.dequeueLocked(priority, w)
		l.mu.Unlock()
		if !stillWaiting {
			// Granted concurrently with cancellation (the closing of
			// w.grant and its removal from the queue both already happened,
			// under l.mu, before dequeueLocked observed it missing): honor
			// the grant rather than leaking capacity, then release it right
			// back so this Acquire still, from the caller's view, holds
			// nothing.
			l.releaseFunc(priority)()
		}
		return nil, ctx.Err()
	}
}

func (l *InferenceLimiter) tryGrantLocked(priority InferencePriority) bool {
	if l.inUse >= l.capacity {
		return false
	}
	if priority == InferenceProfile && l.profileHeld {
		return false
	}
	l.inUse++
	if priority == InferenceProfile {
		l.profileHeld = true
	}
	return true
}

func (l *InferenceLimiter) enqueueLocked(priority InferencePriority, w *inferenceWaiter) {
	if priority == InferenceAssessment {
		l.assessmentWaiters = append(l.assessmentWaiters, w)
	} else {
		l.profileWaiters = append(l.profileWaiters, w)
	}
}

// dequeueLocked removes w from its queue if still present, reporting
// whether it found (and removed) it. false means w was already granted a
// slot by a concurrent release.
func (l *InferenceLimiter) dequeueLocked(priority InferencePriority, w *inferenceWaiter) bool {
	queue := &l.assessmentWaiters
	if priority == InferenceProfile {
		queue = &l.profileWaiters
	}
	for i, q := range *queue {
		if q == w {
			*queue = append((*queue)[:i], (*queue)[i+1:]...)
			return true
		}
	}
	return false
}

func (l *InferenceLimiter) releaseFunc(priority InferencePriority) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			l.inUse--
			if priority == InferenceProfile {
				l.profileHeld = false
			}
			l.wakeNextLocked()
			l.mu.Unlock()
		})
	}
}

// wakeNextLocked grants the single slot a release just freed to the
// highest-priority eligible waiter: an Assessment waiter always wins over a
// Profile one, and a Profile waiter is only eligible while no Profile slot
// is currently held.
func (l *InferenceLimiter) wakeNextLocked() {
	if l.inUse >= l.capacity {
		return
	}
	if len(l.assessmentWaiters) > 0 {
		w := l.assessmentWaiters[0]
		l.assessmentWaiters = l.assessmentWaiters[1:]
		l.inUse++
		close(w.grant)
		return
	}
	if !l.profileHeld && len(l.profileWaiters) > 0 {
		w := l.profileWaiters[0]
		l.profileWaiters = l.profileWaiters[1:]
		l.inUse++
		l.profileHeld = true
		close(w.grant)
	}
}
