// SPDX-License-Identifier: FSL-1.1-ALv2

package llm

import "context"

type requestObserverKey struct{}

// WithRequestObserver observes each provider request beneath Complete's retry
// loop. The callback receives usage and dispatch certainty for that attempt;
// an admission rejection is reported too, with ErrRequestNotSent. It must not
// mutate the completion. No observer means no change to client behavior.
func WithRequestObserver(ctx context.Context, observe func(Completion, error)) context.Context {
	return context.WithValue(ctx, requestObserverKey{}, observe)
}

// ObserveRequest is called by providers once per doRequest, before a retry.
func ObserveRequest(ctx context.Context, comp Completion, err error) {
	if observe, ok := ctx.Value(requestObserverKey{}).(func(Completion, error)); ok {
		observe(comp, err)
	}
}
