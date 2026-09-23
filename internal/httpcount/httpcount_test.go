// SPDX-License-Identifier: FSL-1.1-ALv2

package httpcount

import (
	"context"
	"testing"
)

func TestCounterCountsEveryObservedRequestAttempt(t *testing.T) {
	ctx, counter := WithCounter(context.Background())
	Observe(ctx)
	Observe(ctx)
	if got := counter.Attempts(); got != 2 {
		t.Fatalf("attempts = %d, want 2", got)
	}
}
