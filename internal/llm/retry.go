// SPDX-License-Identifier: FSL-1.1-ALv2

package llm

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"
)

// CallWithRetry runs do, retrying on RetryableError with exponential backoff
// starting at baseDelay, up to maxRetries retries. It is the single backoff
// loop every provider client shares: which statuses are retryable stays a
// per-client decision (doRequest wraps them in RetryableError), but the
// retry behavior itself must never diverge between providers. The usage
// type parameter keeps each client's private token-usage type intact.
func CallWithRetry[U any](
	ctx context.Context,
	logger *slog.Logger,
	maxRetries int,
	baseDelay time.Duration,
	do func(context.Context) (json.RawMessage, U, error),
) (json.RawMessage, U, error) {
	var (
		raw  json.RawMessage
		err  error
		zero U
	)
	delay := baseDelay
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, zero, ctx.Err()
			}
			delay *= 2
		}
		var usage U
		raw, usage, err = do(ctx)
		if err == nil {
			return raw, usage, nil
		}
		var retryErr *RetryableError
		if errors.As(err, &retryErr) && attempt < maxRetries {
			logger.Warn("llm: retryable error, backing off",
				"attempt", attempt+1,
				"status", retryErr.StatusCode,
				"delay", delay,
			)
			continue
		}
		return nil, zero, err
	}
	return nil, zero, err
}
