// SPDX-License-Identifier: FSL-1.1-ALv2

// Package httpcount carries a request-attempt counter through connector
// contexts. Connectors increment immediately before http.Client.Do, so retries
// and fallbacks are counted even when the request fails without a response.
package httpcount

import (
	"context"
	"sync/atomic"
)

type counterKey struct{}

type Counter struct{ attempts atomic.Int64 }

func WithCounter(ctx context.Context) (context.Context, *Counter) {
	c := &Counter{}
	return context.WithValue(ctx, counterKey{}, c), c
}

func Observe(ctx context.Context) {
	if c, ok := ctx.Value(counterKey{}).(*Counter); ok {
		c.attempts.Add(1)
	}
}

func (c *Counter) Attempts() int { return int(c.attempts.Load()) }
