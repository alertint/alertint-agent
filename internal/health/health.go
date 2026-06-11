// SPDX-License-Identifier: FSL-1.1-ALv2

// Package health runs connectivity probes for enabled integrations
// (Prometheus, Slack, ...) so a misconfigured integration is visible
// immediately after startup — in the console log and in GET /health —
// instead of failing silently on first use.
//
// Probe results are cached: the registry re-probes at most once per TTL,
// so a Docker HEALTHCHECK polling /health every few seconds does not
// hammer external APIs.
package health

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// DefaultTTL is how long probe results are reused before re-probing.
const DefaultTTL = 60 * time.Second

// probeTimeout bounds a single integration probe.
const probeTimeout = 10 * time.Second

// Check is one integration connectivity probe.
type Check struct {
	// Name of the integration, e.g. "prometheus".
	Name string
	// Detail is shown alongside the status, e.g. the base URL or channel.
	Detail string
	// Probe returns nil when the integration is reachable and usable.
	Probe func(ctx context.Context) error
}

// Status is the outcome of one probe.
type Status struct {
	Name      string    `json:"name"`
	Detail    string    `json:"detail,omitempty"`
	OK        bool      `json:"ok"`
	Error     string    `json:"error,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// Registry holds the configured checks and the cached results.
type Registry struct {
	checks []Check
	ttl    time.Duration

	mu       sync.Mutex
	cached   []Status
	probedAt time.Time
}

// NewRegistry builds a registry; ttl <= 0 uses DefaultTTL.
func NewRegistry(ttl time.Duration, checks ...Check) *Registry {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Registry{checks: checks, ttl: ttl}
}

// Run returns the status of every check, re-probing only when the cache
// is older than the TTL. Safe for concurrent use. A nil registry returns
// no statuses so callers can stay nil-safe.
func (r *Registry) Run(ctx context.Context) []Status {
	if r == nil || len(r.checks) == 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cached != nil && time.Since(r.probedAt) < r.ttl {
		return r.cached
	}

	now := time.Now().UTC()
	statuses := make([]Status, 0, len(r.checks))
	for _, c := range r.checks {
		pctx, cancel := context.WithTimeout(ctx, probeTimeout)
		err := c.Probe(pctx)
		cancel()
		s := Status{Name: c.Name, Detail: c.Detail, OK: err == nil, CheckedAt: now}
		if err != nil {
			s.Error = err.Error()
		}
		statuses = append(statuses, s)
	}
	r.cached = statuses
	r.probedAt = now
	return statuses
}

// LogStatuses writes one log line per integration: Info when reachable,
// Warn when not. Intended for the startup health pass.
func LogStatuses(logger *slog.Logger, statuses []Status) {
	if logger == nil {
		logger = slog.Default()
	}
	for _, s := range statuses {
		if s.OK {
			logger.Info("integration health: OK",
				slog.String("integration", s.Name),
				slog.String("detail", s.Detail),
			)
		} else {
			logger.Warn("integration health: FAILED",
				slog.String("integration", s.Name),
				slog.String("detail", s.Detail),
				slog.String("err", s.Error),
			)
		}
	}
}
