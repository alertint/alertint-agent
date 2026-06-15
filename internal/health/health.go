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

// Watch pacing: while an integration is failing the watcher re-probes
// quickly — a failure is usually a co-deployed dependency still starting —
// doubling the delay each round. watchSteadyInterval is both the backoff
// cap and the pace once everything is healthy, so an integration that goes
// down later (or comes back) is noticed within a minute.
const (
	watchMinDelay       = 2 * time.Second
	watchSteadyInterval = 60 * time.Second
)

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
	checks      []Check
	ttl         time.Duration
	watchMin    time.Duration // first retry delay while a check is failing
	watchSteady time.Duration // backoff cap; also the pace when healthy

	mu       sync.Mutex
	cached   []Status
	probedAt time.Time
}

// NewRegistry builds a registry; ttl <= 0 uses DefaultTTL.
func NewRegistry(ttl time.Duration, checks ...Check) *Registry {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Registry{
		checks:      checks,
		ttl:         ttl,
		watchMin:    watchMinDelay,
		watchSteady: watchSteadyInterval,
	}
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

	statuses := probeAll(ctx, r.checks)
	r.cached = statuses
	r.probedAt = time.Now().UTC()
	return statuses
}

// Watch probes the checks in a loop until ctx is cancelled. The first
// pass logs every status; after that it logs a connection loss (OK→FAILED),
// each failed retry, and the recovery (FAILED→OK) — a steady healthy state
// is silent. While any check fails the delay doubles from watchMin up to
// watchSteady, so a dependency that is still booting alongside the agent
// is re-detected within seconds and a prod outage doesn't trigger a probe
// storm; once healthy it keeps probing at the steady pace to catch later
// outages. Every pass refreshes the cache used by Run / GET /health.
// A nil registry returns immediately.
func (r *Registry) Watch(ctx context.Context, logger *slog.Logger) {
	if r == nil || len(r.checks) == 0 {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	statuses := r.probeAndCache(ctx)
	LogStatuses(logger, statuses)
	downSince := make(map[string]time.Time)
	for _, s := range statuses {
		if !s.OK {
			downSince[s.Name] = s.CheckedAt
		}
	}

	delay := r.watchMin
	if allOK(statuses) {
		delay = r.watchSteady
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		prev := statuses
		statuses = r.probeAndCache(ctx)
		switch {
		case allOK(statuses):
			delay = r.watchSteady
		case allOK(prev): // fresh failure: start the backoff over
			delay = r.watchMin
		default: // still failing: keep backing off
			delay = min(delay*2, r.watchSteady)
		}

		for _, s := range statuses {
			since, wasDown := downSince[s.Name]
			switch {
			case s.OK && wasDown:
				logger.Info("integration health: connection restored",
					slog.String("integration", s.Name),
					slog.String("detail", s.Detail),
					slog.Duration("down_for", s.CheckedAt.Sub(since)),
				)
				delete(downSince, s.Name)
			case !s.OK && !wasDown:
				logger.Warn("integration health: connection lost; retrying",
					slog.String("integration", s.Name),
					slog.String("detail", s.Detail),
					slog.String("err", s.Error),
					slog.Duration("retry_in", delay),
				)
				downSince[s.Name] = s.CheckedAt
			case !s.OK && wasDown:
				logger.Warn("integration health: retry failed",
					slog.String("integration", s.Name),
					slog.String("detail", s.Detail),
					slog.String("err", s.Error),
					slog.Duration("retry_in", delay),
				)
			}
		}
	}
}

// probeAndCache runs every probe once and replaces the cached statuses.
// It probes without holding the lock so /health is never blocked on a
// slow probe; it only takes the lock to swap the result in.
func (r *Registry) probeAndCache(ctx context.Context) []Status {
	statuses := probeAll(ctx, r.checks)
	r.mu.Lock()
	r.cached = statuses
	r.probedAt = time.Now().UTC()
	r.mu.Unlock()
	return statuses
}

// probeAll runs every probe once and returns the statuses.
func probeAll(ctx context.Context, checks []Check) []Status {
	now := time.Now().UTC()
	statuses := make([]Status, 0, len(checks))
	for _, c := range checks {
		pctx, cancel := context.WithTimeout(ctx, probeTimeout)
		err := c.Probe(pctx)
		cancel()
		s := Status{Name: c.Name, Detail: c.Detail, OK: err == nil, CheckedAt: now}
		if err != nil {
			s.Error = err.Error()
		}
		statuses = append(statuses, s)
	}
	return statuses
}

func allOK(statuses []Status) bool {
	for _, s := range statuses {
		if !s.OK {
			return false
		}
	}
	return true
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
