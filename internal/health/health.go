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

// Sink receives durable dependency-health status observations. Registry
// calls it only on the first observation of each check and on every
// OK<->failing transition thereafter — never on a steady repeat — so a
// sustained shared outage produces at most one recorded failing observation
// plus one recovery observation, matching the installation-level "at most
// one health root, one recovery update" contract
// (internal/situation.DependencyHealthSink is the concrete implementation;
// expressed here as an interface so this package never imports
// internal/situation, which already imports this package indirectly via
// cmd/alertint wiring).
type Sink interface {
	RecordDependencyStatus(ctx context.Context, status Status) error
}

// Registry holds the configured checks and the cached results.
type Registry struct {
	checks      []Check
	ttl         time.Duration
	watchMin    time.Duration // first retry delay while a check is failing
	watchSteady time.Duration // backoff cap; also the pace when healthy

	mu           sync.Mutex
	cached       []Status
	probedAt     time.Time
	sink         Sink
	lastObserved map[string]bool // name -> last OK reported to sink
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

// SetSink attaches an optional durable dependency-health sink (nil detaches
// it). It is called synchronously from Run/Watch on first observation of
// each check and on every OK<->failing transition; a sink error is only
// logged where a logger is available (Watch) and never blocks or fails the
// probe itself — dependency-health persistence is best-effort
// observability, not probe authority. Safe for concurrent use; a nil
// registry is a no-op.
func (r *Registry) SetSink(sink Sink) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sink = sink
}

// Run returns the status of every check, re-probing only when the cache
// is older than the TTL. Safe for concurrent use. A nil registry returns
// no statuses so callers can stay nil-safe.
func (r *Registry) Run(ctx context.Context) []Status {
	if r == nil || len(r.checks) == 0 {
		return nil
	}
	r.mu.Lock()
	if r.cached != nil && time.Since(r.probedAt) < r.ttl {
		cached := r.cached
		r.mu.Unlock()
		return cached
	}
	// The lock stays held across the probe itself (unchanged from before
	// this sink addition): it serializes concurrent callers racing a TTL
	// expiry onto a single real probe rather than a stampede.
	statuses := probeAll(ctx, r.checks)
	r.cached = statuses
	r.probedAt = time.Now().UTC()
	sink, due := r.dueForSink(statuses)
	r.mu.Unlock()
	notifySink(ctx, sink, due, nil)
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
	r.notifyFromProbe(ctx, statuses, logger)
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
		r.notifyFromProbe(ctx, statuses, logger)
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

// notifyFromProbe reports one probeAndCache result to the attached sink
// (first observation / transitions only), logging a sink failure when a
// logger is available. It never blocks the caller on I/O beyond the sink
// call itself and never affects probe results. Unlike Run — which already
// holds r.mu across its own probe — Watch's probeAndCache runs unlocked, so
// this method takes the lock itself just to compute the due set.
func (r *Registry) notifyFromProbe(ctx context.Context, statuses []Status, logger *slog.Logger) {
	r.mu.Lock()
	sink, due := r.dueForSink(statuses)
	r.mu.Unlock()
	notifySink(ctx, sink, due, logger)
}

// dueForSink requires the caller to already hold r.mu (Run's own call site
// does; notifyFromProbe locks around it for Watch's unlocked probe path).
// It updates the per-check last reported OK/failing state and returns the
// currently attached sink (nil if none) together with the subset of
// statuses that are reportable this pass: a check's very first
// observation, or one whose OK/failing state differs from what was last
// reported. A steady repeat reports nothing.
func (r *Registry) dueForSink(statuses []Status) (Sink, []Status) {
	sink := r.sink
	if sink == nil {
		return nil, nil
	}
	if r.lastObserved == nil {
		r.lastObserved = make(map[string]bool, len(statuses))
	}
	var due []Status
	for _, s := range statuses {
		prev, seen := r.lastObserved[s.Name]
		if !seen || prev != s.OK {
			due = append(due, s)
		}
		r.lastObserved[s.Name] = s.OK
	}
	return sink, due
}

// notifySink calls sink for each due status, outside any Registry lock. A
// sink error is logged (when a logger is available) and otherwise
// swallowed — dependency-health persistence is best-effort observability,
// never probe authority.
func notifySink(ctx context.Context, sink Sink, due []Status, logger *slog.Logger) {
	if sink == nil {
		return
	}
	for _, s := range due {
		if err := sink.RecordDependencyStatus(ctx, s); err != nil && logger != nil {
			logger.Warn("integration health: dependency status sink failed",
				slog.String("integration", s.Name),
				slog.String("err", err.Error()),
			)
		}
	}
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
