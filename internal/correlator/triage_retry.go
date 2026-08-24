// SPDX-License-Identifier: FSL-1.1-ALv2

package correlator

import (
	"context"
	"errors"
	"time"

	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/store"
)

// triageRetryDelays is the backoff schedule for re-dispatching an incident
// whose triage handoff (IncidentSink.OnIncidentReady) returned an error. The
// first retry waits 30 s and the last ~32 min, so a short LLM or connector
// outage self-heals and a long one exhausts inside the hour instead of
// leaving the incident in "ready" forever. Five attempts in total, counting
// the initial dispatch.
var triageRetryDelays = []time.Duration{
	30 * time.Second,
	2 * time.Minute,
	8 * time.Minute,
	32 * time.Minute,
}

// startupRetryWindow bounds startup recovery: an incident that has been
// "ready" for longer than this is closed out as "failed" without a triage
// call instead of being re-dispatched, so an upgrade over a long backlog of
// stuck incidents does not turn into an LLM burst. It matches the ~43 min
// retry horizon: had the process stayed up, such an incident would have
// exhausted its schedule by now. A condition that is still active re-fires
// and opens a fresh incident.
const startupRetryWindow = time.Hour

// triageRetry is the in-memory retry state for one incident. The correlator
// keeps it only for incidents whose sink call errored — an incident the skill
// deliberately leaves in "ready" (below min_alerts, no member alerts) returns
// nil and is never re-dispatched.
//
// The map does not survive a restart, so Start seeds it from every incident
// still in "ready": each is dispatched once on the first tick and either
// completes, is skipped again (nil, dropped), or enters the schedule.
type triageRetry struct {
	groupKey   string
	alertCount int
	failures   int       // sink errors so far, including the initial dispatch
	nextAt     time.Time // earliest time of the next attempt
	// exhausted is set once the schedule is spent; from then on only the
	// terminal "failed" write is pending, and it is retried on its own
	// without another sink call.
	exhausted bool
	lastErr   error
}

// seedTriageRetries handles every incident still in "ready" at Start: a
// previous process may have died mid-triage or exited during the backoff, and
// nothing else re-reads ready rows. Incidents ready for less than
// startupRetryWindow are registered for one dispatch on the next tick (clean
// skips cost one nil sink call per restart); older ones are marked "failed"
// outright, audited with reason startup_retry_window_expired, and never sent
// to the sink or the notifier — one summary log line covers them.
func (c *Correlator) seedTriageRetries(ctx context.Context) error {
	incs, err := c.st.ListReadyIncidents(ctx)
	if err != nil {
		return err
	}
	now := c.now().UTC()
	var seeded, expired int
	for _, inc := range incs {
		if now.Sub(inc.ReadyAt) <= startupRetryWindow {
			c.retries[inc.ID] = &triageRetry{groupKey: inc.GroupKey, alertCount: inc.AlertCount}
			seeded++
			continue
		}
		if err := c.st.MarkIncidentFailed(ctx, inc.ID); err != nil {
			c.logger.Error("correlator: startup recovery: mark stale incident failed",
				"incident_id", inc.ID, "group_key", inc.GroupKey, "err", err)
			continue
		}
		expired++
		if c.auditor != nil {
			if err := c.auditor.Append(ctx, "correlator", "incident.triage_exhausted", map[string]any{
				"incident_id": inc.ID,
				"group_key":   inc.GroupKey,
				"attempts":    0,
				"reason":      "startup_retry_window_expired",
				"ready_at":    inc.ReadyAt.UTC(),
			}); err != nil {
				c.logger.Warn("correlator: audit stale incident failed", "incident_id", inc.ID, "err", err)
			}
		}
	}
	if len(incs) > 0 {
		c.logger.Warn("correlator: startup recovery: ready incidents found",
			"ready_incidents", len(incs), "redispatch", seeded,
			"marked_failed", expired, "retry_window", startupRetryWindow)
	}
	return nil
}

// triageFailed records a failed sink call for inc and either schedules the
// next attempt or, once the schedule is spent, moves the incident to the
// terminal "failed" status. The retry deadline is taken from a fresh clock
// reading: the sink call itself may have run for longer than the delay.
func (c *Correlator) triageFailed(ctx context.Context, inc store.Incident, cause error) {
	r := c.retries[inc.ID]
	if r == nil {
		r = &triageRetry{groupKey: inc.GroupKey, alertCount: inc.AlertCount}
		c.retries[inc.ID] = r
	}
	r.failures++
	r.lastErr = cause
	now := c.now().UTC()
	maxAttempts := len(triageRetryDelays) + 1
	if r.failures < maxAttempts {
		delay := triageRetryDelays[r.failures-1]
		r.nextAt = now.Add(delay)
		c.logger.Warn("correlator: triage failed; will retry",
			"incident_id", inc.ID, "group_key", inc.GroupKey,
			"attempt", r.failures, "max_attempts", maxAttempts,
			"retry_in", delay, "err", cause)
		return
	}
	r.exhausted = true
	c.closeExhausted(ctx, inc.ID, r, now)
}

// closeExhausted performs the terminal "failed" write for an incident whose
// schedule is spent. The retry entry is dropped only once the write has
// succeeded, or when the incident has already left "ready" (ErrNotFound);
// on any other store error the write is re-attempted on a later tick so a
// transient SQLite failure cannot recreate the permanent orphan. The audit
// row and the notifier event follow the successful write, so both fire
// exactly once per incident.
func (c *Correlator) closeExhausted(ctx context.Context, id string, r *triageRetry, now time.Time) {
	err := c.st.MarkIncidentFailed(ctx, id)
	switch {
	case err == nil:
		delete(c.retries, id)
	case errors.Is(err, store.ErrNotFound):
		delete(c.retries, id)
		c.logger.Info("correlator: triage exhausted but incident already left ready; not marking failed",
			"incident_id", id, "group_key", r.groupKey)
		return
	default:
		r.nextAt = now.Add(triageRetryDelays[0])
		c.logger.Error("correlator: mark incident failed; will retry the write",
			"incident_id", id, "group_key", r.groupKey, "retry_in", triageRetryDelays[0], "err", err)
		return
	}

	c.logger.Error("correlator: triage exhausted; incident marked failed",
		"incident_id", id, "group_key", r.groupKey,
		"attempts", r.failures, "err", r.lastErr)
	if c.auditor != nil {
		if err := c.auditor.Append(ctx, "correlator", "incident.triage_exhausted", map[string]any{
			"incident_id": id,
			"group_key":   r.groupKey,
			"attempts":    r.failures,
			"reason":      "max_attempts",
			"error":       r.lastErr.Error(),
		}); err != nil {
			c.logger.Warn("correlator: audit triage exhausted", "incident_id", id, "err", err)
		}
	}
	if c.triageNotifier != nil {
		ev := notify.TriageExhaustedEvent{
			IncidentID: id,
			GroupKey:   r.groupKey,
			AlertCount: r.alertCount,
			Attempts:   r.failures,
			Error:      r.lastErr.Error(),
		}
		if err := c.triageNotifier.OnTriageExhausted(ctx, ev); err != nil {
			c.logger.Warn("correlator: triage exhausted notify failed", "incident_id", id, "err", err)
		}
	}
}

// retryTriage re-dispatches every incident whose retry is due and completes
// pending terminal writes. An incident that left "ready" in the meantime
// (resolved by its alerts recovering, or analyzed by a re-judgment) is
// dropped without a sink call.
func (c *Correlator) retryTriage(ctx context.Context, now time.Time) {
	for id, r := range c.retries {
		if now.Before(r.nextAt) {
			continue
		}
		if r.exhausted {
			c.closeExhausted(ctx, id, r, now)
			continue
		}
		inc, err := c.st.GetIncidentByID(ctx, id)
		if err != nil {
			c.logger.Error("correlator: load incident for triage retry", "incident_id", id, "err", err)
			continue
		}
		if inc == nil || inc.Status != "ready" {
			delete(c.retries, id)
			continue
		}
		c.logger.Info("correlator: retrying triage",
			"incident_id", id, "group_key", inc.GroupKey, "attempt", r.failures+1)
		if err := c.sink.OnIncidentReady(ctx, *inc); err != nil {
			c.triageFailed(ctx, *inc, err)
			continue
		}
		delete(c.retries, id)
	}
}
