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

// startupRetryWindow bounds startup recovery: an unjudged incident whose due
// time is older than this is closed out as "failed" without a triage call
// instead of being re-dispatched, so an upgrade over a long backlog of stuck
// incidents does not turn into an LLM burst (ADR-0045). It matches the ~43
// min retry horizon: had the process stayed up, such an incident would have
// exhausted its schedule by now. A condition that is still active re-fires
// and opens a fresh incident.
const startupRetryWindow = time.Hour

// dispatchTriage runs one triage attempt for incidentID: it begins the
// durable attempt (Incident status -> processing, triage phase -> in_flight)
// before calling the sink (R1), invokes the sink, and resolves the terminal
// outcome by rereading the Incident so alert_count can never be stale (R5).
func (c *Correlator) dispatchTriage(ctx context.Context, incidentID string) {
	now := c.now().UTC()
	active, err := c.st.BeginIncidentTriage(ctx, incidentID, now)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			c.logger.Error("correlator: begin triage dispatch", "incident_id", incidentID, "err", err)
		}
		return
	}

	inc, err := c.st.GetIncidentByID(ctx, incidentID)
	if err != nil || inc == nil {
		c.logger.Error("correlator: load incident for triage dispatch", "incident_id", incidentID, "err", err)
		return
	}
	c.logger.Info("correlator: dispatching triage", "incident_id", incidentID, "group_key", inc.GroupKey, "attempt", active.Attempts)

	sinkErr := c.sink.OnIncidentReady(ctx, *inc)

	fresh, ferr := c.st.GetIncidentByID(ctx, incidentID)
	if ferr != nil || fresh == nil {
		c.logger.Error("correlator: reload incident after triage dispatch", "incident_id", incidentID, "err", ferr)
		fresh = inc
	}

	switch {
	case sinkErr != nil:
		c.triageFailed(ctx, *fresh, active, sinkErr)
	case fresh.Status == "processing":
		// The skill returned nil without persisting a Finding: a deterministic
		// clean skip (e.g. below min_alerts), which counts as judgment.
		if err := c.st.SkipIncidentTriage(ctx, incidentID); err != nil && !errors.Is(err, store.ErrNotFound) {
			c.logger.Error("correlator: skip triage", "incident_id", incidentID, "err", err)
		}
	default:
		// analyzed | resolved: a Finding persisted during the sink call.
		if err := c.st.CompleteIncidentTriage(ctx, incidentID); err != nil && !errors.Is(err, store.ErrNotFound) {
			c.logger.Error("correlator: complete triage", "incident_id", incidentID, "err", err)
		}
	}
}

// classifyTriageError produces the bounded, sanitized code/detail persisted
// on a failed dispatch (R9). All non-LLM sink errors classify conservatively;
// the sibling LLM-health PR replaces this with capability-aware dependency
// codes without changing the retry schedule.
func classifyTriageError(err error) (code, detail string) {
	return "triage_dispatch_failed", err.Error()
}

// triageFailed records a failed dispatch and either schedules the next
// attempt or, once the schedule is spent, moves the incident to the terminal
// "failed" status.
func (c *Correlator) triageFailed(ctx context.Context, inc store.Incident, active store.IncidentTriage, cause error) {
	code, detail := classifyTriageError(cause)
	if active.Attempts >= len(triageRetryDelays)+1 {
		c.exhaustTriage(ctx, inc, active.Attempts, code, detail, "max_attempts")
		return
	}
	next := c.now().UTC().Add(triageRetryDelays[active.Attempts-1])
	if err := c.st.BackoffIncidentTriage(ctx, inc.ID, next, code, detail); err != nil {
		c.logger.Error("correlator: backoff triage", "incident_id", inc.ID, "err", err)
		return
	}
	c.logger.Warn("correlator: triage failed; will retry",
		"incident_id", inc.ID, "group_key", inc.GroupKey,
		"attempt", active.Attempts, "max_attempts", len(triageRetryDelays)+1,
		"retry_in", next.Sub(c.now().UTC()), "err", cause)
}

// exhaustTriage performs the terminal "failed" write for an incident whose
// schedule is spent. Only after ExhaustIncidentTriage succeeds does the audit
// row and notifier event fire, so both happen exactly once per incident; a
// repeated terminal transition returns ErrNotFound and emits nothing, and any
// other store error leaves the row `in_flight` so a later tick retries the
// write itself (never another sink call) via retryStuckTerminalWrites.
func (c *Correlator) exhaustTriage(ctx context.Context, inc store.Incident, attempts int, code, detail, reason string) {
	updated, err := c.st.ExhaustIncidentTriage(ctx, inc.ID, code, detail)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			c.logger.Info("correlator: triage exhausted but incident already left ready/processing; not marking failed",
				"incident_id", inc.ID, "group_key", inc.GroupKey)
			return
		}
		c.logger.Error("correlator: mark incident exhausted; will retry the write",
			"incident_id", inc.ID, "group_key", inc.GroupKey, "err", err)
		return
	}

	fresh, ferr := c.st.GetIncidentByID(ctx, inc.ID)
	if ferr != nil || fresh == nil {
		fresh = &inc
	}
	c.logger.Error("correlator: triage exhausted; incident marked failed",
		"incident_id", inc.ID, "group_key", inc.GroupKey, "attempts", attempts, "err", updated.LastErrorDetail)

	if c.auditor != nil {
		if err := c.auditor.Append(ctx, "correlator", "incident.triage_exhausted", map[string]any{
			"incident_id": inc.ID,
			"group_key":   inc.GroupKey,
			"attempts":    attempts,
			"reason":      reason,
			"error":       updated.LastErrorDetail,
		}); err != nil {
			c.logger.Warn("correlator: audit triage exhausted", "incident_id", inc.ID, "err", err)
		}
	}
	if c.triageNotifier != nil {
		ev := notify.TriageExhaustedEvent{
			IncidentID: inc.ID,
			GroupKey:   inc.GroupKey,
			AlertCount: fresh.AlertCount,
			Attempts:   attempts,
			Error:      updated.LastErrorDetail,
		}
		if err := c.triageNotifier.OnTriageExhausted(ctx, ev); err != nil {
			c.logger.Warn("correlator: triage exhausted notify failed", "incident_id", inc.ID, "err", err)
		}
	}
}

// retryStuckTerminalWrites finishes any dispatch whose terminal write
// (backoff or exhaustion) did not persist on an earlier tick — e.g. a
// transient store failure right after the sink call resolved. Such a row is
// left `in_flight` deliberately: this is the same durable signal a restart
// recovers from, so retrying it every tick is safe, never re-invokes the
// sink, and only ever finishes the transition that failed to write. Only the
// already-exhausted case is retried here; a sub-max in_flight row left by a
// genuine process interruption is reconciled at startup.
func (c *Correlator) retryStuckTerminalWrites(ctx context.Context) {
	stuck, err := c.st.ListInterruptedIncidentTriage(ctx)
	if err != nil {
		c.logger.Error("correlator: list interrupted triage", "err", err)
		return
	}
	for _, active := range stuck {
		if active.Attempts < len(triageRetryDelays)+1 {
			continue
		}
		inc, err := c.st.GetIncidentByID(ctx, active.IncidentID)
		if err != nil || inc == nil {
			c.logger.Error("correlator: load incident for stuck triage write", "incident_id", active.IncidentID, "err", err)
			continue
		}
		c.exhaustTriage(ctx, *inc, active.Attempts, active.LastErrorCode, active.LastErrorDetail, "max_attempts")
	}
}

// dispatchDueTriage reconciles any stuck terminal write, then dispatches
// every incident whose durable backoff is due.
func (c *Correlator) dispatchDueTriage(ctx context.Context, now time.Time) {
	c.retryStuckTerminalWrites(ctx)

	due, err := c.st.ListDueIncidentTriage(ctx, now)
	if err != nil {
		c.logger.Error("correlator: list due triage", "err", err)
		return
	}
	for _, d := range due {
		c.dispatchTriage(ctx, d.IncidentID)
	}
}
