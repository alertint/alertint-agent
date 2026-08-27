// SPDX-License-Identifier: FSL-1.1-ALv2

package correlator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/alertint/alertint-agent/internal/llmhealth"
	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/store"
)

// triageRetryDelays is the backoff schedule for re-dispatching an incident
// whose triage handoff (IncidentSink.OnIncidentReady) returned an error. The
// first retry waits 30 s and the last ~32 min, so a short LLM or connector
// outage self-heals and a long one exhausts inside the hour instead of
// leaving the incident in "ready" forever. Five attempts in total, counting
// the initial dispatch — len(triageRetryDelays)+1 must stay in sync with the
// attempts CHECK constraint in migrations/0011_incident_triage.sql.
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

// ambiguousShapedReasons are llmhealth reasons that match on generic stdlib
// error shapes (context.DeadlineExceeded, a net.Error, a *url.Error) rather
// than an internal/llm- or internal/llmhealth-specific typed value. The
// Acute Triage sink error classifyTriageError sees is the WHOLE skill
// invocation's error, not just the LLM call's — a SQLite write timing out or
// a Prometheus/Zabbix/log-source fetch failing can produce these same
// shapes, so trusting them here would misattribute a non-LLM failure as an
// LLM dependency code.
var ambiguousShapedReasons = map[llmhealth.Reason]bool{
	llmhealth.ReasonTimeout:  true,
	llmhealth.ReasonNetwork:  true,
	llmhealth.ReasonCanceled: true,
}

// classifyTriageError produces the bounded, sanitized code/detail persisted
// on a failed dispatch (R9). A dispatch error that llmhealth can classify
// into a reason backed by an LLM-specific typed error (a provider status,
// a schema/malformed-response sentinel) persists that reason code and its
// safe detail; anything else — an ambiguous generic-shaped reason that a
// non-LLM sink error could equally produce, or a shape llmhealth has never
// seen — falls back to the generic triage_dispatch_failed code so a failure
// is always recorded, never dropped, and never misattributed.
func classifyTriageError(err error) (code, detail string) {
	reason := llmhealth.Classify(err)
	if reason != llmhealth.ReasonUnknown && !ambiguousShapedReasons[reason] {
		return string(reason), llmhealth.SafeDetail(err)
	}
	return "triage_dispatch_failed", llmhealth.SafeDetail(err)
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
// write itself (never another sink call) via reconcileInFlightTriage.
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

// reconcileInFlightTriage resolves every triage row currently `in_flight`
// without ever re-invoking the sink. A row observed at rest between ticks
// cannot be a dispatch actively in progress — the Correlator loop is
// synchronous, so dispatchTriage always runs a row to completion (or fails a
// write and returns) before control comes back here — so any row found here
// is either a genuine process-crash interruption or a terminal write that
// itself failed to persist on an earlier tick. Both are indistinguishable
// from the store's point of view and reconciled identically (ADR-0045): the
// interrupted attempt counts. Called every tick (so a stuck write recovers
// as soon as the store does, not only at restart) and once at startup.
func (c *Correlator) reconcileInFlightTriage(ctx context.Context) {
	stuck, err := c.st.ListInterruptedIncidentTriage(ctx)
	if err != nil {
		c.logger.Error("correlator: list interrupted triage", "err", err)
		return
	}
	for _, active := range stuck {
		c.recoverInterruptedAttempt(ctx, active)
	}
}

// reconcileUnscheduledTriage seeds a durable pending row for any "ready"
// Incident with no triage row at all, and applies the startup horizon to it.
// Such an Incident arises two ways: a pre-upgrade legacy row, or — since
// MarkIncidentReady and SeedIncidentTriage are two separate store calls, not
// one transaction — this run's own SeedIncidentTriage call failing right
// after MarkIncidentReady already committed. Either way the Incident is
// otherwise invisible to every later scan (R1/R3: it is neither collecting
// nor present in the due schedule), so this is called every tick, not only
// once at startup.
func (c *Correlator) reconcileUnscheduledTriage(ctx context.Context, now time.Time) {
	unscheduled, err := c.st.ListLegacyReadyIncidents(ctx)
	if err != nil {
		c.logger.Error("correlator: list unscheduled ready incidents", "err", err)
		return
	}
	if len(unscheduled) > 0 {
		c.logger.Warn("correlator: found ready incidents with no triage schedule", "count", len(unscheduled))
	}
	for _, inc := range unscheduled {
		if err := c.st.SeedIncidentTriage(ctx, inc.ID, inc.ReadyAt); err != nil {
			c.logger.Error("correlator: seed unscheduled triage", "incident_id", inc.ID, "err", err)
			continue
		}
		c.applyStartupHorizon(ctx, inc, inc.ReadyAt, 0, now)
	}
}

// dispatchDueTriage reconciles any stuck in_flight row and any unscheduled
// ready incident, then dispatches every incident whose durable backoff is
// due.
func (c *Correlator) dispatchDueTriage(ctx context.Context, now time.Time) {
	c.reconcileInFlightTriage(ctx)
	c.reconcileUnscheduledTriage(ctx, now)

	due, err := c.st.ListDueIncidentTriage(ctx, now)
	if err != nil {
		c.logger.Error("correlator: list due triage", "err", err)
		return
	}
	for _, d := range due {
		c.dispatchTriage(ctx, d.IncidentID)
	}
}

// recoverTriageState reconciles the durable triage schedule before the loop
// starts (ADR-0045): every interrupted in_flight row is resolved first (the
// attempt counts), every unscheduled "ready" row (legacy or otherwise) is
// seeded as pending, and finally the one-hour startup horizon is applied to
// every pending/backoff row so a long backlog cannot become a boot-time LLM
// burst. It never calls the sink; due work runs on the first tick after
// Start.
func (c *Correlator) recoverTriageState(ctx context.Context, now time.Time) error {
	c.reconcileInFlightTriage(ctx)
	c.reconcileUnscheduledTriage(ctx, now)

	due, err := c.st.ListDueIncidentTriage(ctx, now)
	if err != nil {
		return fmt.Errorf("list due: %w", err)
	}
	for _, active := range due {
		inc, err := c.st.GetIncidentByID(ctx, active.IncidentID)
		if err != nil || inc == nil {
			c.logger.Error("correlator: load incident for startup horizon", "incident_id", active.IncidentID, "err", err)
			continue
		}
		c.applyStartupHorizon(ctx, *inc, active.NextAt, active.Attempts, now)
	}
	return nil
}

// recoverInterruptedAttempt resolves one triage row found still in_flight —
// a process crash mid-call, or a terminal write that itself failed to
// persist on an earlier tick. The attempt counts (ADR-0045): a row already
// at the attempt ceiling goes straight to exhausted; otherwise it moves to
// backoff with next_at computed from when the interrupted attempt itself
// began, so it does not get a free extra delay from the restart/retry time.
//
// If the Incident's own status has already moved past "processing" — the
// triage skill's own persist (SaveIncidentOutput) succeeded, but the
// dispatch's own CompleteIncidentTriage cleanup failed to write, or lost a
// race with a crash — the row is stale bookkeeping for an Incident that is
// no longer unjudged (CONTEXT.md: Triage schedule) and is deleted outright
// rather than reconciled into a schedule that would never be reached again.
func (c *Correlator) recoverInterruptedAttempt(ctx context.Context, active store.IncidentTriage) {
	inc, err := c.st.GetIncidentByID(ctx, active.IncidentID)
	if err != nil || inc == nil {
		c.logger.Error("correlator: load incident for interrupted triage", "incident_id", active.IncidentID, "err", err)
		return
	}
	if inc.Status != "processing" {
		if err := c.st.CompleteIncidentTriage(ctx, active.IncidentID); err != nil && !errors.Is(err, store.ErrNotFound) {
			c.logger.Error("correlator: clear stale in-flight triage row", "incident_id", active.IncidentID, "err", err)
			return
		}
		c.logger.Warn("correlator: cleared stale in-flight triage row for an incident already judged",
			"incident_id", active.IncidentID, "group_key", inc.GroupKey, "status", inc.Status)
		return
	}
	const code = "process_interrupted"
	const detail = "attempt interrupted before completion"
	if active.Attempts >= len(triageRetryDelays)+1 {
		c.exhaustTriage(ctx, *inc, active.Attempts, code, detail, "interrupted")
		return
	}
	next := active.StartedAt.Add(triageRetryDelays[active.Attempts-1])
	if err := c.st.RecoverInterruptedIncidentTriage(ctx, active.IncidentID, next, code, detail); err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			c.logger.Error("correlator: recover interrupted triage", "incident_id", active.IncidentID, "err", err)
		}
		return
	}
	c.logger.Warn("correlator: startup recovery: interrupted triage attempt recovered to backoff",
		"incident_id", active.IncidentID, "group_key", inc.GroupKey, "attempts", active.Attempts, "next_at", next)
	if c.auditor != nil {
		if err := c.auditor.Append(ctx, "correlator", "incident.triage_attempt", map[string]any{
			"incident_id": active.IncidentID,
			"group_key":   inc.GroupKey,
			"phase":       "backoff",
			"attempts":    active.Attempts,
			"next_at":     next,
			"reason":      "interrupted",
		}); err != nil {
			c.logger.Warn("correlator: audit interrupted triage recovery", "incident_id", active.IncidentID, "err", err)
		}
	}
}

// applyStartupHorizon closes out inc if due is more than startupRetryWindow
// before now (ADR-0045) — the one-hour horizon that already governed legacy
// "ready" rows, applied here to every unjudged row regardless of how it got
// there. A condition that is still real re-fires and opens a fresh incident,
// so nothing live is lost.
func (c *Correlator) applyStartupHorizon(ctx context.Context, inc store.Incident, due time.Time, attempts int, now time.Time) {
	if now.Sub(due) <= startupRetryWindow {
		return
	}
	c.exhaustTriage(ctx, inc, attempts, "startup_retry_window_expired",
		"due time exceeded the one-hour startup horizon", "startup_retry_window_expired")
}
