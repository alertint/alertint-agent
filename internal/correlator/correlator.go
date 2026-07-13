// SPDX-License-Identifier: FSL-1.1-ALv2

// Package correlator implements the fixed-window time-window correlator
// described in Slice 05 of the AlertINT agent plan.
//
// Design notes
//   - Group key: a deterministic string derived from the alert's labels
//     (sorted key=value pairs joined with commas). The correlator groups
//     all alerts that share the same group key into a single incident
//     within the current open window.
//   - Fixed window: ready_at = first_alert_at + WindowSeconds. Once the
//     window closes the incident is marked "ready" and handed off via
//     IncidentSink.OnIncidentReady.
//   - Deduplication: alerts with the same fingerprint are added to the
//     incident at most once (incident_alerts has a composite PK).
//   - Startup recovery: on Start the correlator scans incidents in
//     status "collecting" and re-arms their timers so a restart does
//     not silently drop windows.
//   - The MarkReady ticker wakes every TickInterval (default 5 s) and
//     flushes every collecting incident whose ready_at is in the past.
//
// Thread-safety: Accept may be called from multiple goroutines; all
// mutations go through a single serialised loop via a channel.
package correlator

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/google/uuid"
)

// IncidentSink receives incidents that have exited the collecting window
// and are ready for further processing.
type IncidentSink interface {
	OnIncidentReady(ctx context.Context, inc store.Incident) error
}

// ResolutionNotifier receives notifications when an incident becomes fully resolved
// (all alerts have status="resolved").
type ResolutionNotifier interface {
	OnIncidentResolved(ctx context.Context, inc store.Incident) error
}

// NopIncidentSink discards every incident. Useful in tests that only
// verify store state.
type NopIncidentSink struct{}

func (NopIncidentSink) OnIncidentReady(_ context.Context, _ store.Incident) error { return nil }

// OccurrenceNotifier receives a deterministic, zero-LLM notification each time a
// re-fire attaches as an occurrence (recurrence collapse). The stdout notifier
// emits one line; the Slack notifier edits the card and/or broadcasts the "why".
// nil means no occurrence notifications.
type OccurrenceNotifier interface {
	OnOccurrenceAttached(ctx context.Context, ev notify.RecurrenceEvent) error
}

// Rejudger runs a fresh triage that replaces an incident's finding in place when
// an escalation trigger or the Clock B ceiling fires. Implemented by the triage
// skill and wired in U4 — nil means an escalation records its occurrence and
// trigger but no re-judgment runs yet.
type Rejudger interface {
	Rejudge(ctx context.Context, inc store.Incident, trigger string) error
}

// Auditor is the subset of internal/audit the correlator uses to record
// occurrence attaches (incident.occurrence_attached). nil disables auditing.
type Auditor interface {
	Append(ctx context.Context, actor, kind string, payload any) error
}

// Config holds tunables for the Correlator.
type Config struct {
	// WindowSeconds is the fixed correlation window duration. Defaults to 60.
	WindowSeconds int
	// TickInterval controls how often the background goroutine polls for
	// expired windows. Defaults to 5 s. Tests may set this much smaller.
	TickInterval time.Duration
	// GroupLabels is the list of label keys to use for grouping alerts.
	// Only these labels are included in the group key. If empty, all
	// labels are used (not recommended for production).
	GroupLabels []string

	// Incident-memory (M1) horizon knobs. Zero values take the defaults below.
	AttachWindow    time.Duration // Clock A: sliding attach window from the last occurrence (default 30m)
	JudgmentCeiling time.Duration // Clock B: max time since the last judgment before a forced re-judgment (default 4h)
	OccurrenceCap   int           // re-judge backstop after this many attaches since the last judgment (default 100)
	Lookback        time.Duration // occurrence pruning + cadence lookback horizon (default 90d)
}

// DefaultTickInterval is the flush-ticker default, exported so callers that
// budget around window expiry (e.g. `alertint drill`) reference the real value
// instead of hand-copying it.
const DefaultTickInterval = 5 * time.Second

func (c *Config) defaults() {
	if c.WindowSeconds <= 0 {
		c.WindowSeconds = 60
	}
	if c.TickInterval <= 0 {
		c.TickInterval = DefaultTickInterval
	}
	if c.AttachWindow <= 0 {
		c.AttachWindow = 30 * time.Minute
	}
	if c.JudgmentCeiling <= 0 {
		c.JudgmentCeiling = 4 * time.Hour
	}
	if c.OccurrenceCap <= 0 {
		c.OccurrenceCap = 100
	}
	if c.Lookback <= 0 {
		c.Lookback = 90 * 24 * time.Hour
	}
}

// Correlator groups incoming store.Alert values into incidents using a
// fixed time window and notifies an IncidentSink when each window closes.
type Correlator struct {
	cfg                Config
	st                 *store.Store
	sink               IncidentSink
	resolutionNotifier ResolutionNotifier
	occNotifier        OccurrenceNotifier
	rejudger           Rejudger
	auditor            Auditor
	logger             *slog.Logger

	// pruneEvery is how many flush ticks pass between occurrence prunes (~hourly
	// at the default tick). Set in New; tests may override.
	pruneEvery int
	flushCount int

	alertCh chan store.Alert

	once   sync.Once
	stopCh chan struct{}
	doneCh chan struct{}
}

// New creates a Correlator. Call Start to begin processing.
// Passing nil for logger falls back to slog.Default().
func New(cfg Config, st *store.Store, sink IncidentSink, logger *slog.Logger) *Correlator {
	cfg.defaults()
	if sink == nil {
		sink = NopIncidentSink{}
	}
	if logger == nil {
		logger = slog.Default()
	}
	pruneEvery := int(time.Hour / cfg.TickInterval)
	if pruneEvery < 1 {
		pruneEvery = 1
	}
	return &Correlator{
		cfg:        cfg,
		st:         st,
		sink:       sink,
		logger:     logger,
		pruneEvery: pruneEvery,
		alertCh:    make(chan store.Alert, 256),
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
	}
}

// SetResolutionNotifier sets the notifier for incident resolution events.
// Call this after New() but before Start().
func (c *Correlator) SetResolutionNotifier(rn ResolutionNotifier) {
	c.resolutionNotifier = rn
}

// SetOccurrenceNotifier sets the collapse notifier (U5). Call after New, before Start.
func (c *Correlator) SetOccurrenceNotifier(n OccurrenceNotifier) { c.occNotifier = n }

// SetRejudger sets the re-judgment runner (U4). Call after New, before Start.
func (c *Correlator) SetRejudger(r Rejudger) { c.rejudger = r }

// SetAuditor sets the auditor for occurrence-attach events. Call after New, before Start.
func (c *Correlator) SetAuditor(a Auditor) { c.auditor = a }

// Accept implements ingress.AlertSink. It is safe to call from multiple
// goroutines and will not block unless the internal channel is full.
func (c *Correlator) Accept(ctx context.Context, a store.Alert) error {
	select {
	case c.alertCh <- a:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-c.stopCh:
		return fmt.Errorf("correlator: stopped")
	}
}

// Start launches the background processing loop and returns immediately.
// It must be called exactly once.
func (c *Correlator) Start(ctx context.Context) error {
	var startErr error
	c.once.Do(func() {
		startErr = c.recover(ctx)
		if startErr != nil {
			return
		}
		go c.loop(ctx)
	})
	return startErr
}

// Stop signals the processing loop to exit and waits for it to drain.
func (c *Correlator) Stop() {
	close(c.stopCh)
	<-c.doneCh
}

// ----------------------------------------------------------------------
// Internal implementation
// ----------------------------------------------------------------------

func (c *Correlator) loop(ctx context.Context) {
	defer close(c.doneCh)

	ticker := time.NewTicker(c.cfg.TickInterval)
	defer ticker.Stop()

	for {
		select {
		case a := <-c.alertCh:
			if err := c.handleAlert(ctx, a); err != nil {
				c.logger.Error("correlator: handle alert", "err", err, "fingerprint", a.Fingerprint)
			}
		case <-ticker.C:
			if err := c.flushExpired(ctx); err != nil {
				c.logger.Error("correlator: flush expired", "err", err)
			}
		case <-c.stopCh:
			// Drain remaining alerts before shutting down.
			for {
				select {
				case a := <-c.alertCh:
					if err := c.handleAlert(ctx, a); err != nil {
						c.logger.Error("correlator: drain alert", "err", err, "fingerprint", a.Fingerprint)
					}
				default:
					return
				}
			}
		}
	}
}

// recover re-arms timers for any incidents that were "collecting" when
// the process last exited. It does NOT fire them immediately — the tick
// loop will catch overdue ones on the next tick.
func (c *Correlator) recover(ctx context.Context) error {
	incs, err := listCollectingIncidents(ctx, c.st)
	if err != nil {
		return fmt.Errorf("correlator: startup recovery: %w", err)
	}
	c.logger.Info("correlator: startup recovery", "collecting_incidents", len(incs))
	return nil
}

// handleAlert places the alert into the correct collecting incident,
// creating one if none exists yet for this group key.
// For resolved alerts, links to the most recent incident with matching group key.
func (c *Correlator) handleAlert(ctx context.Context, a store.Alert) error {
	gk := c.groupKey(a)

	inc, err := c.st.GetCollectingIncident(ctx, gk)
	if err != nil && err != store.ErrNotFound {
		return fmt.Errorf("correlator: get collecting incident: %w", err)
	}

	if err == store.ErrNotFound && a.Status == "resolved" {
		handled, handleErr := c.handleResolvedAlert(ctx, a, gk)
		if handleErr != nil {
			return handleErr
		}
		if handled {
			return nil
		}
	}

	// Recurrence collapse (M1): a firing re-fire with no open window may attach
	// to an already-judged incident as an occurrence instead of minting a new
	// incident + LLM call. This is a firing-side mirror of the resolved branch
	// above. Loop-serialization invariant: re-judgment runs inline on this
	// goroutine, so attaches arriving mid-flight queue in alertCh behind it —
	// that gives R7's single-flight and the no-double-mint property for free. A
	// future async refactor reopens the mid-flight double-mint race.
	if err == store.ErrNotFound && a.Status == "firing" {
		handled, attachErr := c.maybeAttachOccurrence(ctx, a, gk)
		if attachErr != nil {
			return attachErr
		}
		if handled {
			return nil
		}
	}

	if err == store.ErrNotFound {
		// Open a new window.
		window := time.Duration(c.cfg.WindowSeconds) * time.Second
		inc = &store.Incident{
			ID:           uuid.NewString(),
			GroupKey:     gk,
			FirstAlertAt: a.ReceivedAt,
			LastAlertAt:  a.ReceivedAt,
			ReadyAt:      a.ReceivedAt.Add(window),
			AlertCount:   0,
		}
		if err := c.st.InsertIncident(ctx, *inc); err != nil {
			return fmt.Errorf("correlator: insert incident: %w", err)
		}
		alertStatus := "firing"
		if a.Status == "resolved" {
			alertStatus = "resolved"
		}
		c.logger.Info("correlator: new incident", "incident_id", inc.ID, "group_key", gk, "ready_at", inc.ReadyAt, "alert_status", alertStatus)
	}

	if err := c.st.AddAlertToIncident(ctx, inc.ID, a.ID, a.ReceivedAt); err != nil {
		return fmt.Errorf("correlator: add alert to incident: %w", err)
	}

	c.logger.Debug("correlator: alert added to incident", "incident_id", inc.ID, "alert_id", a.ID, "alert_status", a.Status)
	return nil
}

// handleResolvedAlert tries to link a resolved alert (which has no collecting
// incident) to the most recent incident for its group key. Returns (true, nil)
// when the alert was linked and the caller should return early, (false, nil)
// when no prior incident was found (ErrNotFound) so a new window should be
// opened instead, or (false, err) on any other hard failure.
func (c *Correlator) handleResolvedAlert(ctx context.Context, a store.Alert, gk string) (bool, error) {
	recentInc, err := c.st.GetRecentIncidentByGroupKey(ctx, gk)
	if err == store.ErrNotFound {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("correlator: get recent incident: %w", err)
	}

	if addErr := c.st.AddAlertToIncident(ctx, recentInc.ID, a.ID, a.ReceivedAt); addErr != nil {
		return false, fmt.Errorf("correlator: add resolved alert to incident: %w", addErr)
	}
	c.logger.Info("correlator: resolved alert linked to incident", "incident_id", recentInc.ID, "alert_id", a.ID, "group_key", gk, "status", recentInc.Status)

	if recentInc.Status == "analyzed" || recentInc.Status == "ready" {
		c.maybeResolveIncident(ctx, recentInc, gk)
	}
	return true, nil
}

// maybeResolveIncident checks whether all alerts in inc are now resolved and,
// if so, marks the incident resolved and fires the resolution notifier.
func (c *Correlator) maybeResolveIncident(ctx context.Context, inc *store.Incident, gk string) {
	allResolved, checkErr := c.checkAllAlertsResolved(ctx, inc.ID)
	c.logger.Debug("correlator: resolution check", "incident_id", inc.ID, "all_resolved", allResolved, "err", checkErr)
	if checkErr != nil {
		c.logger.Warn("correlator: resolution check failed", "incident_id", inc.ID, "err", checkErr)
		return
	}
	if !allResolved {
		return
	}
	if markErr := c.st.MarkIncidentResolved(ctx, inc.ID); markErr != nil {
		c.logger.Warn("correlator: mark incident resolved failed", "incident_id", inc.ID, "incident_status", inc.Status, "err", markErr)
		return
	}
	c.logger.Info("correlator: incident resolved - all alerts recovered", "incident_id", inc.ID, "group_key", gk)
	if c.resolutionNotifier != nil {
		if notifyErr := c.resolutionNotifier.OnIncidentResolved(ctx, *inc); notifyErr != nil {
			c.logger.Warn("correlator: resolution notify failed", "incident_id", inc.ID, "err", notifyErr)
		}
	}
}

// checkAllAlertsResolved returns true if all alerts in the incident are resolved.
func (c *Correlator) checkAllAlertsResolved(ctx context.Context, incidentID string) (bool, error) {
	alerts, err := c.st.GetIncidentAlerts(ctx, incidentID)
	if err != nil {
		return false, err
	}
	if len(alerts) == 0 {
		return false, nil
	}
	for _, a := range alerts {
		if a.Status != "resolved" {
			return false, nil
		}
	}
	return true, nil
}

// flushExpired marks every overdue collecting incident as ready and
// notifies the sink.
func (c *Correlator) flushExpired(ctx context.Context) error {
	incs, err := listCollectingIncidents(ctx, c.st)
	if err != nil {
		return fmt.Errorf("correlator: list collecting: %w", err)
	}

	now := time.Now().UTC()
	for _, inc := range incs {
		if now.Before(inc.ReadyAt) {
			continue
		}
		if err := c.st.MarkIncidentReady(ctx, inc.ID); err != nil {
			c.logger.Error("correlator: mark ready", "incident_id", inc.ID, "err", err)
			continue
		}
		c.logger.Info("correlator: incident ready", "incident_id", inc.ID, "group_key", inc.GroupKey, "alert_count", inc.AlertCount)

		// Refresh the struct so the sink sees updated fields.
		ready := inc
		ready.Status = "ready"
		if err := c.sink.OnIncidentReady(ctx, ready); err != nil {
			c.logger.Error("correlator: sink error", "incident_id", inc.ID, "err", err)
		}
	}

	// Piggyback occurrence pruning on the flush ticker (~hourly at the default
	// tick), so old occurrence rows are reclaimed without a separate job (R12).
	c.flushCount++
	if c.pruneEvery > 0 && c.flushCount%c.pruneEvery == 0 {
		c.pruneOldOccurrences(ctx)
	}
	return nil
}

// groupKey builds a deterministic string from the alert's labels.
// Only labels specified in GroupLabels are used; if GroupLabels is empty,
// all labels are used (backwards compatibility for tests).
// Labels are sorted so key order never matters.
func (c *Correlator) groupKey(a store.Alert) string {
	var keys []string
	if len(c.cfg.GroupLabels) > 0 {
		// Use only configured group labels
		keys = make([]string, 0, len(c.cfg.GroupLabels))
		for _, k := range c.cfg.GroupLabels {
			if _, ok := a.Labels[k]; ok {
				keys = append(keys, k)
			}
		}
	} else {
		// Fallback: use all labels (for backwards compatibility in tests)
		keys = make([]string, 0, len(a.Labels))
		for k := range a.Labels {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+a.Labels[k])
	}
	return strings.Join(parts, ",")
}

// listCollectingIncidents returns all incidents currently in status
// "collecting" by scanning the store.
func listCollectingIncidents(ctx context.Context, st *store.Store) ([]store.Incident, error) {
	return st.ListCollectingIncidents(ctx)
}
