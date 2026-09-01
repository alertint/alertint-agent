// SPDX-License-Identifier: FSL-1.1-ALv2

// Package correlator implements the fixed-window time-window correlator
// described in Slice 05 of the AlertINT agent plan.
//
// Design notes
//   - Group key: the Receiver's stable identity unless a non-empty configured
//     label list overrides it, with alertname/fingerprint safety fallbacks. The
//     correlator groups all alerts sharing that key into one incident within
//     the current open window.
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
//   - Triage retry: when the sink returns an error the incident stays "ready"
//     and is re-dispatched on later ticks with backoff; once the schedule is
//     spent it moves to the terminal "failed" status. Start re-dispatches
//     every incident still "ready" once (see triage_retry.go).
//
// Thread-safety: Accept may be called from multiple goroutines; all
// mutations go through a single serialised loop via a channel.
package correlator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/alertint/alertint-agent/internal/grouping"
	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/severity"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/google/uuid"
)

// IncidentSink receives incidents that have exited the collecting window
// and are ready for further processing. The Incident passed to
// OnIncidentReady carries Status "processing", not "ready": the transition
// to "processing" is a real durable lease taken before the sink is called
// (R1), not a display value, so an implementation must not branch on
// Status == "ready" here.
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
// emits one line; the Slack notifier edits the card and/or posts the "why" as a
// thread reply. nil means no occurrence notifications.
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

// TriageFailureNotifier receives one event when an incident's triage has
// exhausted its retry schedule and the incident was marked "failed". nil
// disables it.
type TriageFailureNotifier interface {
	OnTriageExhausted(ctx context.Context, ev notify.TriageExhaustedEvent) error
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
	// GroupLabels is an optional explicit override of the Receiver grouping
	// identity. Only these labels are included when the list is non-empty.
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
	triageNotifier     TriageFailureNotifier
	auditor            Auditor
	logger             *slog.Logger

	// pruneEvery is how many flush ticks pass between occurrence prunes (~hourly
	// at the default tick). Set in New; tests may override.
	pruneEvery int
	flushCount int

	// now is the clock flushExpired reads; tests substitute a fake.
	now func() time.Time

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
		now:        time.Now,
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

// SetTriageFailureNotifier sets the notifier for triage-exhausted events. Call
// after New, before Start.
func (c *Correlator) SetTriageFailureNotifier(n TriageFailureNotifier) { c.triageNotifier = n }

// SetAuditor sets the auditor for occurrence-attach events. Call after New, before Start.
func (c *Correlator) SetAuditor(a Auditor) { c.auditor = a }

// Accept queues an already-persisted alert for correlation. As of the
// durable delivery ledger (Task 4), no production Receiver calls this
// directly anymore — that handoff moves to a durable dispatch worker in a
// later task; callers here are tests and any other direct caller within this
// package's boundary. It is safe to call from multiple goroutines and will
// not block unless the internal channel is full.
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

// recover re-arms timers for any incidents that were "collecting" when the
// process last exited, and reconciles the durable triage schedule (interrupted
// in_flight rows, legacy ready rows with no triage row, and the one-hour
// startup horizon — see recoverTriageState). It does NOT fire anything
// immediately — the tick loop will catch due work on the next tick.
func (c *Correlator) recover(ctx context.Context) error {
	incs, err := listCollectingIncidents(ctx, c.st)
	if err != nil {
		return fmt.Errorf("correlator: startup recovery: %w", err)
	}
	c.logger.Info("correlator: startup recovery", "collecting_incidents", len(incs))
	if err := c.recoverTriageState(ctx, c.now().UTC()); err != nil {
		return fmt.Errorf("correlator: startup recovery: %w", err)
	}
	return nil
}

// handleAlert places the alert into the correct collecting incident,
// creating one if none exists yet for this group key.
// For resolved alerts, links to the most recent incident with matching group key.
func (c *Correlator) handleAlert(ctx context.Context, a store.Alert) error {
	gk, overrideMiss := c.groupKeySelection(a)

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

	// Retry-aware attachment (issue 60): a firing re-fire with no open window
	// joins a same-group Incident that is still unjudged and durably retrying
	// (ready + backoff) before recurrence collapse or a new Incident is ever
	// considered — an unjudged Incident stays collected until its first
	// judgment (CONTEXT.md: Incident).
	if err == store.ErrNotFound && a.Status == "firing" {
		handled, attachErr := c.maybeAttachRetryingIncident(ctx, a, gk)
		if attachErr != nil {
			return attachErr
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
		if overrideMiss {
			c.logger.Warn("correlator: configured group_labels matched no alert labels; using safety fallback",
				"fingerprint", a.Fingerprint, "group_key", gk)
		}
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

// flushExpired marks every overdue collecting incident as ready, seeds its
// durable triage row, and dispatches it, then dispatches every incident
// whose durable backoff is due.
func (c *Correlator) flushExpired(ctx context.Context) error {
	incs, err := listCollectingIncidents(ctx, c.st)
	if err != nil {
		return fmt.Errorf("correlator: list collecting: %w", err)
	}

	now := c.now().UTC()
	for _, inc := range incs {
		if now.Before(inc.ReadyAt) {
			continue
		}
		// The ready transition and its incident_ready Situation input commit
		// together (Task 5), so this is durably visible to the Situation even
		// if the process crashes before SeedIncidentTriage below ever runs —
		// Plan 2 replaces that immediate seed with "awaiting_decision".
		if err := c.st.MarkIncidentReadyWithSituationInput(ctx, inc.ID, now); err != nil {
			c.logger.Error("correlator: mark ready", "incident_id", inc.ID, "err", err)
			continue
		}
		c.logger.Info("correlator: incident ready", "incident_id", inc.ID, "group_key", inc.GroupKey, "alert_count", inc.AlertCount)

		if err := c.st.SeedIncidentTriage(ctx, inc.ID, now); err != nil {
			c.logger.Error("correlator: seed triage", "incident_id", inc.ID, "err", err)
			continue
		}
		c.dispatchTriage(ctx, inc.ID)
	}

	// Sink calls above may have taken a while (an LLM round-trip); re-read
	// the clock so due retries are not pushed to the next tick.
	c.dispatchDueTriage(ctx, c.now().UTC())

	// Piggyback occurrence pruning on the flush ticker (~hourly at the default
	// tick), so old occurrence rows are reclaimed without a separate job (R12).
	c.flushCount++
	if c.pruneEvery > 0 && c.flushCount%c.pruneEvery == 0 {
		c.pruneOldOccurrences(ctx)
	}
	return nil
}

// groupKey selects the explicit configured-label identity when present,
// otherwise the identity supplied by the Receiver. The shared safety fallback
// guarantees that the resulting Incident key is never empty.
func (c *Correlator) groupKey(a store.Alert) string {
	key, _ := c.groupKeySelection(a)
	return key
}

func (c *Correlator) groupKeySelection(a store.Alert) (key string, overrideMiss bool) {
	identity := a.ReceiverGroupingIdentity
	if len(c.cfg.GroupLabels) > 0 {
		identity = grouping.RenderSelectedLabels(a.Labels, c.cfg.GroupLabels)
		overrideMiss = identity == ""
	}
	return grouping.Ensure(identity, a.Labels, a.Fingerprint), overrideMiss
}

// listCollectingIncidents returns all incidents currently in status
// "collecting" by scanning the store.
func listCollectingIncidents(ctx context.Context, st *store.Store) ([]store.Incident, error) {
	return st.ListCollectingIncidents(ctx)
}

// ----------------------------------------------------------------------
// Durable delivery correlation (Task 5)
//
// ApplyDelivery is the delivery-ledger-backed replacement for handleAlert: it
// plans the same grouping/attachment decisions handleAlert makes, then
// converts the plan into one store.CorrelatedDeliveryMutation and commits it
// through a single call to the store, which performs the Incident/Occurrence
// mutation, the current incident_alerts compatibility attachment, the
// immutable incident_alert_deliveries ownership link, and the Situation
// input insertion atomically. No production Receiver calls handleAlert
// anymore (Task 4); a later durable dispatch worker calls ApplyDelivery for
// every claimed store.AlertDispatch. handleAlert stays untouched for the
// legacy in-memory fixtures that still exercise it directly.
// ----------------------------------------------------------------------

// ErrInvalidDelivery classifies a durably claimed delivery that cannot
// satisfy the correlation contract (missing identity or receipt time). It is
// a permanent local dead letter, not a retryable dependency failure.
var ErrInvalidDelivery = errors.New("correlator: invalid delivery")

// ApplyDelivery correlates one immutable, durably claimed delivery. The
// Incident/Occurrence mutation, immutable ownership link, compatibility
// membership, and Situation-input production commit atomically in the
// store — see store.ApplyCorrelatedDelivery.
func (c *Correlator) ApplyDelivery(ctx context.Context, claim store.AlertDispatch) error {
	d := claim.Delivery
	if d.ID == "" || d.Alert.ID == "" || d.Alert.Fingerprint == "" || d.ReceivedAt.IsZero() {
		return fmt.Errorf("%w: delivery identity and receipt time are required", ErrInvalidDelivery)
	}
	a := d.Alert
	a.ReceivedAt = d.ReceivedAt.UTC()
	a.ReceiverGroupingIdentity = d.ReceiverGroupingIdentity
	gk, overrideMiss := c.groupKeySelection(a)
	// Select collecting, unjudged retry attachment, resolved owner, recurrence,
	// or a fresh fixed-window Incident using current-main order and Drill guards.
	return c.applyDeliveryPlan(ctx, claim, a, gk, overrideMiss)
}

// applyDeliveryPlan mirrors handleAlert's decision order exactly — a
// collecting window first, then (for a delivery with no open window) the
// resolved-association, retry-backoff-attachment, and judged-Incident
// recurrence-collapse branches in that order, falling back to a fresh
// Incident only when none of them claims the delivery.
func (c *Correlator) applyDeliveryPlan(ctx context.Context, claim store.AlertDispatch, a store.Alert, gk string, overrideMiss bool) error {
	inc, err := c.st.GetCollectingIncident(ctx, gk)
	if err != nil && err != store.ErrNotFound {
		return fmt.Errorf("correlator: get collecting incident for delivery: %w", err)
	}

	if err == store.ErrNotFound && a.Status == "resolved" {
		return c.applyResolvedDeliveryPlan(ctx, claim, a, gk)
	}

	// Retry-aware attachment (issue 60): a firing re-fire with no open window
	// joins a same-group Incident that is still unjudged and durably retrying
	// (ready + backoff) before recurrence collapse or a new Incident is ever
	// considered.
	if err == store.ErrNotFound && a.Status == "firing" {
		handled, attachErr := c.applyRetryAttachDeliveryPlan(ctx, claim, a, gk)
		if attachErr != nil {
			return attachErr
		}
		if handled {
			return nil
		}
	}

	// Recurrence collapse (M1): a firing re-fire with no open window may
	// attach to an already-judged incident as an occurrence instead of
	// minting a new incident.
	if err == store.ErrNotFound && a.Status == "firing" {
		handled, attachErr := c.applyRecurrenceDeliveryPlan(ctx, claim, a, gk)
		if attachErr != nil {
			return attachErr
		}
		if handled {
			return nil
		}
	}

	if err == store.ErrNotFound {
		return c.applyFreshIncidentDeliveryPlan(ctx, claim, a, gk, overrideMiss)
	}

	if _, err := c.applyExistingIncidentDeliveryPlan(ctx, claim, *inc, "membership_changed", false); err != nil {
		return fmt.Errorf("correlator: apply delivery to incident: %w", err)
	}
	return nil
}

// applyExistingIncidentDeliveryPlan attaches a delivery to an Incident the
// caller already resolved to a concrete row (a still-open collecting window,
// a resolved-delivery association, or a retry-backoff/recurrence candidate).
func (c *Correlator) applyExistingIncidentDeliveryPlan(ctx context.Context, claim store.AlertDispatch, inc store.Incident, kind string, requireNonterminalOwner bool) (store.CorrelatedDeliveryResult, error) {
	m, err := c.correlatedDeliveryMutation(claim, inc, nil, kind, requireNonterminalOwner)
	if err != nil {
		return store.CorrelatedDeliveryResult{}, err
	}
	return c.st.ApplyCorrelatedDelivery(ctx, m)
}

// applyResolvedDeliveryPlan mirrors handleResolvedAlert: a resolved delivery
// with no open collecting window links to the most recent Incident for its
// group key regardless of status, opening a fresh Incident only when no
// prior Incident exists for the group at all. When the commit itself flips
// the Incident to "resolved" the legacy resolution notifier fires — after
// the transaction, never inside it.
func (c *Correlator) applyResolvedDeliveryPlan(ctx context.Context, claim store.AlertDispatch, a store.Alert, gk string) error {
	recentInc, err := c.st.GetRecentIncidentByGroupKey(ctx, gk)
	if err == store.ErrNotFound {
		return c.applyFreshIncidentDeliveryPlan(ctx, claim, a, gk, false)
	}
	if err != nil {
		return fmt.Errorf("correlator: get recent incident for resolved delivery: %w", err)
	}
	result, err := c.applyExistingIncidentDeliveryPlan(ctx, claim, *recentInc, "membership_changed", false)
	if err != nil {
		return fmt.Errorf("correlator: apply resolved delivery: %w", err)
	}
	c.logger.Info("correlator: resolved delivery linked to incident", "incident_id", result.Incident.ID, "delivery_id", claim.Delivery.ID, "group_key", gk, "status", result.Incident.Status)
	if result.Resolved && c.resolutionNotifier != nil {
		// Pass the pre-commit, fully-scanned *recentInc — not result.Incident,
		// which comes back through the store's lightweight scanIncident (no
		// Summary/RootCause/Confidence/LastJudgedAt) — so a resolved card for
		// an analyzed Incident still carries its real analysis, matching what
		// current main's handleResolvedAlert passes today (pre-resolution
		// status included; the notifier never depended on a post-commit
		// Status="resolved" value).
		if notifyErr := c.resolutionNotifier.OnIncidentResolved(ctx, *recentInc); notifyErr != nil {
			c.logger.Warn("correlator: resolution notify failed", "incident_id", result.Incident.ID, "err", notifyErr)
		}
	}
	return nil
}

// applyFreshIncidentDeliveryPlan opens a new fixed-window Incident for a
// delivery that matched none of the attachment paths above.
func (c *Correlator) applyFreshIncidentDeliveryPlan(ctx context.Context, claim store.AlertDispatch, a store.Alert, gk string, overrideMiss bool) error {
	if overrideMiss {
		c.logger.Warn("correlator: configured group_labels matched no delivery labels; using safety fallback",
			"fingerprint", a.Fingerprint, "group_key", gk)
	}
	window := time.Duration(c.cfg.WindowSeconds) * time.Second
	fresh := store.Incident{
		ID:           uuid.NewString(),
		GroupKey:     gk,
		FirstAlertAt: a.ReceivedAt,
		LastAlertAt:  a.ReceivedAt,
		ReadyAt:      a.ReceivedAt.Add(window),
	}
	result, err := c.applyExistingIncidentDeliveryPlan(ctx, claim, fresh, "incident_created", false)
	if err != nil {
		return fmt.Errorf("correlator: apply delivery to new incident: %w", err)
	}
	c.logger.Info("correlator: delivery opened incident", "delivery_id", claim.Delivery.ID, "incident_id", result.Incident.ID, "group_key", gk)
	return nil
}

// applyRetryAttachDeliveryPlan implements R4 for durable deliveries: a
// firing delivery with no collecting window may join the newest same-group
// Incident that is durably retrying (ready + backoff, non-exhausted)
// instead of collapsing into a recurrence or minting a new Incident. Store
// lookup errors and a Drill-parity mismatch fail safe to the caller trying
// the next attachment path. RequireNonterminalOwner closes the race between
// this read and the commit: if the candidate stopped being a valid retry
// target in between (e.g. it was judged or exhausted), the store rejects the
// attach and this falls through to the next plan rather than misattaching a
// delivery to an Incident it no longer belongs to.
func (c *Correlator) applyRetryAttachDeliveryPlan(ctx context.Context, claim store.AlertDispatch, a store.Alert, gk string) (bool, error) {
	candidate, _, err := c.st.GetBackoffIncidentByGroupKey(ctx, gk)
	if err == store.ErrNotFound {
		return false, nil
	}
	if err != nil {
		c.logger.Warn("correlator: backoff-incident lookup failed; treating as new incident", "err", err, "group_key", gk)
		return false, nil
	}

	members, err := c.st.GetIncidentAlerts(ctx, candidate.ID)
	if err != nil {
		c.logger.Warn("correlator: member lookup failed; treating as new incident", "err", err, "incident_id", candidate.ID)
		return false, nil
	}
	candidateDrill := false
	alreadyMember := false
	for _, mem := range members {
		if store.IsDrillAlert(mem) {
			candidateDrill = true
		}
		if mem.Fingerprint == a.Fingerprint {
			alreadyMember = true
		}
	}
	if store.IsDrillAlert(a) != candidateDrill {
		return false, nil
	}

	result, err := c.applyExistingIncidentDeliveryPlan(ctx, claim, *candidate, "membership_changed", true)
	if err != nil {
		if errors.Is(err, store.ErrIncidentOwnerNotCollapsible) {
			return false, nil
		}
		return false, fmt.Errorf("correlator: attach retrying incident: %w", err)
	}
	c.logger.Info("correlator: delivery attached during triage backoff", "incident_id", result.Incident.ID, "group_key", gk, "delivery_id", claim.Delivery.ID)

	// An idempotent re-fire of an already-attached fingerprint adds no new
	// membership — nothing meaningful happened, so no audit, mirroring the
	// legacy retry-attach "repeat" short-circuit (retry_attach.go).
	if !alreadyMember && c.auditor != nil {
		if err := c.auditor.Append(ctx, "correlator", "incident.triage_member_attached", map[string]any{
			"incident_id":  result.Incident.ID,
			"group_key":    gk,
			"alert_id":     a.ID,
			"member_count": result.Incident.AlertCount,
		}); err != nil {
			c.logger.Warn("correlator: audit triage_member_attached failed", "err", err, "incident_id", result.Incident.ID)
		}
	}
	return true, nil
}

// deliveryRecurrencePlan is the read-only outcome of planDeliveryRecurrence:
// the candidate Incident to attach to, and — only for a genuine new episode
// — the Occurrence to insert or touch plus the display-only "why" facts for
// the (post-commit) recurrence notifier.
type deliveryRecurrencePlan struct {
	incident        store.Incident
	occurrence      *store.Occurrence
	trigger         string
	isNewOccurrence bool
	delta           recurrenceDelta
}

// planDeliveryRecurrence gathers the durable facts for a recurrence
// decision and runs decideAttach — the same pure trigger matrix attach.go's
// maybeAttachOccurrence uses for handleAlert — without writing anything. It
// is the pure planning half of F1 for the delivery-ledger path: missing
// ownership, a Drill mismatch, or any lookup failure takes the safe
// new-Incident path (ok=false). ApplyCorrelatedDelivery repeats the owner
// check inside its transaction (RequireNonterminalOwner) to close the
// decision/commit race.
func (c *Correlator) planDeliveryRecurrence(ctx context.Context, a store.Alert, gk string) (deliveryRecurrencePlan, bool) {
	now := a.ReceivedAt

	candidate, err := c.st.GetRecentJudgedIncidentByGroupKey(ctx, gk)
	if err == store.ErrNotFound {
		return deliveryRecurrencePlan{}, false
	}
	if err != nil {
		c.logger.Warn("correlator: judged-incident lookup failed; treating as new incident", "err", err, "group_key", gk)
		return deliveryRecurrencePlan{}, false
	}

	members, err := c.st.GetIncidentAlerts(ctx, candidate.ID)
	if err != nil {
		c.logger.Warn("correlator: member lookup failed; treating as new incident", "err", err)
		return deliveryRecurrencePlan{}, false
	}
	baselineSev, baselineSevLabel, known, isMember, candidateDrill := memberBaselines(members, a.Fingerprint)

	if store.IsDrillAlert(a) != candidateDrill {
		return deliveryRecurrencePlan{}, false
	}

	latestOcc, err := c.st.LatestOccurrence(ctx, candidate.ID)
	if err != nil && err != store.ErrNotFound {
		c.logger.Warn("correlator: latest-occurrence lookup failed; treating as new incident", "err", err)
		return deliveryRecurrencePlan{}, false
	}

	isNewEpisode := candidate.Status == "resolved" || !isMember

	if !isNewEpisode {
		if latestOcc != nil {
			touch := *latestOcc
			touch.LastSeen = now
			return deliveryRecurrencePlan{incident: *candidate, occurrence: &touch}, true
		}
		return deliveryRecurrencePlan{incident: *candidate}, true
	}

	lastActivity := candidate.LastAlertAt
	if latestOcc != nil {
		lastActivity = latestOcc.LastSeen
	}
	lastJudged := candidate.FirstAlertAt
	if candidate.LastJudgedAt != nil {
		lastJudged = *candidate.LastJudgedAt
	}

	occSince, err := c.st.CountOccurrencesSince(ctx, candidate.ID, lastJudged)
	if err != nil {
		c.logger.Warn("correlator: occurrence-count lookup failed; treating as new incident", "err", err)
		return deliveryRecurrencePlan{}, false
	}
	episodeTimes, err := c.st.KeyEpisodeTimes(ctx, gk, now.Add(-c.cfg.Lookback))
	if err != nil {
		c.logger.Warn("correlator: episode-times lookup failed; treating as new incident", "err", err)
		return deliveryRecurrencePlan{}, false
	}

	decision := decideAttach(attachInputs{
		now:                    now,
		lastJudgedAt:           lastJudged,
		lastActivity:           lastActivity,
		occurrencesSinceJudged: occSince,
		isNewEpisode:           true,
		incomingSeverityRank:   severity.Rank(a.Labels["severity"]),
		incomingAlertname:      a.Labels["alertname"],
		baselineSeverityRank:   baselineSev,
		knownAlertnames:        known,
		episodeTimes:           episodeTimes,
		attachWindow:           c.cfg.AttachWindow,
		judgmentCeiling:        c.cfg.JudgmentCeiling,
		occurrenceCap:          c.cfg.OccurrenceCap,
	})

	if decision.action == actionNewIncident || decision.action == actionRepeatTouch {
		return deliveryRecurrencePlan{}, false
	}

	var delta recurrenceDelta
	switch decision.trigger {
	case "severity":
		delta.priorSeverity, delta.newSeverity = baselineSevLabel, a.Labels["severity"]
	case "new_alertname":
		delta.newAlertname = a.Labels["alertname"]
	case "cadence":
		delta.newInterval, delta.priorMedian = decision.cadenceInterval, decision.cadenceMedian
	}

	occ := store.Occurrence{
		IncidentID:   candidate.ID,
		OccurredAt:   a.ReceivedAt,
		LastSeen:     a.ReceivedAt,
		Fingerprints: []string{a.Fingerprint},
		Payload:      []store.OccurrenceMember{{Fingerprint: a.Fingerprint, Labels: a.Labels, Annotations: a.Annotations}},
		TriggerKind:  decision.trigger,
	}
	return deliveryRecurrencePlan{incident: *candidate, occurrence: &occ, trigger: decision.trigger, isNewOccurrence: true, delta: delta}, true
}

// applyRecurrenceDeliveryPlan converts planDeliveryRecurrence's verdict into
// one durable commit. A newly inserted occurrence fires the (post-commit)
// occurrence notifier; re-judgment is deliberately not invoked here — an LLM
// call has no place inside (or synchronously after) a durable dispatch
// commit, and the Situation controller (a later task) is what acts on a
// "membership_changed" input's trigger going forward.
func (c *Correlator) applyRecurrenceDeliveryPlan(ctx context.Context, claim store.AlertDispatch, a store.Alert, gk string) (bool, error) {
	plan, ok := c.planDeliveryRecurrence(ctx, a, gk)
	if !ok {
		return false, nil
	}
	m, err := c.correlatedDeliveryMutation(claim, plan.incident, plan.occurrence, "membership_changed", true)
	if err != nil {
		return false, err
	}
	result, err := c.st.ApplyCorrelatedDelivery(ctx, m)
	if err != nil {
		if errors.Is(err, store.ErrIncidentOwnerNotCollapsible) {
			return false, nil
		}
		return false, fmt.Errorf("correlator: apply recurring delivery: %w", err)
	}
	c.logger.Info("correlator: delivery collapsed into incident", "delivery_id", claim.Delivery.ID, "incident_id", result.Incident.ID, "group_key", gk, "trigger", plan.trigger)

	// result.Occurrence is nil for a duplicate-delivery replay (crash
	// recovery re-claiming an already-applied delivery): the store commits
	// nothing new in that case, so neither the audit nor the notifier below
	// fires, mirroring the legacy attachOccurrence audit call this durable
	// path re-emits (attach.go).
	if plan.isNewOccurrence && result.Occurrence != nil && c.auditor != nil {
		if err := c.auditor.Append(ctx, "correlator", "incident.occurrence_attached", map[string]any{
			"incident_id": result.Incident.ID,
			"group_key":   gk,
			"trigger":     plan.trigger,
		}); err != nil {
			c.logger.Warn("correlator: audit occurrence_attached failed", "err", err, "incident_id", result.Incident.ID)
		}
	}

	if plan.isNewOccurrence && c.occNotifier != nil && result.Occurrence != nil {
		stats := c.occurrenceStats(ctx, result.Incident.ID)
		ev := notify.RecurrenceEvent{
			Incident:      result.Incident,
			Stats:         stats,
			Trigger:       plan.trigger,
			Drill:         store.IsDrillAlert(a),
			PriorSeverity: plan.delta.priorSeverity,
			NewSeverity:   plan.delta.newSeverity,
			NewAlertname:  plan.delta.newAlertname,
			NewInterval:   plan.delta.newInterval,
			PriorMedian:   plan.delta.priorMedian,
		}
		if notifyErr := c.occNotifier.OnOccurrenceAttached(ctx, ev); notifyErr != nil {
			c.logger.Warn("correlator: occurrence notify failed", "err", notifyErr, "incident_id", result.Incident.ID)
		}
	}
	return true, nil
}

// correlatedDeliveryMutation builds the store mutation for one claimed
// delivery attaching to inc (a fresh, proposed Incident or an already-real
// one — the store's ensureCorrelatedIncidentTx tells the difference), with
// occ non-nil only for a recurrence-collapse plan. kind is the caller's
// best guess at the Situation input's Kind ("incident_created" or
// "membership_changed"); the store derives the authoritative Kind from
// committed state (including "incident_resolved") and never trusts this
// guess blindly.
func (c *Correlator) correlatedDeliveryMutation(claim store.AlertDispatch, inc store.Incident, occ *store.Occurrence, kind string, requireNonterminalOwner bool) (store.CorrelatedDeliveryMutation, error) {
	if claim.LeaseOwner == nil || *claim.LeaseOwner == "" {
		return store.CorrelatedDeliveryMutation{}, fmt.Errorf("%w: claimed delivery is missing its lease owner", ErrInvalidDelivery)
	}
	d := claim.Delivery
	deliveryID := d.ID
	return store.CorrelatedDeliveryMutation{
		DeliveryID:         d.ID,
		DispatchOwner:      *claim.LeaseOwner,
		DispatchClaimToken: claim.ClaimToken,
		Incident:           inc,
		Occurrence:         occ,
		Input: store.SituationInput{
			ID:             uuid.NewString(),
			IdempotencyKey: "delivery:" + d.ID,
			IncidentID:     inc.ID,
			Kind:           kind,
			GroupKey:       inc.GroupKey,
			DeliveryID:     &deliveryID,
			OccurredAt:     d.ReceivedAt.UTC(),
		},
		RequireNonterminalOwner: requireNonterminalOwner,
	}, nil
}
